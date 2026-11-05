"""裁判書全文取得工具（httpx + F5 WAF cookie bypass）"""

import json
import logging
import re
import time
from datetime import datetime
from urllib.parse import parse_qs, quote, unquote, urlparse

import httpx
from bs4 import BeautifulSoup

from mcp_server.config import (
    JUDICIAL_DATA_URL,
    CACHE_JUDGMENT_TTL,
)
from mcp_server.cache.db import CacheDB
from mcp_server.parsers.judicial_parser import (
    parse_judgment_page,
    _extract_sections,
    _extract_cited_statutes,
    _extract_cited_cases,
)
from mcp_server.tools.pdf_text import extract_raw_pdf_text
from mcp_server.tools._errors import error_response
from mcp_server.tools.waf_bypass import (
    JudicialWAFBypass,
    WAFPermanentBlockError,
    get_with_waf_retry,
)

logger = logging.getLogger(__name__)

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


_HISTORY_KEY = re.compile(r"GetJudHistory\.ashx\?jid=([0-9A-Za-z%.,`_-]+)")
_HISTORY_URL = "https://judgment.judicial.gov.tw/controls/GetJudHistory.ashx?jid="
_HISTORY_NOTE = (
    "司法院依案號串起的歷審清單。pending_supreme_court=true 表示案件目前上訴到最高法院／最高行政法院審理中；"
    "url 為空表示案件目前繫屬法院或該案號沒有裁判書。清單最後一筆之後沒有更高審級，不等於已經確定"
    "（可能仍在上訴期間內，或上級審裁判尚未上網）。"
)


def _history_item(c: dict) -> dict:
    href = c.get("href") or ""
    jid = parse_qs(urlparse(href).query).get("id", [""])[0]
    return {
        "desc": c.get("desc", ""),
        "jid": jid,
        "url": f"https://judgment.judicial.gov.tw/FJUD/{href}" if href else "",
        "pending_supreme_court": c.get("red") == 1,
    }


class JudgmentDocClient:
    """裁判書全文取得：HTTP GET data.aspx + F5 WAF cookie bypass"""

    def __init__(self, cache: CacheDB, waf: JudicialWAFBypass):
        self.cache = cache
        self.waf = waf
        self.http = httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": _USER_AGENT},
            follow_redirects=True,
            cookies=waf.get_cookies(),
        )

    async def close(self):
        await self.http.aclose()

    async def get_by_jid(self, jid: str) -> dict:
        """以 JID 取得裁判書全文

        JID 格式範例：TPSV,104,台上,472,20150326,1
        """
        # 快取查詢
        cached = await self.cache.get_judgment(jid)
        if cached and "history_key" in cached and (cached.get("main_text") or cached.get("reasoning") or len(cached.get("full_text", "")) > 300):
            return await self._with_history({"success": True, "cached": True, **cached})

        # HTTP GET data.aspx
        try:
            result = await self._fetch_via_http(jid)
        except WAFPermanentBlockError:
            logger.warning("取裁判書遭司法院 WAF 硬擋 (JID: %s)", jid)
            return error_response(
                "司法院網站暫時無法通過 WAF 防護，請稍後重試", jid=jid,
            )
        if result and result.get("success"):
            return await self._with_history(result)

        return error_response(f"無法取得裁判書全文（JID: {jid}）", jid=jid)

    async def get_by_url(self, url: str) -> dict:
        """以 URL 取得裁判書全文"""
        from mcp_server.config import validate_url_domain
        if not validate_url_domain(url):
            return error_response("URL 域名不在白名單中", url=url)

        # 嘗試從 URL 擷取 JID 作為快取 key
        import re
        jid_match = re.search(r"id=([^&]+)", url)
        cache_key = jid_match.group(1) if jid_match else url

        cached = await self.cache.get_judgment(cache_key)
        if cached and "history_key" in cached and (cached.get("main_text") or cached.get("reasoning") or len(cached.get("full_text", "")) > 300):
            return await self._with_history({"success": True, "cached": True, **cached})

        try:
            resp = await get_with_waf_retry(self.http, url, self.waf)
            resp.raise_for_status()

            soup = BeautifulSoup(resp.text, "lxml")
            jud_el = soup.select_one("#jud")
            if jud_el:
                jud_html = str(jud_el)
                parsed = parse_judgment_page(f"<html><body>{jud_html}</body></html>")
            else:
                parsed = parse_judgment_page(resp.text)

            if parsed.get("full_text"):
                source_type = "http"
                pdf_url = _extract_scan_pdf_url(resp.text, cache_key if jid_match else "")
                if pdf_url and not parsed.get("main_text") and not parsed.get("reasoning"):
                    pdf_text = await self._fetch_scan_pdf_text(pdf_url)
                    if pdf_text:
                        source_type = "http_scan_pdf"
                        parsed["pdf_url"] = pdf_url
                        parsed["full_text"] = f"{parsed['full_text']}\n\n{pdf_text}".strip()
                        _enrich_from_scan_pdf_text(parsed, pdf_text)
                data = {
                    "source": source_type,
                    "source_url": url,
                    "history_key": _history_key(resp.text),
                    "timestamp": datetime.now().isoformat(),
                    **parsed,
                }
                await self.cache.set_judgment(cache_key, data, source=source_type)
                return await self._with_history({"success": True, "cached": False, **data})
        except WAFPermanentBlockError:
            logger.warning("取裁判書遭司法院 WAF 硬擋 (URL: %s)", url)
            return error_response(
                "司法院網站暫時無法通過 WAF 防護，請稍後重試", url=url,
            )
        except httpx.HTTPError as e:
            logger.warning("HTTP 取得裁判書失敗: %s", e)

        return error_response(f"無法取得裁判書全文（URL: {url}）", url=url)

    async def _with_history(self, result: dict) -> dict:
        """附上歷審清單。歷審會隨上訴變動，不跟全文一起快取 30 天，另以 24 小時快取。"""
        key = result.pop("history_key", "")
        if not key:
            return result
        cache_params = {"judgment_history": key}
        cached = await self.cache.get_search(cache_params)
        if cached is None:
            try:
                resp = await get_with_waf_retry(self.http, _HISTORY_URL + key, self.waf)
                resp.raise_for_status()
                cached = {"items": [_history_item(c) for c in json.loads(resp.text).get("list", [])]}
            except (httpx.HTTPError, ValueError, WAFPermanentBlockError, AttributeError) as e:
                logger.warning("取歷審清單失敗: %s", e)
                result["history_error"] = "歷審清單暫時取不到"
                return result
            await self.cache.set_search(cache_params, cached)
        result["history"] = cached["items"]
        result["history_note"] = _HISTORY_NOTE
        return result

    async def _fetch_via_http(self, jid: str) -> dict | None:
        """透過 HTTP GET data.aspx 取得裁判書（遇 WAF 自動刷 cookie 重試）"""
        # 用 httpx params 參數化：防 jid="x&ty=evil" 等注入綁 query string。
        params = {"ty": "JD", "id": jid}
        url = JUDICIAL_DATA_URL

        try:
            start = time.monotonic()
            resp = await get_with_waf_retry(self.http, url, self.waf, params=params)
            elapsed = time.monotonic() - start
            logger.info("HTTP data.aspx 回應: status=%d, elapsed=%.2fs, jid=%s",
                        resp.status_code, elapsed, jid)

            if resp.status_code != 200:
                return None

            soup = BeautifulSoup(resp.text, "lxml")
            jud_el = soup.select_one("#jud")

            if not jud_el:
                logger.info("data.aspx 無 #jud 元素 (JID: %s)", jid)
                return None

            full_text = jud_el.get_text(strip=False)
            if len(full_text) < 100:
                logger.info("data.aspx #jud 文字太短 (%d chars, JID: %s)", len(full_text), jid)
                return None

            jud_html = str(jud_el)
            parsed = parse_judgment_page(f"<html><body>{jud_html}</body></html>")

            if not parsed.get("full_text") or len(parsed["full_text"]) < len(full_text.strip()):
                parsed["full_text"] = full_text.strip()

            source_type = "http_data_aspx"
            pdf_url = _extract_scan_pdf_url(resp.text, jid)
            if pdf_url and not parsed.get("main_text") and not parsed.get("reasoning"):
                pdf_text = await self._fetch_scan_pdf_text(pdf_url)
                if pdf_text:
                    source_type = "http_scan_pdf"
                    parsed["pdf_url"] = pdf_url
                    parsed["full_text"] = f"{parsed['full_text']}\n\n{pdf_text}".strip()
                    _enrich_from_scan_pdf_text(parsed, pdf_text)

            data = {
                "source": source_type,
                "source_url": str(resp.url),
                "history_key": _history_key(resp.text),
                "timestamp": datetime.now().isoformat(),
                **parsed,
            }

            await self.cache.set_judgment(jid, data, source=source_type)
            return {"success": True, "cached": False, **data}

        except (httpx.HTTPError, ValueError) as e:
            logger.warning("HTTP data.aspx 呼叫失敗: %s", e)
            return None


    async def _fetch_scan_pdf_text(self, pdf_url: str) -> str:
        """下載司法院掃描裁判 PDF 並提取內嵌文字層"""
        try:
            resp = await get_with_waf_retry(self.http, pdf_url, self.waf)
            if resp.status_code == 200 and resp.content[:4] == b"%PDF":
                return extract_raw_pdf_text(resp.content)
        except Exception as e:
            logger.warning("下載或解析掃描裁判 PDF 失敗 (%s): %s", pdf_url, e)
        return ""


_SCAN_PDF_OBJ = re.compile(r'data=["\'](/FILES/[^"\']+\.pdf)["\']', re.I)


def _build_scan_pdf_url(jid: str) -> str:
    """由 JID 組出司法院 /FILES/{court}/{year},{word},{num},{date},{ver}.pdf 網址"""
    parts = [p.strip() for p in unquote(jid).split(",")]
    if len(parts) < 5:
        return ""
    court_code = parts[0]
    rest = ",".join(parts[1:])
    encoded_rest = quote(rest, safe=",")
    return f"https://judgment.judicial.gov.tw/FILES/{court_code}/{encoded_rest}.pdf"


def _extract_scan_pdf_url(page_html: str, jid: str = "") -> str:
    """從 data.aspx HTML 擷取 <object data="/FILES/...pdf"> 或由 JID 推導"""
    m = _SCAN_PDF_OBJ.search(page_html)
    if m:
        path = m.group(1)
        return f"https://judgment.judicial.gov.tw{path}" if path.startswith("/") else path
    return _build_scan_pdf_url(jid) if jid else ""


def _normalize_scan_headers(raw: str) -> str:
    """修復掃描 PDF 內嵌文字層常見的斷行標題（如「主\n文」「事\n實」「理\n由」）"""
    text = re.sub(
        r"(?:^|\n)[ \t\u3000]*主[ \t\u3000]*\n(?:[ \t\u3000]*\n)*[ \t\u3000]*文[ \t\u3000]*(?=\n|$)",
        "\n主文\n",
        raw,
    )
    text = re.sub(
        r"(?:^|\n)[ \t\u3000]*事[ \t\u3000]*\n(?:[ \t\u3000]*\n)*[ \t\u3000]*實[ \t\u3000]*(?=\n|$)",
        "\n事實\n",
        text,
    )
    text = re.sub(
        r"(?:^|\n)[ \t\u3000]*理[ \t\u3000]*\n(?:[ \t\u3000]*\n)*[ \t\u3000]*由[ \t\u3000]*(?=\n|$)",
        "\n理由\n",
        text,
    )
    return text


def _enrich_from_scan_pdf_text(parsed: dict, pdf_text: str) -> None:
    """以掃描 PDF 內嵌文字層補齊 main_text、facts、reasoning、judges、cited_statutes 等欄位，保留 HTML 原有 case_id/date/cause"""
    orig_case_id = parsed.get("case_id", "")
    orig_date = parsed.get("date", "")
    orig_cause = parsed.get("cause", "")
    parsed.setdefault("parties", {})
    norm_text = _normalize_scan_headers(pdf_text)
    _extract_sections(parsed, norm_text)
    if orig_case_id:
        parsed["case_id"] = orig_case_id
    if orig_date:
        parsed["date"] = orig_date
    if orig_cause:
        parsed["cause"] = orig_cause
    parsed["cited_statutes"] = _extract_cited_statutes(parsed["full_text"])
    parsed["cited_cases"] = _extract_cited_cases(parsed["full_text"])


def _history_key(page_html: str) -> str:
    m = _HISTORY_KEY.search(page_html)
    return m.group(1) if m else ""
