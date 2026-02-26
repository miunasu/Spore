"""Utility helpers for web browsing and search functionality."""
from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from ddgs import DDGS
from ..logger import log_tool_error
from ..config import get_config

# 从配置获取默认值（向后兼容）
_config = get_config()
DEFAULT_TIMEOUT = _config.web_browser_timeout
DEFAULT_PROXY_PORT = _config.web_proxy_port
MAX_CONTENT_LENGTH = _config.web_max_content_length
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/91.0.4472.124 Safari/537.36"
)

_CHINESE_DOMAINS = {
    ".cn",
    ".com.cn",
    ".net.cn",
    ".gov.cn",
    ".edu.cn",
    "baidu.com",
    "taobao.com",
    "qq.com",
    "zhihu.com",
    "bilibili.com",
    "csdn.net",
    "jd.com",
    "sina.com.cn",
    "weibo.com",
    "sohu.com",
    "163.com",
    "ifeng.com",
    "tudou.com",
    "youku.com",
    "douban.com",
    "alibaba.com",
    "aliyun.com",
    "tencent.com",
    "weixin.com",
    "meituan.com",
    "dianping.com",
    "ctrip.com",
    "qunar.com",
    "netease.com",
    "sogou.com",
    "360.cn",
    "360.com",
    "mi.com",
    "xiaomi.com",
    "huawei.com",
    "oppo.com",
    "vivo.com",
    "antiy.cn",
    "antiy.net",
    "antiy.com",
}


def _is_chinese_domain(domain: str) -> bool:
    normalized = domain.lower()
    for chinese_domain in _CHINESE_DOMAINS:
        if normalized.endswith(chinese_domain):
            return True
    return False


def _get_proxies(url: str, proxy_port: int) -> Optional[Dict[str, str]]:
    # 如果 proxy_port 为 0，表示禁用代理
    if proxy_port == 0:
        return None
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if ":" in domain:
        domain = domain.split(":", 1)[0]

    if _is_chinese_domain(domain):
        return None

    proxy = f"http://127.0.0.1:{proxy_port}"
    return {"http": proxy, "https": proxy}


def visit_url(
    url: str,
    *,
    extract_text: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    debug: bool = False,
    proxy_port: int = DEFAULT_PROXY_PORT,
) -> Dict[str, Any]:
    try:
        proxies = _get_proxies(url, proxy_port)
        headers = {"User-Agent": USER_AGENT}

        response = requests.get(
            url,
            timeout=timeout,
            proxies=proxies,
            headers=headers,
        )

        if response.status_code != 200:
            return {"ok": False, "error": f"HTTP {response.status_code}"}

        result: Dict[str, Any] = {
            "ok": True,
            "url": url,
            "status_code": response.status_code,
        }

        if extract_text:
            soup = BeautifulSoup(response.content, "lxml")
            for script in soup(["script", "style"]):
                script.decompose()

            text = soup.get_text()
            lines = (line.strip() for line in text.splitlines())
            chunks = (
                phrase.strip()
                for line in lines
                for phrase in line.split("  ")
            )
            text_content = "\n".join(chunk for chunk in chunks if chunk)

            if len(text_content) > MAX_CONTENT_LENGTH:
                text_content = text_content[:MAX_CONTENT_LENGTH] + "... [内容被截断]"

            result.update(
                {
                    "title": (soup.title.string or "") if soup.title else "",
                    "content": text_content,
                    "content_length": len(text_content),
                }
            )
        else:
            html_content = response.text
            if len(html_content) > MAX_CONTENT_LENGTH:
                html_content = html_content[:MAX_CONTENT_LENGTH] + "... [内容被截断]"

            result.update(
                {
                    "html": html_content,
                    "html_length": len(html_content),
                }
            )

        if debug:
            result["debug"] = {
                "proxies": proxies,
                "timeout": timeout,
            }

        return result

    except Exception as exc:
        log_tool_error("web_browser", f"Failed to visit URL: {url}", {"url": url}, exc)
        return {"ok": False, "error": str(exc)}


def search(query: str, *, num_results: int = 10) -> Dict[str, Any]:
    try:
        ddgs = DDGS()
        results = []
        for entry in ddgs.text(query, max_results=num_results):
            results.append(
                {
                    "title": entry.get("title", ""),
                    "url": entry.get("href", ""),
                    "description": entry.get("body", ""),
                    "engine": "duckduckgo",
                }
            )

        return {
            "ok": True,
            "engine": "duckduckgo",
            "query": query,
            "num_results": len(results),
            "results": results,
        }

    except Exception as exc:
        log_tool_error("web_browser", f"Search failed for query: {query}", {"query": query}, exc)
        return {"ok": False, "error": str(exc)}


def web_browser(
    action: str,
    target: str,
    *,
    num_results: int = 10,
    raw: bool = False,
    debug: bool = False,
    proxy_port: int = DEFAULT_PROXY_PORT,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    if not action:
        return {"ok": False, "error": "参数缺失: action"}
    if not target:
        return {"ok": False, "error": "参数缺失: target"}

    normalized = action.strip().lower()
    if normalized == "visit":
        return visit_url(
            target,
            extract_text=not raw,
            timeout=timeout,
            debug=debug,
            proxy_port=proxy_port,
        )
    if normalized == "search":
        return search(target, num_results=num_results)

    return {"ok": False, "error": f"不支持的 action: {action}"}


__all__ = ["visit_url", "search", "web_browser"]
