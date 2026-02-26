from typing import Optional, Union

import httpx
from openai import OpenAI, AsyncOpenAI

from .config import get_config

# Anthropic SDK 延迟导入，避免未安装时报错
_anthropic_available = False
try:
    from anthropic import Anthropic, AsyncAnthropic
    _anthropic_available = True
except ImportError:
    Anthropic = None
    AsyncAnthropic = None


class CleanHeadersTransport(httpx.HTTPTransport):
    """
    自定义 HTTP Transport，移除 SDK 添加的特定 headers。
    某些第三方 API 代理（如 packyapi）会拦截带有这些 headers 的请求。
    
    移除的 headers:
    - x-stainless-*: OpenAI/Anthropic SDK 的追踪头
    - authorization (可选): Anthropic SDK 会同时发送 x-api-key 和 authorization
    """
    def __init__(self, clean_auth: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.clean_auth = clean_auth
    
    def handle_request(self, request):
        headers_to_remove = [k for k in request.headers.keys() if k.lower().startswith('x-stainless')]
        if self.clean_auth:
            headers_to_remove.extend([k for k in request.headers.keys() if k.lower() == 'authorization'])
        for h in headers_to_remove:
            del request.headers[h]
        request.headers['user-agent'] = 'python-httpx/0.27.0'
        return super().handle_request(request)


class AsyncCleanHeadersTransport(httpx.AsyncHTTPTransport):
    """异步版本的 CleanHeadersTransport"""
    def __init__(self, clean_auth: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.clean_auth = clean_auth
    
    async def handle_async_request(self, request):
        headers_to_remove = [k for k in request.headers.keys() if k.lower().startswith('x-stainless')]
        if self.clean_auth:
            headers_to_remove.extend([k for k in request.headers.keys() if k.lower() == 'authorization'])
        for h in headers_to_remove:
            del request.headers[h]
        request.headers['user-agent'] = 'python-httpx/0.27.0'
        return await super().handle_async_request(request)


def load_openai_client() -> OpenAI:
    """加载 OpenAI 客户端"""
    config = get_config()
    api_key = config.openai_api_key
    base_url: Optional[str] = config.openai_api_url
    
    # 根据配置决定是否清理 headers（OpenAI 不需要清理 auth header）
    if config.clean_sdk_headers:
        http_client = httpx.Client(transport=CleanHeadersTransport(clean_auth=False))
        if base_url:
            return OpenAI(api_key=api_key, base_url=base_url, http_client=http_client)
        return OpenAI(api_key=api_key, http_client=http_client)
    
    if base_url:
        return OpenAI(api_key=api_key, base_url=base_url)
    return OpenAI(api_key=api_key)


def load_async_openai_client() -> AsyncOpenAI:
    """加载异步 OpenAI 客户端"""
    config = get_config()
    api_key = config.openai_api_key
    base_url: Optional[str] = config.openai_api_url
    
    # 根据配置决定是否清理 headers（OpenAI 不需要清理 auth header）
    if config.clean_sdk_headers:
        http_client = httpx.AsyncClient(transport=AsyncCleanHeadersTransport(clean_auth=False))
        if base_url:
            return AsyncOpenAI(api_key=api_key, base_url=base_url, http_client=http_client)
        return AsyncOpenAI(api_key=api_key, http_client=http_client)
    
    if base_url:
        return AsyncOpenAI(api_key=api_key, base_url=base_url)
    return AsyncOpenAI(api_key=api_key)


def load_anthropic_client() -> "Anthropic":
    """加载 Anthropic 客户端"""
    if not _anthropic_available:
        raise RuntimeError("Anthropic SDK 未安装。请运行: pip install anthropic")
    
    config = get_config()
    api_key = config.anthropic_api_key
    base_url: Optional[str] = config.anthropic_api_url
    
    # 根据配置决定是否清理 headers
    if config.clean_sdk_headers or config.clean_auth_header:
        transport = CleanHeadersTransport(clean_auth=config.clean_auth_header)
        http_client = httpx.Client(transport=transport)
        if base_url:
            return Anthropic(api_key=api_key, base_url=base_url, http_client=http_client)
        return Anthropic(api_key=api_key, http_client=http_client)
    
    if base_url:
        return Anthropic(api_key=api_key, base_url=base_url)
    return Anthropic(api_key=api_key)


def load_async_anthropic_client() -> "AsyncAnthropic":
    """加载异步 Anthropic 客户端"""
    if not _anthropic_available:
        raise RuntimeError("Anthropic SDK 未安装。请运行: pip install anthropic")
    
    config = get_config()
    api_key = config.anthropic_api_key
    base_url: Optional[str] = config.anthropic_api_url
    
    # 根据配置决定是否清理 headers
    if config.clean_sdk_headers or config.clean_auth_header:
        transport = AsyncCleanHeadersTransport(clean_auth=config.clean_auth_header)
        http_client = httpx.AsyncClient(transport=transport)
        if base_url:
            return AsyncAnthropic(api_key=api_key, base_url=base_url, http_client=http_client)
        return AsyncAnthropic(api_key=api_key, http_client=http_client)
    
    if base_url:
        return AsyncAnthropic(api_key=api_key, base_url=base_url)
    return AsyncAnthropic(api_key=api_key)


def load_llm_client() -> Union[OpenAI, "Anthropic"]:
    """根据配置加载对应的 LLM 客户端"""
    config = get_config()
    if config.llm_sdk == "anthropic":
        return load_anthropic_client()
    return load_openai_client()


