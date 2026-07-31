"""
Embedding generation using OpenAI API

仅使用 EMBEDDING_API_* 专用配置；未配置时由调用方禁用 Learning。
"""
import os
import struct
import time
from typing import List, Optional
import requests


class EmbeddingGenerator:
    """Generate embeddings using OpenAI-compatible API"""

    # 类级别熔断器状态（所有实例共享）
    # 连续失败超过阈值后，直接跳过 embedding 调用，避免阻塞 LLM 请求
    _failure_count: int = 0
    _last_failure_time: float = 0.0
    _CIRCUIT_OPEN_THRESHOLD: int = 3   # 连续失败几次后开路
    _CIRCUIT_RESET_SECONDS: float = 60.0  # 开路后多少秒尝试半开
    _REQUEST_TIMEOUT: int = 5  # 单次请求超时（秒）

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        model: Optional[str] = None,
    ):
        # 优先使用显式传入参数，其次读专用 EMBEDDING_* 配置；不复用聊天 API。
        try:
            from base.config import get_config
            cfg = get_config()
            self.api_key = api_key or cfg.embedding_api_key or ""
            resolved_url = api_url or cfg.embedding_api_url or "https://api.openai.com/v1"
            self.model = model or cfg.embedding_model or "text-embedding-3-small"
        except Exception:
            # config 不可用（测试环境等），直接读专用环境变量
            self.api_key = api_key or os.getenv("EMBEDDING_API_KEY", "")
            resolved_url = api_url or os.getenv("EMBEDDING_API_URL") or "https://api.openai.com/v1"
            self.model = model or os.getenv("EMBEDDING_MODEL") or "text-embedding-3-small"

        if not self.api_key:
            raise ValueError("Embedding API key not found (set EMBEDDING_API_KEY)")

        # 确保 base_url 以 /v1 结尾
        if not resolved_url.endswith("/v1"):
            resolved_url = resolved_url.rstrip("/") + "/v1"
        self.api_url = f"{resolved_url}/embeddings"

        # text-embedding-3-small 的维度是 1536
        self.embedding_dim = 1536

    # ------------------------------------------------------------------
    # 熔断器辅助方法
    # ------------------------------------------------------------------
    @classmethod
    def _is_circuit_open(cls) -> bool:
        """熔断器是否处于开路状态（服务不可用，直接跳过）"""
        if cls._failure_count >= cls._CIRCUIT_OPEN_THRESHOLD:
            if time.time() - cls._last_failure_time < cls._CIRCUIT_RESET_SECONDS:
                return True
            # 超过冷却时间，进入半开状态，允许一次试探
            cls._failure_count = 0
        return False

    @classmethod
    def _record_failure(cls) -> None:
        cls._failure_count += 1
        cls._last_failure_time = time.time()

    @classmethod
    def _record_success(cls) -> None:
        cls._failure_count = 0

    def probe(self) -> bool:
        """
        启动探针：向 embedding API 发一个最小请求，
        确认服务可用。不可用时返回 False（不修改熔断器计数）。
        """
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            payload = {"model": self.model, "input": "ping", "encoding_format": "float"}
            resp = requests.post(
                self.api_url, json=payload, headers=headers, timeout=5
            )
            resp.raise_for_status()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # 核心接口
    # ------------------------------------------------------------------
    def generate(self, text: str) -> List[float]:
        """Generate embedding for a single text"""
        if self._is_circuit_open():
            raise RuntimeError(
                f"Embedding service circuit breaker open "
                f"(>{self._CIRCUIT_OPEN_THRESHOLD} consecutive failures, "
                f"retry in {max(0, int(self._CIRCUIT_RESET_SECONDS - (time.time() - self._last_failure_time)))}s)"
            )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "input": text,
            "encoding_format": "float",
        }

        try:
            response = requests.post(
                self.api_url, json=payload, headers=headers,
                timeout=self._REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            self._record_success()
            return response.json()["data"][0]["embedding"]
        except Exception:
            self._record_failure()
            raise

    def generate_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts"""
        if self._is_circuit_open():
            raise RuntimeError(
                f"Embedding service circuit breaker open "
                f"(>{self._CIRCUIT_OPEN_THRESHOLD} consecutive failures)"
            )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "input": texts,
            "encoding_format": "float",
        }

        try:
            response = requests.post(
                self.api_url, json=payload, headers=headers,
                timeout=self._REQUEST_TIMEOUT * 2,  # batch 给两倍时间
            )
            response.raise_for_status()
            self._record_success()
            return [item["embedding"] for item in response.json()["data"]]
        except Exception:
            self._record_failure()
            raise

    @staticmethod
    def serialize_embedding(embedding: List[float]) -> bytes:
        """Convert embedding to binary format for storage"""
        return struct.pack(f'{len(embedding)}f', *embedding)

    @staticmethod
    def deserialize_embedding(blob: bytes) -> List[float]:
        """Convert binary format back to embedding"""
        num_floats = len(blob) // 4
        return list(struct.unpack(f'{num_floats}f', blob))

    @staticmethod
    def cosine_similarity(a: List[float], b: List[float]) -> float:
        """Calculate cosine similarity between two embeddings"""
        dot_product = sum(x * y for x, y in zip(a, b))
        magnitude_a = sum(x * x for x in a) ** 0.5
        magnitude_b = sum(x * x for x in b) ** 0.5

        if magnitude_a == 0 or magnitude_b == 0:
            return 0.0

        return dot_product / (magnitude_a * magnitude_b)
