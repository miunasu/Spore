"""
Embedding generation using OpenAI API
"""
import os
import struct
from typing import List, Optional
import requests


class EmbeddingGenerator:
    """Generate embeddings using OpenAI API"""
    
    def __init__(self, api_key: Optional[str] = None, api_url: Optional[str] = None, model: str = "text-embedding-3-small"):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not found in environment")
        
        self.model = model
        
        # 支持自定义 API URL
        base_url = api_url or os.getenv("OPENAI_API_URL", "https://api.openai.com/v1")
        # 确保 URL 以 /v1 结尾但不重复
        if not base_url.endswith('/v1'):
            base_url = base_url.rstrip('/') + '/v1'
        self.api_url = f"{base_url}/embeddings"
        
        # text-embedding-3-small 的维度是 1536
        self.embedding_dim = 1536
    
    def generate(self, text: str) -> List[float]:
        """Generate embedding for a single text"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "input": text,
            "encoding_format": "float"
        }
        
        response = requests.post(self.api_url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        embedding = data["data"][0]["embedding"]
        
        return embedding
    
    def generate_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "input": texts,
            "encoding_format": "float"
        }
        
        response = requests.post(self.api_url, json=payload, headers=headers, timeout=60)
        response.raise_for_status()
        
        data = response.json()
        embeddings = [item["embedding"] for item in data["data"]]
        
        return embeddings
    
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