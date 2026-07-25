"""
Spore Learning System - Episodic and Semantic Memory
"""

from .episode_store import EpisodeStore
from .embedding import EmbeddingGenerator
from .retrieval import EpisodicRetriever
from .consolidation import ConsolidationEngine

__all__ = ['EpisodeStore', 'EmbeddingGenerator', 'EpisodicRetriever', 'ConsolidationEngine']