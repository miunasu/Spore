"""
Episodic Memory Store
存储和检索完整的任务执行记录
"""
import json
import math
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import uuid

from .embedding import EmbeddingGenerator


class EpisodeStore:
    """管理 episodic memory 的存储和检索"""
    
    def __init__(self, db_path: str = "F:/friend/spore/memory/episodic.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.embedding_gen = EmbeddingGenerator()
        self._init_database()
    
    def _init_database(self):
        """初始化数据库 schema"""
        schema_path = Path(__file__).parent / "schema.sql"
        
        with sqlite3.connect(self.db_path) as conn:
            with open(schema_path, 'r', encoding='utf-8') as f:
                schema_sql = f.read()
            conn.executescript(schema_sql)
            conn.commit()
    
    def add_episode(
        self,
        task_type: str,
        input_data: Dict[str, Any],
        output_data: Dict[str, Any],
        outcome: str,
        source: str = "user",
        trust_zone: str = "verified",
        reasoning_trace: Optional[List[str]] = None,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        salience: float = 0.5,
        half_life_days: int = 90
    ) -> str:
        """
        添加一条 episodic 记录
        
        Args:
            task_type: 任务类型标签
            input_data: 任务输入数据
            output_data: 任务输出数据
            outcome: 任务结果 (success/partial/failed)
            source: 来源 (user/tool/spore-self)
            trust_zone: 可信度 (verified/inferred/speculative)
            reasoning_trace: 推理痕迹列表
            tool_calls: 工具调用记录列表
            evidence: 证据链
            salience: 显著性评分 (0-1)
            half_life_days: 半衰期（天）
            
        Returns:
            episode_id: 生成的记录 ID
        """
        # 生成唯一 ID
        timestamp = datetime.now(timezone.utc)
        episode_id = f"ep_{timestamp.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:4]}"
        
        # 准备数据
        input_json = json.dumps(input_data, ensure_ascii=False)
        output_json = json.dumps(output_data, ensure_ascii=False)
        reasoning_json = json.dumps(reasoning_trace or [], ensure_ascii=False)
        tool_calls_json = json.dumps(tool_calls or [], ensure_ascii=False)
        evidence_json = json.dumps(evidence or {}, ensure_ascii=False)
        
        # 生成 embedding（使用 user_query 作为主要文本）
        query_text = input_data.get('user_query', '')
        if query_text:
            embedding = self.embedding_gen.generate(query_text)
            embedding_blob = self.embedding_gen.serialize_embedding(embedding)
        else:
            embedding_blob = None
        
        # 写入数据库
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO episodes (
                    episode_id, timestamp, source, trust_zone, task_type,
                    input_json, reasoning_trace, tool_calls, output_json,
                    outcome, salience, evidence, half_life_days
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                episode_id,
                timestamp.isoformat(),
                source,
                trust_zone,
                task_type,
                input_json,
                reasoning_json,
                tool_calls_json,
                output_json,
                outcome,
                salience,
                evidence_json,
                half_life_days
            ))
            
            # 写入 embedding
            if embedding_blob:
                conn.execute("""
                    INSERT INTO episodes_embeddings (
                        episode_id, embedding, embedding_model, embedding_dim
                    ) VALUES (?, ?, ?, ?)
                """, (
                    episode_id,
                    embedding_blob,
                    self.embedding_gen.model,
                    self.embedding_gen.embedding_dim
                ))
            
            conn.commit()
        
        return episode_id
    
    def get_episode(self, episode_id: str) -> Optional[Dict[str, Any]]:
        """获取单条 episode 记录"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM episodes WHERE episode_id = ?
            """, (episode_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return self._row_to_dict(row)
    
    def search_similar(
        self,
        query: str,
        top_k: int = 5,
        task_type: Optional[str] = None,
        recency_weight: float = 0.3,
        relevance_weight: float = 0.5,
        salience_weight: float = 0.2
    ) -> List[Tuple[Dict[str, Any], float]]:
        """
        检索相似的 episodic 记录
        
        使用三因子评分：
        - Recency: 时间近度（指数衰减）
        - Relevance: 语义相似度（cosine similarity）
        - Salience: 显著性评分
        
        Returns:
            List of (episode_dict, score) tuples, sorted by score descending
        """
        # 生成 query embedding
        query_embedding = self.embedding_gen.generate(query)
        
        # 获取候选记录
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # 构建查询
            sql = """
                SELECT e.*, ee.embedding
                FROM episodes e
                LEFT JOIN episodes_embeddings ee ON e.episode_id = ee.episode_id
                WHERE e.superseded_by IS NULL
            """
            params = []
            
            if task_type:
                sql += " AND e.task_type = ?"
                params.append(task_type)
            
            sql += " ORDER BY e.timestamp DESC LIMIT 100"
            
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
        
        # 计算三因子评分
        scored_episodes = []
        now = datetime.now(timezone.utc)
        
        for row in rows:
            episode = self._row_to_dict(row)
            
            # Recency: 时间衰减
            timestamp = datetime.fromisoformat(episode['timestamp'])
            days_ago = (now - timestamp).total_seconds() / 86400
            half_life = episode['half_life_days']
            recency_score = math.exp(-days_ago / half_life)
            
            # Relevance: 语义相似度
            relevance_score = 0.0
            if row['embedding']:
                episode_embedding = self.embedding_gen.deserialize_embedding(row['embedding'])
                relevance_score = self.embedding_gen.cosine_similarity(
                    query_embedding, episode_embedding
                )
            
            # Salience: 显著性
            salience_score = episode['salience']
            
            # 综合评分
            final_score = (
                recency_weight * recency_score +
                relevance_weight * relevance_score +
                salience_weight * salience_score
            )
            
            scored_episodes.append((episode, final_score))
        
        # 排序并返回 top_k
        scored_episodes.sort(key=lambda x: x[1], reverse=True)
        return scored_episodes[:top_k]
    
    def list_episodes(
        self,
        task_type: Optional[str] = None,
        outcome: Optional[str] = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """列出 episodes"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            sql = "SELECT * FROM episodes WHERE 1=1"
            params = []
            
            if task_type:
                sql += " AND task_type = ?"
                params.append(task_type)
            
            if outcome:
                sql += " AND outcome = ?"
                params.append(outcome)
            
            sql += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
        
        return [self._row_to_dict(row) for row in rows]
    
    def mark_superseded(self, old_episode_id: str, new_episode_id: str):
        """标记旧记录被新记录修正"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE episodes SET superseded_by = ? WHERE episode_id = ?
            """, (new_episode_id, old_episode_id))
            conn.commit()
    
    def update_salience(self, episode_id: str, salience: float):
        """更新显著性评分"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE episodes SET salience = ? WHERE episode_id = ?
            """, (salience, episode_id))
            conn.commit()
    
    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        """Convert SQLite Row to dict, parsing JSON fields"""
        episode = dict(row)
        
        # 解析 JSON 字段
        if episode.get('input_json'):
            episode['input'] = json.loads(episode['input_json'])
            del episode['input_json']
        
        if episode.get('output_json'):
            episode['output'] = json.loads(episode['output_json'])
            del episode['output_json']
        
        if episode.get('reasoning_trace'):
            episode['reasoning_trace'] = json.loads(episode['reasoning_trace'])
        
        if episode.get('tool_calls'):
            episode['tool_calls'] = json.loads(episode['tool_calls'])
        
        if episode.get('evidence'):
            episode['evidence'] = json.loads(episode['evidence'])
        
        # 移除内部字段
        if 'embedding' in episode:
            del episode['embedding']
        
        return episode