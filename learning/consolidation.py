"""
Phase 3: Consolidation
定期将episodic记录合并成semantic知识
"""
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from .episode_store import EpisodeStore


class ConsolidationEngine:
    """管理 episodic -> semantic 的知识提炼"""
    
    def __init__(
        self,
        episode_store: Optional[EpisodeStore] = None,
        db_path: str = "F:/friend/spore/memory/episodic.db"
    ):
        self.store = episode_store or EpisodeStore()
        self.db_path = Path(db_path)
    
    def find_consolidation_candidates(
        self,
        task_type: str,
        min_episodes: int = 3,
        min_success_rate: float = 0.6
    ) -> List[str]:
        """
        查找适合 consolidation 的 episode 集群
        
        Args:
            task_type: 任务类型
            min_episodes: 最少记录数
            min_success_rate: 最低成功率
            
        Returns:
            符合条件的 episode_id 列表
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # 获取该任务类型的所有成功记录
            cursor = conn.execute("""
                SELECT episode_id, outcome, salience
                FROM episodes
                WHERE task_type = ?
                  AND superseded_by IS NULL
                  AND outcome IN ('success', 'partial')
                ORDER BY timestamp DESC
                LIMIT 50
            """, (task_type,))
            
            rows = cursor.fetchall()
        
        if len(rows) < min_episodes:
            return []
        
        # 计算成功率
        success_count = sum(1 for r in rows if r['outcome'] == 'success')
        success_rate = success_count / len(rows)
        
        if success_rate < min_success_rate:
            return []
        
        # 返回高显著性的记录
        candidates = [
            r['episode_id']
            for r in rows
            if r['salience'] >= 0.5
        ][:min_episodes * 2]  # 最多取 2 倍数量
        
        return candidates
    
    def extract_patterns(
        self,
        episode_ids: List[str]
    ) -> Dict[str, Any]:
        """
        从一组 episodes 中提取共性模式
        
        Returns:
            包含模式信息的字典
        """
        episodes = [self.store.get_episode(eid) for eid in episode_ids]
        episodes = [e for e in episodes if e]  # 过滤空值
        
        if not episodes:
            return {}
        
        # 提取共性
        task_types = set(e['task_type'] for e in episodes)
        outcomes = [e['outcome'] for e in episodes]
        
        # 统计工具使用
        tool_usage = {}
        for episode in episodes:
            if episode.get('tool_calls'):
                for tool in episode['tool_calls']:
                    tool_name = tool.get('tool', 'unknown')
                    tool_usage[tool_name] = tool_usage.get(tool_name, 0) + 1
        
        # 提取推理步骤关键词
        reasoning_keywords = set()
        for episode in episodes:
            if episode.get('reasoning_trace'):
                for step in episode['reasoning_trace']:
                    # 简单的关键词提取（实际应用中可用 LLM）
                    words = step.lower().split()
                    reasoning_keywords.update(words[:5])
        
        return {
            'task_types': list(task_types),
            'success_rate': outcomes.count('success') / len(outcomes),
            'total_episodes': len(episodes),
            'common_tools': sorted(tool_usage.items(), key=lambda x: x[1], reverse=True)[:5],
            'reasoning_keywords': list(reasoning_keywords)[:20],
            'timestamps': [e['timestamp'] for e in episodes]
        }
    
    def create_semantic_knowledge(
        self,
        task_type: str,
        knowledge_text: str,
        source_episode_ids: List[str],
        confidence: float = 0.8,
        actor: str = "consolidation_engine"
    ) -> str:
        """
        创建一条 semantic knowledge 记录
        
        Args:
            task_type: 任务类型
            knowledge_text: 知识描述
            source_episode_ids: 来源 episode 列表
            confidence: 置信度 (0-1)
            actor: 创建者标识
            
        Returns:
            semantic_id
        """
        timestamp = datetime.now(timezone.utc)
        semantic_id = f"sem_{timestamp.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:4]}"
        
        source_episodes_json = json.dumps(source_episode_ids)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO semantic_knowledge (
                    semantic_id, task_type, knowledge, source_episodes,
                    confidence, actor, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                semantic_id,
                task_type,
                knowledge_text,
                source_episodes_json,
                confidence,
                actor,
                timestamp.isoformat()
            ))
            conn.commit()
        
        return semantic_id
    
    def consolidate_task_type(
        self,
        task_type: str,
        llm_summarize_func: Optional[callable] = None
    ) -> Optional[str]:
        """
        对某个任务类型执行 consolidation
        
        Args:
            task_type: 任务类型
            llm_summarize_func: LLM 总结函数 (episodes_data -> knowledge_text)
                                如果为 None，使用简单的模式提取
            
        Returns:
            semantic_id 或 None（如果没有生成知识）
        """
        # 查找候选记录
        candidates = self.find_consolidation_candidates(task_type)
        
        if len(candidates) < 3:
            return None
        
        # 提取模式
        patterns = self.extract_patterns(candidates)
        
        # 生成知识描述
        if llm_summarize_func:
            # 使用 LLM 总结
            episodes_data = [self.store.get_episode(eid) for eid in candidates]
            knowledge_text = llm_summarize_func(episodes_data)
        else:
            # 简单模式总结
            knowledge_text = self._simple_summarize(task_type, patterns)
        
        # 创建 semantic knowledge
        semantic_id = self.create_semantic_knowledge(
            task_type=task_type,
            knowledge_text=knowledge_text,
            source_episode_ids=candidates,
            confidence=patterns['success_rate']
        )
        
        return semantic_id
    
    def _simple_summarize(self, task_type: str, patterns: Dict[str, Any]) -> str:
        """简单的模式总结（不使用 LLM）"""
        lines = [f"任务类型 '{task_type}' 的执行模式:"]
        lines.append(f"- 成功率: {patterns['success_rate']:.1%}")
        lines.append(f"- 基于 {patterns['total_episodes']} 条历史记录")
        
        if patterns['common_tools']:
            lines.append("- 常用工具:")
            for tool, count in patterns['common_tools']:
                lines.append(f"  - {tool} (使用 {count} 次)")
        
        return "\n".join(lines)
    
    def get_semantic_knowledge(
        self,
        task_type: Optional[str] = None,
        min_confidence: float = 0.5,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        获取 semantic knowledge 记录
        
        Args:
            task_type: 任务类型过滤
            min_confidence: 最低置信度
            limit: 返回数量
            
        Returns:
            knowledge 记录列表
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            sql = """
                SELECT * FROM semantic_knowledge
                WHERE confidence >= ?
            """
            params = [min_confidence]
            
            if task_type:
                sql += " AND task_type = ?"
                params.append(task_type)
            
            sql += " ORDER BY confidence DESC, created_at DESC LIMIT ?"
            params.append(limit)
            
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
        
        results = []
        for row in rows:
            record = dict(row)
            record['source_episodes'] = json.loads(record['source_episodes'])
            results.append(record)
        
        return results
    
    def run_periodic_consolidation(
        self,
        task_types: Optional[List[str]] = None,
        llm_summarize_func: Optional[callable] = None
    ) -> Dict[str, str]:
        """
        运行定期 consolidation 任务
        
        Args:
            task_types: 要处理的任务类型列表，None 则自动发现
            llm_summarize_func: LLM 总结函数
            
        Returns:
            {task_type: semantic_id} 字典
        """
        if task_types is None:
            # 自动发现有足够记录的任务类型
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT task_type, COUNT(*) as cnt
                    FROM episodes
                    WHERE superseded_by IS NULL
                      AND outcome IN ('success', 'partial')
                    GROUP BY task_type
                    HAVING cnt >= 3
                    ORDER BY cnt DESC
                """)
                task_types = [row[0] for row in cursor.fetchall()]
        
        results = {}
        for task_type in task_types:
            semantic_id = self.consolidate_task_type(
                task_type=task_type,
                llm_summarize_func=llm_summarize_func
            )
            if semantic_id:
                results[task_type] = semantic_id
        
        return results
    
    def resolve_conflict(
        self,
        old_semantic_id: str,
        new_knowledge_text: str,
        confidence: float,
        actor: str = "conflict_resolver"
    ) -> str:
        """
        解决知识冲突，创建修正记录
        
        Args:
            old_semantic_id: 旧知识 ID
            new_knowledge_text: 新知识描述
            confidence: 新知识置信度
            actor: 修正者
            
        Returns:
            新的 semantic_id
        """
        # 获取旧记录
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM semantic_knowledge WHERE semantic_id = ?",
                (old_semantic_id,)
            )
            old_record = cursor.fetchone()
        
        if not old_record:
            raise ValueError(f"Semantic knowledge not found: {old_semantic_id}")
        
        # 创建新记录
        timestamp = datetime.now(timezone.utc)
        new_semantic_id = f"sem_{timestamp.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:4]}"
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO semantic_knowledge (
                    semantic_id, task_type, knowledge, source_episodes,
                    confidence, actor, supersedes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                new_semantic_id,
                old_record['task_type'],
                new_knowledge_text,
                old_record['source_episodes'],
                confidence,
                actor,
                old_semantic_id,
                timestamp.isoformat()
            ))
            conn.commit()
        
        return new_semantic_id