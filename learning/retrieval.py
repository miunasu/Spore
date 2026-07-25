"""
Phase 2: Retrieval Integration
在任务开始时自动检索相似的历史记录，为LLM提供上下文
"""
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from .episode_store import EpisodeStore


class EpisodicRetriever:
    """管理 episodic memory 的检索和上下文注入"""
    
    def __init__(self, episode_store: Optional[EpisodeStore] = None):
        self.store = episode_store or EpisodeStore()
    
    def retrieve_for_task(
        self,
        user_query: str,
        task_type: Optional[str] = None,
        top_k: int = 3,
        min_score: float = 0.3,
        recency_weight: float = 0.3,
        relevance_weight: float = 0.5,
        salience_weight: float = 0.2
    ) -> List[Dict[str, Any]]:
        """
        为新任务检索相关的历史记录
        
        Args:
            user_query: 用户查询
            task_type: 任务类型过滤
            top_k: 返回记录数
            min_score: 最低相似度阈值
            recency_weight: 时间权重
            relevance_weight: 相似度权重
            salience_weight: 显著性权重
            
        Returns:
            相关的 episode 列表，按相关性排序
        """
        # 使用 EpisodeStore 的三因子检索
        results = self.store.search_similar(
            query=user_query,
            top_k=top_k,
            task_type=task_type,
            recency_weight=recency_weight,
            relevance_weight=relevance_weight,
            salience_weight=salience_weight
        )
        
        # 过滤低分记录
        filtered = [
            {
                'episode': episode,
                'score': score
            }
            for episode, score in results
            if score >= min_score
        ]
        
        return filtered
    
    def format_for_prompt(
        self,
        retrieved_episodes: List[Dict[str, Any]],
        max_episodes: int = 3,
        include_reasoning: bool = True,
        include_tools: bool = False
    ) -> str:
        """
        将检索到的 episodes 格式化为可注入 prompt 的文本
        
        Args:
            retrieved_episodes: retrieve_for_task() 返回的结果
            max_episodes: 最多包含的记录数
            include_reasoning: 是否包含推理过程
            include_tools: 是否包含工具调用记录
            
        Returns:
            格式化的文本，可直接注入 system prompt
        """
        if not retrieved_episodes:
            return ""
        
        lines = ["## 相关历史经验\n"]
        lines.append("以下是与当前任务相关的历史执行记录，供参考：\n")
        
        for idx, item in enumerate(retrieved_episodes[:max_episodes], 1):
            episode = item['episode']
            score = item['score']
            
            lines.append(f"### 记录 {idx} (相关度: {score:.2f})")
            lines.append(f"**任务类型**: {episode['task_type']}")
            lines.append(f"**时间**: {episode['timestamp'][:10]}")
            lines.append(f"**结果**: {episode['outcome']}")
            
            # 输入
            if 'input' in episode and 'user_query' in episode['input']:
                lines.append(f"**用户查询**: {episode['input']['user_query']}")
            
            # 推理过程
            if include_reasoning and episode.get('reasoning_trace'):
                lines.append(f"**推理步骤**:")
                for step_idx, step in enumerate(episode['reasoning_trace'][:5], 1):
                    lines.append(f"  {step_idx}. {step}")
                if len(episode['reasoning_trace']) > 5:
                    lines.append(f"  ... (共 {len(episode['reasoning_trace'])} 步)")
            
            # 工具调用
            if include_tools and episode.get('tool_calls'):
                lines.append(f"**工具使用**: {len(episode['tool_calls'])} 个工具调用")
                for tool in episode['tool_calls'][:3]:
                    if 'tool' in tool:
                        lines.append(f"  - {tool['tool']}")
            
            # 输出摘要
            if 'output' in episode:
                output_str = json.dumps(episode['output'], ensure_ascii=False)
                if len(output_str) > 200:
                    output_str = output_str[:200] + "..."
                lines.append(f"**输出摘要**: {output_str}")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def get_injection_context(
        self,
        user_query: str,
        task_type: Optional[str] = None,
        max_episodes: int = 3
    ) -> str:
        """
        一键获取可注入 prompt 的上下文
        
        Args:
            user_query: 用户查询
            task_type: 任务类型
            max_episodes: 最多返回记录数
            
        Returns:
            格式化的上下文文本
        """
        retrieved = self.retrieve_for_task(
            user_query=user_query,
            task_type=task_type,
            top_k=max_episodes
        )
        
        if not retrieved:
            return ""
        
        return self.format_for_prompt(
            retrieved_episodes=retrieved,
            max_episodes=max_episodes,
            include_reasoning=True,
            include_tools=False
        )
    
    def record_task_execution(
        self,
        task_type: str,
        user_query: str,
        output_data: Dict[str, Any],
        outcome: str = "success",
        reasoning_trace: Optional[List[str]] = None,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        salience: float = 0.5
    ) -> str:
        """
        记录任务执行（便捷方法）
        
        Returns:
            episode_id
        """
        return self.store.add_episode(
            task_type=task_type,
            input_data={'user_query': user_query},
            output_data=output_data,
            outcome=outcome,
            source='user',
            trust_zone='verified',
            reasoning_trace=reasoning_trace,
            tool_calls=tool_calls,
            salience=salience
        )
    
    def update_salience_from_feedback(
        self,
        episode_id: str,
        feedback: str
    ):
        """
        根据用户反馈更新显著性评分
        
        Args:
            episode_id: 记录 ID
            feedback: 'positive' / 'negative' / 'neutral'
        """
        episode = self.store.get_episode(episode_id)
        if not episode:
            return
        
        current_salience = episode['salience']
        
        # 调整规则
        if feedback == 'positive':
            new_salience = min(1.0, current_salience + 0.1)
        elif feedback == 'negative':
            new_salience = max(0.0, current_salience - 0.2)
        else:  # neutral
            new_salience = current_salience
        
        self.store.update_salience(episode_id, new_salience)