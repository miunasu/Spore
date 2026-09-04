"""
对话状态管理器

管理对话过程中的所有状态变量，提供统一的状态访问和修改接口。
支持多会话管理。
"""
from typing import List, Dict, Any, Optional
import copy
from base.config import get_config

class ConversationState:
    """单个会话的状态"""
    
    def __init__(self):
        # 对话历史
        self.messages: List[Dict[str, str]] = []

        # 临时消息（savemode使用）
        self.temp_msg: Optional[List[Dict[str, str]]] = None

        # save mode标志
        self.save_mode: bool = False

        # 答案状态
        self.last_answer: str = ""
        self.current_answer: str = ""

        # 用户消息计数器
        self.user_message_count: int = 0

        # LLM 回复计数器（用于规则提醒）
        self.llm_reply_count: int = 0

        # 中断世代。每次用户中断递增，用于丢弃旧请求返回。
        self.interrupt_epoch: int = 0

        # 动态工作目录（会话级别，None表示使用项目根目录）
        self.working_dir: Optional[str] = None
        
        # Token 统计（Desktop 模式专用）
        self.last_input_tokens: int = 0  # 上次请求的完整输入 context
        self.last_output_tokens: int = 0  # 上次请求的输出 token
        self.cumulative_input_tokens: int = 0  # 累计输入 token（用于算钱）
        self.cumulative_output_tokens: int = 0  # 累计输出 token（用于算钱）
        # 上次请求的真实上下文规模（含缓存命中部分）。
        # Anthropic 的 input_tokens 不含 cache_read/cache_creation，只看它会把
        # 上下文规模低估到个位数，上下文压缩永远不触发。
        self.last_context_tokens: int = 0

        # 上下文处理模式（每个对话独立，默认从ENV配置读取）
        config = get_config()
        self.context_mode: str = config.context_mode
        
        # TODO列表（每个会话独立）
        self.todos: List[Dict] = []
        
        # Session-level tool enable/disable policy, keyed by mode
        # { "strong_context": { "file": {"read": True, ...}, ... }, "long_context": {...} }
        self.tool_policies: Dict[str, Dict] = {}
        # When context_mode is auto, last ModeSelector result for tool resolution
        self.selected_auto_mode: Optional[str] = None
    
    def add_user_message(self, content: str) -> None:
        """添加用户消息"""
        self.messages.append({"role": "user", "content": content})
        self.user_message_count += 1

    
    def add_assistant_message(self, content: str) -> bool:
        """添加助手消息。

        空内容一律拒绝写入：空的 assistant 消息会让后续每一次请求都被 API 以
        "消息为空或无效"400 拒掉，且历史一旦被污染，后面所有轮次连带失败。
        这里是最后一道闸门，宁可丢掉这一轮，也不能污染历史。

        Returns:
            True 表示已写入；False 表示内容为空被拒绝。
        """
        if not isinstance(content, str) or not content.strip():
            return False
        self.messages.append({"role": "assistant", "content": content})
        self.llm_reply_count += 1
        return True

    def drop_blank_messages(self) -> int:
        """清掉历史里所有空内容消息，返回清理条数（历史卫生兜底）。"""
        before = len(self.messages)
        self.messages = [
            msg for msg in self.messages
            if isinstance(msg, dict) and isinstance(msg.get("content"), str) and msg["content"].strip()
        ]
        return before - len(self.messages)

    def clear_all(self) -> None:
        """清除所有状态"""
        
        self.messages.clear()
        self.user_message_count = 0
        self.llm_reply_count = 0
        self.interrupt_epoch += 1
        self.last_answer = ""
        self.current_answer = ""
        self.temp_msg = None
        # 清除 token 统计
        self.last_input_tokens = 0
        self.last_output_tokens = 0
        self.last_context_tokens = 0
        self.cumulative_input_tokens = 0
        self.cumulative_output_tokens = 0
        # 清除 TODO 列表
        self.todos.clear()
    
    def save_temp_messages(self) -> None:
        """保存临时消息（用于savemode）"""
        if self.temp_msg is None:
            self.temp_msg = copy.deepcopy(self.messages)
    
    def restore_temp_messages(self) -> None:
        """恢复临时消息（用于savemode）"""
        if self.save_mode and self.temp_msg is not None:
            self.messages = copy.deepcopy(self.temp_msg)
            self.temp_msg = None
    
    def toggle_save_mode(self) -> bool:
        """切换save mode"""
        self.save_mode = not self.save_mode
        return self.save_mode
    
    def update_token_stats(
        self,
        input_tokens: int,
        output_tokens: int,
        context_tokens: Optional[int] = None,
    ) -> None:
        """
        更新 token 统计（Desktop 模式专用）

        Args:
            input_tokens: 本次请求的完整输入 context（已统一包含 Claude 缓存 token）
            output_tokens: 本次请求的输出 token 数
            context_tokens: 真实上下文规模（含缓存命中）。缺省时退回 input_tokens。
        """
        input_tokens = input_tokens or 0
        output_tokens = output_tokens or 0
        self.last_input_tokens = input_tokens
        self.last_output_tokens = output_tokens
        self.last_context_tokens = max(context_tokens or 0, input_tokens)
        self.cumulative_input_tokens += input_tokens  # 累加每次请求的完整 input
        self.cumulative_output_tokens += output_tokens  # 累加每次请求的 output


class MultiSessionManager:
    """多会话管理器"""
    
    def __init__(self):
        self._sessions: Dict[str, ConversationState] = {}
        self._current_session_id: str = "default"
        # 创建默认会话
        self._sessions["default"] = ConversationState()
    
    @property
    def current(self) -> ConversationState:
        """获取当前会话状态"""
        return self._sessions.get(self._current_session_id) or self._sessions["default"]
    
    @property
    def current_session_id(self) -> str:
        """获取当前会话 ID"""
        return self._current_session_id
    
    def switch_session(self, session_id: str) -> ConversationState:
        """切换到指定会话，如果不存在则创建"""
        
        if session_id not in self._sessions:
            self._sessions[session_id] = ConversationState()
        
        self._current_session_id = session_id
        return self._sessions[session_id]
    
    def create_session(self, session_id: str) -> ConversationState:
        """创建新会话"""
        # 添加调试日志        
        if session_id in self._sessions:
            # 已存在则清空
            self._sessions[session_id].clear_all()
        else:
            self._sessions[session_id] = ConversationState()
        
        return self._sessions[session_id]
    
    def delete_session(self, session_id: str) -> bool:
        """删除会话"""
        # 添加调试日志
        
        if session_id == "default":
            # 不能删除默认会话，只能清空
            self._sessions["default"].clear_all()
            return True
        if session_id in self._sessions:
            del self._sessions[session_id]
            if self._current_session_id == session_id:
                self._current_session_id = "default"
            return True
        return False
    
    def get_session(self, session_id: str) -> Optional[ConversationState]:
        """获取指定会话"""
        return self._sessions.get(session_id)
    
    def list_sessions(self) -> List[str]:
        """列出所有会话 ID"""
        return list(self._sessions.keys())
