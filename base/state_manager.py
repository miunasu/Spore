"""
对话状态管理器

管理对话过程中的所有状态变量，提供统一的状态访问和修改接口。
支持多会话管理。
"""
from typing import List, Dict, Any, Optional
import copy


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
        
        # 上下文处理模式（每个对话独立，默认从ENV配置读取）
        from base.config import get_config
        config = get_config()
        self.context_mode: str = config.context_mode
    
    def add_user_message(self, content: str) -> None:
        """添加用户消息"""
        self.messages.append({"role": "user", "content": content})
        self.user_message_count += 1
    
    def add_assistant_message(self, content: str) -> None:
        """添加助手消息"""
        self.messages.append({"role": "assistant", "content": content})
        self.llm_reply_count += 1
    
    def clear_all(self) -> None:
        """清除所有状态"""
        self.messages.clear()
        self.user_message_count = 0
        self.llm_reply_count = 0
        self.last_answer = ""
        self.current_answer = ""
        self.temp_msg = None
    
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
        if session_id in self._sessions:
            # 已存在则清空
            self._sessions[session_id].clear_all()
        else:
            self._sessions[session_id] = ConversationState()
        return self._sessions[session_id]
    
    def delete_session(self, session_id: str) -> bool:
        """删除会话"""
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
