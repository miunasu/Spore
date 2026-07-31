"""
ConversationLoop 管理器

为每个会话维护独立的 ConversationLoop 实例，实现真正的并发处理。
类似于子Agent的架构，每个会话有自己的独立实例。
"""
import threading
from typing import Dict, Optional
from base.conversation_loop import ConversationLoop
from base.state_manager import MultiSessionManager, ConversationState
from base.ipc_manager import IPCManager
from base.config import Config


class SessionConversationLoop(ConversationLoop):
    """
    会话专用的 ConversationLoop
    
    与原来的 ConversationLoop 不同，它绑定到特定的会话状态，
    而不是动态获取 session_manager.current
    """
    
    def __init__(
        self,
        session_id: str,
        session_state: ConversationState,
        ipc_manager: IPCManager,
        config: Config,
        system_prompt: str,
        tool_names: list = None
    ):
        # 不调用父类的 __init__，因为我们不需要 session_manager
        self.session_id = session_id
        self._session_state = session_state  # 绑定到特定的会话状态
        self.ipc_manager = ipc_manager
        self.config = config
        self.system_prompt = system_prompt
        self.tool_names = tool_names
        self.execution_lock = threading.RLock()
        self._request_id_lock = threading.Lock()
        self._current_request_id = None

        # 初始化文本协议管理器
        from base.text_protocol import ProtocolManager
        self.protocol_manager = ProtocolManager()

        # 初始化 Learning 系统（情景记忆检索）
        # 注意：本类不调用父类 __init__，所以父类里的 learning 初始化
        # 不会执行，必须在这里同步维护，否则 send_chat_request 会
        # AttributeError: no attribute 'retriever'
        self._task_start_query = None
        self._task_start_time = None
        try:
            if not config.embedding_api_key:
                self.retriever = None
            else:
                from learning import EpisodicRetriever
                from learning.embedding import EmbeddingGenerator
                # 启动探针：若显式配置的 embedding API 不可用，直接跳过 learning，
                # 避免在每条消息时阻塞等待超时。
                _gen = EmbeddingGenerator()
                if not _gen.probe():
                    raise RuntimeError(
                        f"Embedding API probe failed ({_gen.api_url}). "
                        "Learning disabled. Set EMBEDDING_API_URL / EMBEDDING_API_KEY "
                        "to a service that supports /v1/embeddings, or leave unconfigured to skip."
                    )
                self.retriever = EpisodicRetriever()
        except Exception as e:
            # Learning 模块不可用时降级运行
            self.retriever = None
            try:
                from base.logger import log_error
                log_error(
                    "LEARNING_INIT_ERROR",
                    f"Failed to initialize learning system: {e}",
                    e,
                )
            except Exception:
                pass
    
    @property
    def state(self):
        """返回绑定的会话状态（不是动态的）"""
        return self._session_state


class ConversationLoopManager:
    """
    ConversationLoop 管理器
    
    为每个会话维护独立的 ConversationLoop 实例。
    类似于子Agent的架构，实现真正的并发处理。
    """
    
    def __init__(
        self,
        session_manager: MultiSessionManager,
        ipc_manager: IPCManager,
        config: Config
    ):
        self.session_manager = session_manager
        self.ipc_manager = ipc_manager
        self.config = config
        self._loops: Dict[str, SessionConversationLoop] = {}
    
    def get_loop(
        self,
        session_id: str,
        system_prompt: Optional[str] = None,
        tool_names: Optional[list] = None
    ) -> SessionConversationLoop:
        """
        获取或创建指定会话的 ConversationLoop
        
        Args:
            session_id: 会话 ID
            system_prompt: 系统提示（如果创建新实例）
            tool_names: 工具名称列表（如果创建新实例）
        
        Returns:
            SessionConversationLoop: 会话专用的 ConversationLoop 实例
        """
        if session_id not in self._loops:
            # 获取会话状态
            session_state = self.session_manager.get_session(session_id)
            if not session_state:
                # 会话不存在，创建新会话
                session_state = self.session_manager.create_session(session_id)
            
            # 创建新的 ConversationLoop 实例
            self._loops[session_id] = SessionConversationLoop(
                session_id=session_id,
                session_state=session_state,
                ipc_manager=self.ipc_manager,
                config=self.config,
                system_prompt=system_prompt or "",
                tool_names=tool_names
            )
        
        return self._loops[session_id]
    
    def update_loop_config(
        self,
        session_id: str,
        system_prompt: Optional[str] = None,
        tool_names: Optional[list] = None
    ) -> None:
        """
        更新指定会话的 ConversationLoop 配置
        
        Args:
            session_id: 会话 ID
            system_prompt: 新的系统提示
            tool_names: 新的工具名称列表
        """
        if session_id in self._loops:
            loop = self._loops[session_id]
            if system_prompt is not None:
                loop.system_prompt = system_prompt
            if tool_names is not None:
                loop.tool_names = tool_names
    
    def remove_loop(self, session_id: str) -> bool:
        """
        移除指定会话的 ConversationLoop
        
        Args:
            session_id: 会话 ID
        
        Returns:
            bool: 是否成功移除
        """
        if session_id in self._loops:
            del self._loops[session_id]
            return True
        return False
    
    def list_loops(self) -> list:
        """列出所有活动的 ConversationLoop 会话 ID"""
        return list(self._loops.keys())
    
    def clear_all(self) -> None:
        """清除所有 ConversationLoop 实例"""
        self._loops.clear()

