"""
中断处理器模块

处理用户Ctrl+C中断，收集更正信息并协调Agent终止。
"""
import signal
import sys
import threading
from typing import Optional, Dict, Any, Callable, TYPE_CHECKING

from .logger import log_error, log_info

if TYPE_CHECKING:
    from .agent_process import AgentProcessManager
    from .agent_database import SubAgentDatabase


class InterruptHandler:
    """
    中断处理器
    
    处理Ctrl+C中断，提示用户输入更正信息，
    并协调所有Agent的终止。
    """
    
    def __init__(
        self,
        agent_manager: Optional['AgentProcessManager'] = None,
        ipc_manager: Optional[Any] = None
    ):
        """
        初始化中断处理器
        
        Args:
            agent_manager: Agent进程管理器
            ipc_manager: IPC管理器
        """
        self.agent_manager = agent_manager
        self.ipc_manager = ipc_manager
        
        # 用户更正信息
        self.correction_input: Optional[str] = None
        
        # 中断标志
        self._interrupted = threading.Event()
        
        # 原始信号处理器
        self._original_handler = None
        
        # 是否已安装
        self._installed = False
        
        # 回调函数
        self._on_interrupt_callback: Optional[Callable] = None
    
    def set_agent_manager(self, agent_manager: 'AgentProcessManager') -> None:
        """设置Agent进程管理器"""
        self.agent_manager = agent_manager
    
    def set_ipc_manager(self, ipc_manager: Any) -> None:
        """设置IPC管理器"""
        self.ipc_manager = ipc_manager
    
    def set_on_interrupt_callback(self, callback: Callable) -> None:
        """设置中断回调函数"""
        self._on_interrupt_callback = callback
    
    def install(self) -> None:
        """安装信号处理器"""
        if self._installed:
            return
        
        self._original_handler = signal.signal(signal.SIGINT, self._signal_handler)
        self._installed = True
        log_info("Interrupt handler installed")
    
    def uninstall(self) -> None:
        """卸载信号处理器"""
        if not self._installed:
            return
        
        if self._original_handler is not None:
            signal.signal(signal.SIGINT, self._original_handler)
        self._installed = False
        log_info("Interrupt handler uninstalled")
    
    def _signal_handler(self, signum: int, frame) -> None:
        """
        信号处理函数
        
        Args:
            signum: 信号编号
            frame: 当前栈帧
        """
        self._interrupted.set()
        
        print("\n" + "=" * 50)
        print("[中断] 检测到 Ctrl+C，正在停止所有Agent...")
        print("=" * 50)
        
        # 广播终止信号
        self.broadcast_termination()
        
        # 调用回调
        if self._on_interrupt_callback:
            try:
                self._on_interrupt_callback()
            except Exception as e:
                log_error("INTERRUPT_CALLBACK_ERROR", str(e), e)
    
    def broadcast_termination(self) -> None:
        """广播终止信号给所有Agent"""
        # 终止Agent管理器中的所有Agent
        if self.agent_manager:
            try:
                self.agent_manager.terminate_all()
            except Exception as e:
                log_error("AGENT_TERMINATION_ERROR", str(e), e)
        
        # 中断IPC请求
        if self.ipc_manager:
            try:
                self.ipc_manager.interrupt_current_request()
            except Exception as e:
                log_error("IPC_INTERRUPT_ERROR", str(e), e)
    
    def handle_interrupt(self) -> tuple[Optional[str], Dict[str, 'SubAgentDatabase']]:
        """
        处理中断，收集Agent状态
        
        Returns:
            tuple: (None, Agent数据库字典)
        """
        databases = {}
        
        # 收集数据库
        if self.agent_manager:
            databases = self.agent_manager.get_all_databases()
        
        # 显示当前状态
        self._display_status(databases)
        
        # 不再请求用户输入，直接返回
        self.correction_input = None
        
        # 重置中断标志
        self._interrupted.clear()
        
        return self.correction_input, databases
    
    def _display_status(self, databases: Dict[str, 'SubAgentDatabase']) -> None:
        """显示当前Agent状态"""
        if not databases:
            print("\n[状态] 没有正在运行的Agent")
            return
        
        print(f"\n[状态] 共 {len(databases)} 个Agent被中断:")
        for agent_id, db in databases.items():
            tool_count = len(db.tool_calls)
            print(f"  - {agent_id} ({db.agent_type_name}): "
                  f"状态={db.status.value}, 工具调用={tool_count}次")
            
            # 显示最后一个工具调用
            if db.tool_calls:
                last_call = db.tool_calls[-1]
                if last_call.is_file_operation:
                    print(f"    最后操作: {last_call.tool_name} -> {last_call.target_path}")
                else:
                    print(f"    最后操作: {last_call.tool_name}")
    
    def is_interrupted(self) -> bool:
        """检查是否被中断"""
        return self._interrupted.is_set()
    
    def reset(self) -> None:
        """重置中断状态"""
        self._interrupted.clear()
        self.correction_input = None
    
    def __enter__(self):
        """上下文管理器入口"""
        self.install()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.uninstall()
        return False


# 全局中断处理器实例
_interrupt_handler: Optional[InterruptHandler] = None


def get_interrupt_handler() -> InterruptHandler:
    """获取全局中断处理器实例"""
    global _interrupt_handler
    if _interrupt_handler is None:
        _interrupt_handler = InterruptHandler()
    return _interrupt_handler


def setup_interrupt_handler(
    agent_manager: Optional['AgentProcessManager'] = None,
    ipc_manager: Optional[Any] = None
) -> InterruptHandler:
    """
    设置并安装中断处理器
    
    Args:
        agent_manager: Agent进程管理器
        ipc_manager: IPC管理器
    
    Returns:
        InterruptHandler: 配置好的中断处理器
    """
    handler = get_interrupt_handler()
    
    if agent_manager:
        handler.set_agent_manager(agent_manager)
    if ipc_manager:
        handler.set_ipc_manager(ipc_manager)
    
    handler.install()
    return handler
