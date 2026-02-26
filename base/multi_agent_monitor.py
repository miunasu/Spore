"""
多Agent监控终端模块

在独立终端窗口显示各子Agent的执行状态和输出。
使用日志文件实现跨进程通信，支持在独立CMD窗口运行。
"""
import multiprocessing as mp
import threading
import time
import sys
import os
import json
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from queue import Empty, Queue


# 日志文件路径
LOG_DIR = Path(__file__).parent.parent / "logs"
MONITOR_LOG_FILE = LOG_DIR / "multi_agent_monitor.jsonl"
MONITOR_LOCK_FILE = LOG_DIR / "monitor.lock"


# ANSI颜色代码
class Colors:
    """终端颜色"""
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    
    # Agent颜色映射
    AGENT_COLORS = [CYAN, GREEN, YELLOW, MAGENTA, BLUE, WHITE]


def get_agent_color(agent_id: str) -> str:
    """根据agent_id获取颜色"""
    hash_val = hash(agent_id) % len(Colors.AGENT_COLORS)
    return Colors.AGENT_COLORS[hash_val]


def format_log_message(log_entry: Dict[str, Any]) -> str:
    """格式化日志消息"""
    agent_id = log_entry.get("agent_id", "unknown")
    agent_name = log_entry.get("agent_name", "Agent")
    message = log_entry.get("message", "")
    level = log_entry.get("level", "INFO")
    timestamp = log_entry.get("timestamp", time.time())
    
    time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
    color = get_agent_color(agent_id)
    
    level_color = Colors.WHITE
    if level == "ERROR":
        level_color = Colors.RED
    elif level == "WARNING":
        level_color = Colors.YELLOW
    elif level == "SUCCESS":
        level_color = Colors.GREEN
    
    agent_label = f"[{agent_name}-{agent_id[:8]}]"
    
    return (
        f"{Colors.BOLD}{time_str}{Colors.RESET} "
        f"{color}{agent_label}{Colors.RESET} "
        f"{level_color}{message}{Colors.RESET}"
    )


def ensure_log_dir():
    """确保日志目录存在"""
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def write_log_entry(log_entry: Dict[str, Any]) -> None:
    """写入日志条目到文件"""
    ensure_log_dir()
    try:
        with open(MONITOR_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def clear_log_file() -> None:
    """清空日志文件"""
    ensure_log_dir()
    try:
        with open(MONITOR_LOG_FILE, "w", encoding="utf-8") as f:
            pass
    except Exception:
        pass


class MonitorLogWriter:
    """
    监控日志写入器
    
    主进程使用，将Agent输出写入日志文件。
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        clear_log_file()
    
    def log(
        self,
        agent_id: str,
        agent_name: str,
        message: str,
        level: str = "INFO"
    ) -> None:
        """记录Agent输出"""
        log_entry = {
            "agent_id": agent_id,
            "agent_name": agent_name,
            "message": message,
            "level": level,
            "timestamp": time.time()
        }
        with self._lock:
            write_log_entry(log_entry)
    
    def log_system(self, message: str, level: str = "INFO") -> None:
        """记录系统消息"""
        self.log("system", "System", message, level)


class MonitorLogReader:
    """
    监控日志读取器
    
    独立终端使用，读取并显示日志。
    """
    
    def __init__(self):
        self._stop_event = threading.Event()
        self._last_position = 0
        self._agent_stats: Dict[str, Dict[str, Any]] = {}
    
    def run(self) -> None:
        """监控终端主循环"""
        self._print_header()
        
        # 等待日志文件创建
        while not MONITOR_LOG_FILE.exists():
            if self._stop_event.is_set():
                return
            time.sleep(0.5)
        
        while not self._stop_event.is_set():
            try:
                new_entries = self._read_new_entries()
                for entry in new_entries:
                    self._update_stats(entry)
                    formatted = format_log_message(entry)
                    print(formatted)
                    sys.stdout.flush()
                
                if not new_entries:
                    time.sleep(0.2)
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{Colors.RED}[Monitor Error] {e}{Colors.RESET}")
                time.sleep(1)
        
        self._print_footer()
    
    def _read_new_entries(self) -> List[Dict[str, Any]]:
        """读取新的日志条目"""
        entries = []
        try:
            if not MONITOR_LOG_FILE.exists():
                return entries
            
            with open(MONITOR_LOG_FILE, "r", encoding="utf-8") as f:
                f.seek(self._last_position)
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
                self._last_position = f.tell()
        except Exception:
            pass
        return entries
    
    def _print_header(self) -> None:
        """打印监控头部"""
        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  Multi-Agent Monitor - 多Agent监控终端{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.YELLOW}按 Ctrl+C 退出监控{Colors.RESET}")
        print(f"{Colors.WHITE}等待Agent输出...{Colors.RESET}\n")
    
    def _print_footer(self) -> None:
        """打印监控尾部"""
        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  监控结束{Colors.RESET}")
        
        if self._agent_stats:
            print(f"\n{Colors.BOLD}Agent统计:{Colors.RESET}")
            for agent_id, stats in self._agent_stats.items():
                color = get_agent_color(agent_id)
                print(f"  {color}{stats['name']}-{agent_id[:8]}{Colors.RESET}: "
                      f"消息数={stats['count']}")
        
        print(f"{Colors.BOLD}{'=' * 60}{Colors.RESET}\n")
    
    def _update_stats(self, log_entry: Dict[str, Any]) -> None:
        """更新Agent统计"""
        agent_id = log_entry.get("agent_id", "unknown")
        agent_name = log_entry.get("agent_name", "Agent")
        
        if agent_id not in self._agent_stats:
            self._agent_stats[agent_id] = {
                "name": agent_name,
                "count": 0,
                "first_seen": time.time()
            }
        
        self._agent_stats[agent_id]["count"] += 1
        self._agent_stats[agent_id]["last_seen"] = time.time()
    
    def stop(self) -> None:
        """停止监控"""
        self._stop_event.set()


# ============ 兼容旧接口的队列适配器 ============

class QueueToFileAdapter:
    """
    队列到文件适配器
    
    将 mp.Queue 的消息转发到日志文件，保持与旧代码兼容。
    """
    
    def __init__(self, log_writer: MonitorLogWriter):
        self.log_writer = log_writer
        self._queue = mp.Queue()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
    
    def start(self) -> None:
        """启动转发线程"""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._forward_loop, daemon=True)
        self._thread.start()
    
    def stop(self) -> None:
        """停止转发线程"""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
    
    def _forward_loop(self) -> None:
        """转发循环"""
        while not self._stop_event.is_set():
            try:
                entry = self._queue.get(timeout=0.5)
                self.log_writer.log(
                    agent_id=entry.get("agent_id", "unknown"),
                    agent_name=entry.get("agent_name", "Agent"),
                    message=entry.get("message", ""),
                    level=entry.get("level", "INFO")
                )
            except Empty:
                continue
            except Exception:
                pass
    
    def get_queue(self) -> mp.Queue:
        """获取队列对象（供旧代码使用）"""
        return self._queue


# ============ 全局实例管理 ============

_log_writer: Optional[MonitorLogWriter] = None
_queue_adapter: Optional[QueueToFileAdapter] = None
_monitor_terminal_process: Optional[subprocess.Popen] = None
_agent_log_callback: Optional[callable] = None


def set_agent_log_callback(callback: callable) -> None:
    """设置 Agent 日志回调（用于 Desktop 模式 WebSocket 推送）"""
    global _agent_log_callback
    _agent_log_callback = callback


def get_log_writer() -> MonitorLogWriter:
    """获取全局日志写入器"""
    global _log_writer
    if _log_writer is None:
        _log_writer = MonitorLogWriter()
    return _log_writer


def get_monitor_queue() -> mp.Queue:
    """获取全局监控队列（兼容旧接口）"""
    global _queue_adapter
    if _queue_adapter is None:
        _queue_adapter = QueueToFileAdapter(get_log_writer())
        _queue_adapter.start()
    return _queue_adapter.get_queue()


def start_monitor_in_new_terminal() -> Optional[subprocess.Popen]:
    """
    在新的CMD窗口启动监控终端（仅在 CLI 模式下）
    
    Returns:
        Popen: 进程对象，如果启动失败或 desktop 模式返回 None
    """
    global _monitor_terminal_process
    
    # Desktop 模式下不启动 cmd 终端
    from .config import get_config
    config = get_config()
    if config.launch_mode == 'desktop':
        return None
    
    if sys.platform != 'win32':
        print("[警告] 独立监控终端仅支持Windows系统")
        return None
    
    try:
        project_root = Path(__file__).parent.parent
        
        # 使用 start 命令在新窗口运行
        cmd = f'start "Multi-Agent Monitor" cmd /k "cd /d {project_root} && python -m base.multi_agent_monitor"'
        
        _monitor_terminal_process = subprocess.Popen(
            cmd,
            shell=True,
            cwd=str(project_root)
        )
        
        # 记录启动消息
        get_log_writer().log_system("监控终端已启动", "SUCCESS")
        
        return _monitor_terminal_process
        
    except Exception as e:
        print(f"[警告] 启动监控终端失败: {e}")
        return None


def start_global_monitor() -> Optional[subprocess.Popen]:
    """启动全局监控（在新终端窗口）"""
    global _monitor_terminal_process
    
    # 初始化日志写入器和队列适配器
    get_monitor_queue()
    
    # 检查是否已有监控终端运行
    if _monitor_terminal_process is not None:
        if _monitor_terminal_process.poll() is None:
            # 进程仍在运行
            return _monitor_terminal_process
    
    return start_monitor_in_new_terminal()


def stop_global_monitor() -> None:
    """停止全局监控"""
    global _queue_adapter, _monitor_terminal_process
    
    if _queue_adapter:
        _queue_adapter.stop()
        _queue_adapter = None
    
    if _monitor_terminal_process:
        try:
            _monitor_terminal_process.terminate()
        except Exception:
            pass
        _monitor_terminal_process = None


# ============ 独立Agent终端支持 ============

# Agent日志目录（会话级别）
def get_agent_log_dir() -> Path:
    """
    获取当前会话的 Agent 日志目录
    
    优先使用会话日志目录（如 logs/2025-12-28_10-48-47/agents/）
    如果没有会话目录，则使用全局目录（logs/agents/）
    """
    # 检查环境变量中的会话日志目录
    session_dir_env = os.environ.get('SPORE_SESSION_LOG_DIR')
    if session_dir_env:
        session_dir = Path(session_dir_env)
        if session_dir.exists():
            agent_dir = session_dir / "agents"
            agent_dir.mkdir(parents=True, exist_ok=True)
            return agent_dir
    
    # 回退到全局目录
    global_agent_dir = LOG_DIR / "agents"
    global_agent_dir.mkdir(parents=True, exist_ok=True)
    return global_agent_dir


def get_agent_log_file(agent_id: str) -> Path:
    """获取指定Agent的日志文件路径"""
    agent_dir = get_agent_log_dir()
    return agent_dir / f"{agent_id}.jsonl"


class AgentTerminal:
    """
    单个Agent的独立终端管理器
    """
    
    def __init__(self, agent_id: str, agent_name: str):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.log_file = get_agent_log_file(agent_id)
        self.terminal_process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._log_queue: Queue = Queue()
        self._writer_thread: Optional[threading.Thread] = None
        self._running = True
        
        # 清空日志文件
        self._clear_log()
        
        # 启动后台写入线程
        self._start_writer()
    
    def _start_writer(self):
        """启动后台日志写入线程"""
        self._writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
        self._writer_thread.start()
    
    def _writer_loop(self):
        """后台写入循环"""
        while self._running:
            try:
                # 批量获取日志
                entries = []
                try:
                    while True:
                        entry = self._log_queue.get_nowait()
                        entries.append(entry)
                except Empty:
                    pass
                
                if entries:
                    # 批量写入文件
                    with self._lock:
                        try:
                            with open(self.log_file, "a", encoding="utf-8") as f:
                                for entry in entries:
                                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                        except Exception:
                            pass
                else:
                    time.sleep(0.05)  # 50ms 间隔
            except Exception:
                time.sleep(0.1)
    
    def _clear_log(self) -> None:
        """清空日志文件"""
        try:
            with open(self.log_file, "w", encoding="utf-8") as f:
                pass
        except Exception:
            pass
    
    def log(self, message: str, level: str = "INFO") -> None:
        """写入日志（非阻塞）"""
        log_entry = {
            "message": message,
            "level": level,
            "timestamp": time.time()
        }
        
        # 放入队列，不阻塞
        self._log_queue.put(log_entry)
        
        # Desktop 模式下通过回调推送
        if _agent_log_callback:
            _agent_log_callback(self.agent_id, self.agent_name, message, level)
    
    def start_terminal(self) -> bool:
        """启动独立终端窗口（仅在 CLI 模式下）"""
        # Desktop 模式下不启动 cmd 终端，日志通过 WebSocket 推送
        from .config import get_config
        config = get_config()
        if config.launch_mode == 'desktop':
            return False
        
        if sys.platform != 'win32':
            return False
        
        try:
            project_root = Path(__file__).parent.parent
            
            # 使用 start 命令在新窗口运行
            title = f"{self.agent_name}-{self.agent_id[:8]}"
            cmd = f'start "{title}" cmd /c "cd /d {project_root} && python -m base.multi_agent_monitor --agent {self.agent_id} --name {self.agent_name}"'
            
            self.terminal_process = subprocess.Popen(
                cmd,
                shell=True,
                cwd=str(project_root)
            )
            return True
            
        except Exception as e:
            print(f"[警告] 启动Agent终端失败: {e}")
            return False
    
    def signal_complete(self) -> None:
        """发送完成信号（终端将延迟关闭）"""
        self.log("__COMPLETE__", "SYSTEM")
    
    def signal_interrupt(self) -> None:
        """发送中断信号（终端立即关闭）"""
        self.log("__INTERRUPT__", "SYSTEM")
    
    def close(self) -> None:
        """关闭终端"""
        self._running = False
        
        if self.terminal_process:
            try:
                self.terminal_process.terminate()
            except Exception:
                pass
            self.terminal_process = None
        
        # 等待写入线程结束
        if self._writer_thread:
            self._writer_thread.join(timeout=1)
        
        # 清理日志文件
        try:
            if self.log_file.exists():
                self.log_file.unlink()
        except Exception:
            pass
    
    def terminate(self) -> None:
        """中断此Agent（兼容接口）"""
        self.signal_interrupt()


class AgentTerminalManager:
    """管理所有Agent终端"""
    
    def __init__(self):
        self._terminals: Dict[str, AgentTerminal] = {}
        self._lock = threading.Lock()
    
    def create_terminal(self, agent_id: str, agent_name: str) -> AgentTerminal:
        """创建并启动Agent终端"""
        with self._lock:
            terminal = AgentTerminal(agent_id, agent_name)
            terminal.start_terminal()
            self._terminals[agent_id] = terminal
            return terminal
    
    def get_terminal(self, agent_id: str) -> Optional[AgentTerminal]:
        """获取Agent终端"""
        with self._lock:
            return self._terminals.get(agent_id)
    
    def close_all(self) -> None:
        """关闭所有终端"""
        with self._lock:
            for terminal in self._terminals.values():
                terminal.signal_interrupt()
            time.sleep(0.5)
            for terminal in self._terminals.values():
                terminal.close()
            self._terminals.clear()


# 全局终端管理器
_terminal_manager: Optional[AgentTerminalManager] = None


def get_terminal_manager() -> AgentTerminalManager:
    """获取全局终端管理器"""
    global _terminal_manager
    if _terminal_manager is None:
        _terminal_manager = AgentTerminalManager()
    return _terminal_manager


def create_agent_terminal(agent_id: str, agent_name: str) -> AgentTerminal:
    """创建Agent终端"""
    return get_terminal_manager().create_terminal(agent_id, agent_name)


def close_all_terminals() -> None:
    """关闭所有Agent终端"""
    if _terminal_manager:
        _terminal_manager.close_all()


# ============ 单Agent监控终端 ============

class SingleAgentMonitor:
    """单个Agent的监控终端（在独立CMD窗口中运行）"""
    
    def __init__(self, agent_id: str, agent_name: str):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.log_file = get_agent_log_file(agent_id)
        self._last_position = 0
        self._message_count = 0
    
    def run(self) -> None:
        """监控终端主循环"""
        self._print_header()
        
        # 等待日志文件创建
        wait_count = 0
        while not self.log_file.exists():
            time.sleep(0.3)
            wait_count += 1
            if wait_count > 100:
                print(f"{Colors.RED}等待日志文件超时{Colors.RESET}")
                return
        
        while True:
            try:
                entries = self._read_new_entries()
                
                for entry in entries:
                    level = entry.get("level", "INFO")
                    message = entry.get("message", "")
                    
                    # 检查系统信号
                    if level == "SYSTEM":
                        if message == "__COMPLETE__":
                            self._print_footer()
                            print(f"\n{Colors.GREEN}任务完成，2秒后关闭...{Colors.RESET}")
                            time.sleep(2)
                            return
                        elif message == "__INTERRUPT__":
                            print(f"\n{Colors.YELLOW}收到中断信号{Colors.RESET}")
                            return
                        continue
                    
                    # 正常日志
                    self._message_count += 1
                    formatted = self._format_message(entry)
                    print(formatted)
                    sys.stdout.flush()
                
                if not entries:
                    time.sleep(0.2)
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}用户中断{Colors.RESET}")
                break
            except Exception as e:
                print(f"{Colors.RED}[Error] {e}{Colors.RESET}")
                time.sleep(1)
    
    def _read_new_entries(self) -> List[Dict[str, Any]]:
        """读取新的日志条目"""
        entries = []
        try:
            if not self.log_file.exists():
                return entries
            
            with open(self.log_file, "r", encoding="utf-8") as f:
                f.seek(self._last_position)
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
                self._last_position = f.tell()
        except Exception:
            pass
        return entries
    
    def _format_message(self, entry: Dict[str, Any]) -> str:
        """格式化消息"""
        message = entry.get("message", "")
        level = entry.get("level", "INFO")
        timestamp = entry.get("timestamp", time.time())
        
        time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
        
        level_color = Colors.WHITE
        if level == "ERROR":
            level_color = Colors.RED
        elif level == "WARNING":
            level_color = Colors.YELLOW
        elif level == "SUCCESS":
            level_color = Colors.GREEN
        
        return f"{Colors.BOLD}{time_str}{Colors.RESET} {level_color}{message}{Colors.RESET}"
    
    def _print_header(self) -> None:
        """打印监控头部"""
        print(f"\n{Colors.BOLD}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.CYAN}  {self.agent_name} - {self.agent_id}{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 50}{Colors.RESET}\n")
    
    def _print_footer(self) -> None:
        """打印监控尾部"""
        print(f"\n{Colors.BOLD}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.GREEN}  执行完成 - 共 {self._message_count} 条消息{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 50}{Colors.RESET}")


# ============ 直接运行入口 ============

if __name__ == "__main__":
    # 启用Windows终端ANSI支持
    if sys.platform == 'win32':
        os.system('')
    
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", help="Agent ID")
    parser.add_argument("--name", help="Agent Name")
    args = parser.parse_args()
    
    if args.agent and args.name:
        # 单Agent监控模式
        monitor = SingleAgentMonitor(args.agent, args.name)
        monitor.run()
    else:
        # 全局监控模式（兼容旧版）
        reader = MonitorLogReader()
        reader.run()
