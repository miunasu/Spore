"""
日志监控终端 - 命名管道模式

作为独立进程运行，通过 Windows 命名管道接收日志推送
支持多个 Spore 实例同时连接
"""
import os
import sys
import json
import time
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional

# Windows 命名管道
if sys.platform == 'win32':
    import win32pipe
    import win32file
    import pywintypes

# 尝试相对导入
try:
    from .config import get_config
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from base.config import get_config

# 命名管道名称
PIPE_NAME = r'\\.\pipe\SporeLogMonitor'


class LogMonitorServer:
    """日志监控服务端 - 通过命名管道接收日志（支持多客户端）"""
    
    def __init__(self):
        self.running = False
        self.client_count = 0
        self.active_clients = 0  # 当前活跃连接数
        self.client_lock = threading.Lock()
        
        # 从配置获取显示设置
        _config = get_config()
        self.max_line_length = _config.log_monitor_max_line_length
        self.monitor_types = _config.log_monitor_types
        
        # 日志类型对应的颜色
        self.colors = {
            'error': '\033[91m',           # 红色
            'llm_validation': '\033[93m',  # 黄色
            'tool_execution': '\033[95m',  # 紫色
            'general': '\033[96m',         # 青色
        }
        self.reset_color = '\033[0m'
        
        # 打印锁，避免多线程输出混乱
        self.print_lock = threading.Lock()
    
    def start(self):
        """启动监控服务"""
        self.running = True
        self._print_header()
        
        # 持续创建新的管道实例等待连接
        while self.running:
            try:
                # 创建命名管道实例（字节模式，阻塞读取）
                pipe_handle = win32pipe.CreateNamedPipe(
                    PIPE_NAME,
                    win32pipe.PIPE_ACCESS_INBOUND,
                    win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,  # 允许多个实例
                    4096, 4096, 0, None
                )
                
                # 只在没有活跃连接时显示等待提示
                with self.client_lock:
                    if self.active_clients == 0:
                        self._safe_print(f"\033[90m[等待连接...]\033[0m")
                
                # 等待客户端连接（阻塞）
                win32pipe.ConnectNamedPipe(pipe_handle, None)
                
                with self.client_lock:
                    self.client_count += 1
                    self.active_clients += 1
                    client_id = self.client_count
                
                self._safe_print(f"\033[92m[连接 #{client_id}] Spore 实例已连接 (活跃: {self.active_clients})\033[0m")
                
                # 启动线程处理此客户端
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(pipe_handle, client_id),
                    daemon=True
                )
                thread.start()
                
            except pywintypes.error as e:
                if not self.running:
                    break
                self._safe_print(f"\033[91m[错误] 创建管道失败: {e}\033[0m")
                time.sleep(1)
            except KeyboardInterrupt:
                break
            except Exception as e:
                self._safe_print(f"\033[91m[错误] {e}\033[0m")
                time.sleep(1)
        
        self._print_footer()
    
    def _handle_client(self, pipe_handle, client_id: int):
        """处理单个客户端连接"""
        buffer = b""
        try:
            while self.running:
                try:
                    # 读取数据（阻塞等待）
                    result, data = win32file.ReadFile(pipe_handle, 4096)
                    
                    if result == 0 and data:  # 成功读取
                        buffer += data
                        
                        # 处理完整消息（以换行符分隔）
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n', 1)
                            if line.strip():
                                self._process_message(line.decode('utf-8', errors='ignore'))
                    elif result != 0:
                        # 读取出错
                        break
                                
                except pywintypes.error as e:
                    # 109 = ERROR_BROKEN_PIPE (管道已结束)
                    # 232 = ERROR_NO_DATA (管道正在关闭)
                    # 233 = ERROR_PIPE_NOT_CONNECTED (没有进程在管道另一端)
                    if e.winerror in (109, 232, 233):
                        break
                    raise
        except Exception as e:
            self._safe_print(f"\033[91m[错误] 客户端 #{client_id}: {e}\033[0m")
        finally:
            try:
                win32file.CloseHandle(pipe_handle)
            except:
                pass
            with self.client_lock:
                self.active_clients -= 1
                active = self.active_clients
            self._safe_print(f"\033[93m[断开 #{client_id}] 连接已断开 (活跃: {active})\033[0m")
    
    def _process_message(self, message: str):
        """处理日志消息"""
        try:
            data = json.loads(message)
            log_type = data.get('type', 'general')
            content = data.get('content', '')
            
            # 检查是否需要显示此类型
            if log_type not in self.monitor_types:
                return
            
            # 获取颜色和标签
            color = self.colors.get(log_type, self.reset_color)
            label = log_type.upper()
            
            # 截断过长内容
            if len(content) > self.max_line_length:
                content = content[:self.max_line_length] + f"... ({len(content)} chars)"
            
            self._safe_print(f"{color}[{label}]{self.reset_color} {content}")
            
        except json.JSONDecodeError:
            self._safe_print(f"[RAW] {message}")
    
    def _safe_print(self, message: str):
        """线程安全的打印"""
        with self.print_lock:
            print(message, flush=True)
    
    def _print_header(self):
        """打印头部"""
        print("\033[2J\033[H", flush=True)
        print("=" * 80, flush=True)
        print(" " * 22 + "Spore AI 日志监控终端", flush=True)
        print("=" * 80, flush=True)
        print(f"\n[启动时间] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
        print(f"[管道名称] {PIPE_NAME}", flush=True)
        print(f"[监控类型] {', '.join(self.monitor_types)}", flush=True)
        print("\n" + "-" * 80, flush=True)
        print("[提示] 等待 Spore 连接，按 Ctrl+C 退出", flush=True)
        print("-" * 80 + "\n", flush=True)
    
    def _print_footer(self):
        """打印尾部"""
        print("\n" + "=" * 80, flush=True)
        print(" " * 30 + "监控已停止", flush=True)
        print("=" * 80, flush=True)


class LogMonitorClient:
    """日志监控客户端 - 发送日志到监控服务"""
    
    def __init__(self):
        self.pipe_handle = None
        self.connected = False
        self.lock = threading.Lock()
    
    def connect(self) -> bool:
        """连接到监控服务"""
        with self.lock:
            if self.connected and self.pipe_handle:
                return True
            
            try:
                # 等待管道可用
                win32pipe.WaitNamedPipe(PIPE_NAME, 5000)  # 等待最多5秒
                
                # 连接命名管道（字节模式写入）
                self.pipe_handle = win32file.CreateFile(
                    PIPE_NAME,
                    win32file.GENERIC_WRITE,
                    0, None,
                    win32file.OPEN_EXISTING,
                    0, None
                )
                
                self.connected = True
                return True
            except pywintypes.error:
                self.connected = False
                self.pipe_handle = None
                return False
    
    def send(self, log_type: str, content: str) -> bool:
        """发送日志消息"""
        if not self.connected or not self.pipe_handle:
            if not self.connect():
                return False
        
        message = json.dumps({
            'type': log_type,
            'content': content,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }, ensure_ascii=False) + '\n'
        
        with self.lock:
            try:
                win32file.WriteFile(self.pipe_handle, message.encode('utf-8'))
                return True
            except pywintypes.error as e:
                # 连接断开，标记为未连接
                self.connected = False
                try:
                    win32file.CloseHandle(self.pipe_handle)
                except:
                    pass
                self.pipe_handle = None
                return False
    
    def disconnect(self):
        """断开连接"""
        with self.lock:
            if self.pipe_handle:
                try:
                    win32file.CloseHandle(self.pipe_handle)
                except:
                    pass
                self.pipe_handle = None
            self.connected = False


def is_monitor_running() -> bool:
    """检查监控服务是否在运行（通过检查管道是否存在）"""
    if sys.platform != 'win32':
        return False
    
    try:
        # 使用 WaitNamedPipe 检测管道是否存在
        # 超时设为 100ms，足够检测管道是否存在
        win32pipe.WaitNamedPipe(PIPE_NAME, 100)
        return True  # 如果没抛异常，说明管道存在且可连接
    except pywintypes.error as e:
        # 错误码 2 = ERROR_FILE_NOT_FOUND (管道不存在)
        # 错误码 121 = ERROR_SEM_TIMEOUT (信号灯超时，管道存在但所有实例都忙)
        if e.winerror == 121:
            return True  # 管道存在但忙，说明服务在运行
        return False


def main():
    """主函数"""
    if sys.platform != 'win32':
        print("日志监控仅支持 Windows 系统")
        return
    
    print("\n正在启动 Spore AI 日志监控服务...", flush=True)
    time.sleep(0.5)
    
    server = LogMonitorServer()
    try:
        server.start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
