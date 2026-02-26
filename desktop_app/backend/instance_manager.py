"""
后端实例管理器
支持启动多个独立的 Spore 后端实例，每个实例监听不同端口
"""
import subprocess
import sys
import os
import time
import socket
import threading
from typing import Dict, Optional, List
from dataclasses import dataclass, field
from pathlib import Path
import requests


@dataclass
class BackendInstance:
    """后端实例信息"""
    id: str
    port: int
    process: Optional[subprocess.Popen] = None
    status: str = "starting"  # starting, running, stopped, error
    created_at: float = field(default_factory=time.time)
    

class InstanceManager:
    """后端实例管理器"""
    
    # 端口范围
    BASE_PORT = 8765
    MAX_INSTANCES = 10
    
    def __init__(self):
        self.instances: Dict[str, BackendInstance] = {}
        self._lock = threading.Lock()
        self._project_root = Path(__file__).parent.parent.parent
    
    def _find_available_port(self) -> Optional[int]:
        """查找可用端口"""
        for offset in range(self.MAX_INSTANCES):
            port = self.BASE_PORT + offset
            if not self._is_port_in_use(port):
                # 确保没有其他实例使用这个端口
                with self._lock:
                    if not any(inst.port == port for inst in self.instances.values()):
                        return port
        return None
    
    def _is_port_in_use(self, port: int) -> bool:
        """检查端口是否被占用"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
                return False
            except OSError:
                return True
    
    def _wait_for_ready(self, port: int, timeout: float = 30) -> bool:
        """等待后端就绪"""
        start = time.time()
        while time.time() - start < timeout:
            try:
                resp = requests.get(f"http://127.0.0.1:{port}/health", timeout=1)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("initialized"):
                        return True
            except:
                pass
            time.sleep(0.5)
        return False
    
    def create_instance(self, instance_id: str) -> Optional[BackendInstance]:
        """
        创建新的后端实例
        
        Args:
            instance_id: 实例唯一标识
            
        Returns:
            BackendInstance 或 None（如果创建失败）
        """
        with self._lock:
            # 检查是否已存在
            if instance_id in self.instances:
                return self.instances[instance_id]
            
            # 查找可用端口
            port = self._find_available_port()
            if port is None:
                return None
            
            # 创建实例记录
            instance = BackendInstance(id=instance_id, port=port)
            self.instances[instance_id] = instance
        
        # 启动后端进程
        try:
            env = os.environ.copy()
            env['SPORE_DESKTOP_MODE'] = '1'
            env['SPORE_INSTANCE_ID'] = instance_id
            env['SPORE_INSTANCE_PORT'] = str(port)
            
            # 启动独立的后端进程
            # 注意：不使用 PIPE 避免缓冲区满导致阻塞
            process = subprocess.Popen(
                [sys.executable, '-m', 'desktop_app.backend.standalone'],
                cwd=str(self._project_root),
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0,
            )
            
            instance.process = process
            
            # 检查进程是否立即退出
            time.sleep(0.5)
            if process.poll() is not None:
                instance.status = "error"
                with self._lock:
                    del self.instances[instance_id]
                return None
            
            # 等待就绪
            if self._wait_for_ready(port):
                instance.status = "running"
                return instance
            else:
                instance.status = "error"
                self.stop_instance(instance_id)
                return None
                
        except Exception:
            instance.status = "error"
            with self._lock:
                del self.instances[instance_id]
            return None
    
    def stop_instance(self, instance_id: str) -> bool:
        """
        停止后端实例
        
        Args:
            instance_id: 实例唯一标识
            
        Returns:
            是否成功停止
        """
        with self._lock:
            instance = self.instances.get(instance_id)
            if not instance:
                return False
        
        try:
            if instance.process and instance.process.poll() is None:
                # 先尝试优雅关闭
                try:
                    requests.post(f"http://127.0.0.1:{instance.port}/shutdown", timeout=2)
                    instance.process.wait(timeout=5)
                except:
                    # 强制终止
                    instance.process.terminate()
                    try:
                        instance.process.wait(timeout=3)
                    except:
                        instance.process.kill()
            
            instance.status = "stopped"
            
            with self._lock:
                del self.instances[instance_id]
            
            return True
            
        except Exception:
            return False
    
    def get_instance(self, instance_id: str) -> Optional[BackendInstance]:
        """获取实例信息"""
        with self._lock:
            return self.instances.get(instance_id)
    
    def list_instances(self) -> List[Dict]:
        """列出所有实例"""
        with self._lock:
            return [
                {
                    "id": inst.id,
                    "port": inst.port,
                    "status": inst.status,
                    "created_at": inst.created_at,
                }
                for inst in self.instances.values()
            ]
    
    def stop_all(self):
        """停止所有实例"""
        instance_ids = list(self.instances.keys())
        for instance_id in instance_ids:
            self.stop_instance(instance_id)


# 全局实例管理器
_instance_manager: Optional[InstanceManager] = None


def get_instance_manager() -> InstanceManager:
    """获取全局实例管理器"""
    global _instance_manager
    if _instance_manager is None:
        _instance_manager = InstanceManager()
    return _instance_manager
