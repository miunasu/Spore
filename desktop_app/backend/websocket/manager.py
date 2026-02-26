"""
WebSocket 连接管理器（保留用于兼容性）

注意：实际的 WebSocket 推送通过独立进程 (ws_process.py) 处理，
此模块仅保留用于 log_bridge.py 的接口兼容性。
"""
from typing import List, Dict, Any
from fastapi import WebSocket


class WebSocketManager:
    """WebSocket 连接管理器（兼容性保留）"""
    
    def __init__(self):
        """初始化管理器"""
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        """接受新的 WebSocket 连接"""
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        """断开 WebSocket 连接"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    @property
    def connection_count(self) -> int:
        """获取当前连接数"""
        return len(self.active_connections)
