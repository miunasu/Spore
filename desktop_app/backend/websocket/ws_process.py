"""
独立的 WebSocket 推送进程（双向通信）

运行在完全独立的进程中，不受主进程 GIL 影响。
- 接收：通过 message_queue 从主进程接收消息，推送到前端
- 发送：从前端接收消息，通过 response_queue 发送到主进程
"""
import asyncio
import json
import multiprocessing
from multiprocessing import Queue
from typing import Dict, Any, List, Optional
import time


class WSPushServer:
    """WebSocket 双向通信服务器"""
    
    def __init__(self, message_queue: Queue, response_queue: Queue, port: int = 8766):
        self.message_queue = message_queue  # 主进程 -> 前端
        self.response_queue = response_queue  # 前端 -> 主进程
        self.port = port
        self.clients: set = set()
        self._running = True
    
    async def handler(self, websocket):
        """处理 WebSocket 连接"""
        import websockets
        self.clients.add(websocket)
        try:
            async for message in websocket:
                if message == "ping":
                    await websocket.send("pong")
                else:
                    # 处理前端发来的消息
                    try:
                        data = json.loads(message)
                        # 放入响应队列，发送给主进程
                        self.response_queue.put(data)
                    except json.JSONDecodeError:
                        pass
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.clients.discard(websocket)
    
    async def broadcast(self, message: Dict[str, Any]):
        """广播消息"""
        if not self.clients:
            return
        
        data = json.dumps(message, ensure_ascii=False)
        disconnected = set()
        
        for client in self.clients.copy():
            try:
                await client.send(data)
            except Exception:
                disconnected.add(client)
        
        self.clients -= disconnected
    
    async def message_consumer(self):
        """消费消息队列并广播"""
        batch: List[Dict[str, Any]] = []
        last_flush = time.time()
        
        while self._running:
            # 非阻塞获取消息
            try:
                while not self.message_queue.empty():
                    try:
                        msg = self.message_queue.get_nowait()
                        batch.append(msg)
                        if len(batch) >= 20:
                            break
                    except Exception:
                        break
            except Exception:
                pass
            
            # 批量发送（50ms 或 5 条消息）
            now = time.time()
            if batch and (len(batch) >= 5 or now - last_flush >= 0.05):
                if self.clients:
                    await self.broadcast({"type": "batch", "data": batch})
                batch = []
                last_flush = now
            
            await asyncio.sleep(0.01)
    
    async def run(self):
        """运行服务器"""
        from websockets.server import serve
        
        async with serve(self.handler, "127.0.0.1", self.port):
            await self.message_consumer()
    
    def stop(self):
        self._running = False


def _run_ws_process(message_queue: Queue, response_queue: Queue, port: int = 8766):
    """WebSocket 推送进程入口"""
    server = WSPushServer(message_queue, response_queue, port)
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        server.stop()
    except Exception:
        pass


# 全局变量
_ws_process: Optional[multiprocessing.Process] = None
_message_queue: Optional[Queue] = None
_response_queue: Optional[Queue] = None


def start_ws_process(port: int = 8766) -> Queue:
    """启动 WebSocket 推送进程"""
    global _ws_process, _message_queue, _response_queue
    
    _message_queue = multiprocessing.Queue()
    _response_queue = multiprocessing.Queue()
    
    _ws_process = multiprocessing.Process(
        target=_run_ws_process,
        args=(_message_queue, _response_queue, port),
        daemon=True,
        name="WS-Push-Process"
    )
    _ws_process.start()
    return _message_queue


def stop_ws_process():
    """停止 WebSocket 推送进程"""
    global _ws_process, _message_queue, _response_queue
    
    if _ws_process and _ws_process.is_alive():
        _ws_process.terminate()
        _ws_process.join(timeout=2.0)
        if _ws_process.is_alive():
            _ws_process.kill()
            _ws_process.join(timeout=1.0)
    
    if _message_queue:
        try:
            _message_queue.close()
        except Exception:
            pass
    
    if _response_queue:
        try:
            _response_queue.close()
        except Exception:
            pass
    
    _ws_process = None
    _message_queue = None
    _response_queue = None


def send_to_ws_process(message: Dict[str, Any]):
    """发送消息到 WebSocket 进程（主进程 -> 前端）"""
    if _message_queue:
        try:
            _message_queue.put(message, block=False)
        except Exception:
            pass


def get_response_queue() -> Optional[Queue]:
    """获取响应队列（前端 -> 主进程）"""
    return _response_queue
