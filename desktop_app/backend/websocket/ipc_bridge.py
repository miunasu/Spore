"""
WebSocket IPC 桥接

通过 multiprocessing.Queue 将消息发送到独立的 WebSocket 推送进程，
彻底解决 Python GIL 阻塞问题。
"""
from typing import Dict, Any
from .ws_process import send_to_ws_process, start_ws_process, stop_ws_process


def send_ws_message(message: Dict[str, Any]):
    """
    发送消息到 WebSocket（线程安全，跨进程）
    
    Args:
        message: 要发送的消息
    """
    send_to_ws_process(message)


def start_ipc_consumer():
    """启动 WebSocket 推送进程"""
    start_ws_process(port=8766)


def stop_ipc_consumer():
    """停止 WebSocket 推送进程"""
    stop_ws_process()
