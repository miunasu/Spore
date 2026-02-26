"""
确认请求 API 路由（备用）

注意：主要的确认机制通过 WebSocket 双向通信实现，
此路由仅作为备用或调试用途。
"""
from fastapi import APIRouter

router = APIRouter()


@router.get("/status")
def confirm_status():
    """确认系统状态"""
    return {"status": "ok", "method": "websocket"}
