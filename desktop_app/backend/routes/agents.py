"""
Agent 监控 API
"""
from fastapi import APIRouter
from typing import Dict, Any, List

router = APIRouter()

# 活跃的 Agent 信息
_active_agents: Dict[str, Dict[str, Any]] = {}


def register_agent(agent_id: str, agent_name: str, status: str = "running"):
    """注册或更新 Agent"""
    _active_agents[agent_id] = {
        "id": agent_id,
        "name": agent_name,
        "status": status
    }


def update_agent_status(agent_id: str, status: str):
    """更新 Agent 状态"""
    if agent_id in _active_agents:
        _active_agents[agent_id]["status"] = status


def get_active_agents() -> List[Dict[str, Any]]:
    """获取所有活跃的 Agent"""
    return list(_active_agents.values())


@router.get("/list")
def list_agents() -> Dict[str, Any]:
    """获取当前活跃的 Agent 列表"""
    return {"agents": get_active_agents()}

