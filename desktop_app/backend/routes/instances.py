"""
实例管理 API
用于创建、停止和查询后端实例
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List

from ..instance_manager import get_instance_manager

router = APIRouter()


class CreateInstanceRequest(BaseModel):
    """创建实例请求"""
    instance_id: str


class StopInstanceRequest(BaseModel):
    """停止实例请求"""
    instance_id: str


@router.post("/create")
def create_instance(req: CreateInstanceRequest) -> Dict[str, Any]:
    """
    创建新的后端实例
    
    Returns:
        实例信息，包含端口号
    """
    manager = get_instance_manager()
    instance = manager.create_instance(req.instance_id)
    
    if instance is None:
        raise HTTPException(status_code=500, detail="创建实例失败")
    
    return {
        "success": True,
        "instance": {
            "id": instance.id,
            "port": instance.port,
            "status": instance.status,
        }
    }


@router.post("/stop")
def stop_instance(req: StopInstanceRequest) -> Dict[str, Any]:
    """停止后端实例"""
    manager = get_instance_manager()
    success = manager.stop_instance(req.instance_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="实例不存在或停止失败")
    
    return {"success": True, "message": f"实例 {req.instance_id} 已停止"}


@router.get("/list")
def list_instances() -> Dict[str, Any]:
    """列出所有实例"""
    manager = get_instance_manager()
    instances = manager.list_instances()
    return {"instances": instances}


@router.get("/{instance_id}")
def get_instance(instance_id: str) -> Dict[str, Any]:
    """获取实例信息"""
    manager = get_instance_manager()
    instance = manager.get_instance(instance_id)
    
    if instance is None:
        raise HTTPException(status_code=404, detail="实例不存在")
    
    return {
        "id": instance.id,
        "port": instance.port,
        "status": instance.status,
        "created_at": instance.created_at,
    }
