"""
文件管理 API
提供文件和目录的 CRUD 操作
"""
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from pathlib import Path
import os
import sys
import shutil

router = APIRouter()

# 允许访问的根目录（安全限制）
ALLOWED_ROOTS = ["output", "skills", "prompt", "history", "characters"]

# 允许访问的根目录文件（特殊文件）
ALLOWED_ROOT_FILES = ["note.txt", ".env"]


def get_resource_base_dir():
    """
    获取资源基础目录
    
    PyInstaller 打包后，资源文件在 _MEIPASS 临时目录
    """
    # 检查是否设置了资源目录环境变量
    resource_dir = os.environ.get('SPORE_RESOURCE_DIR')
    if resource_dir:
        return Path(resource_dir)
    
    # 默认使用当前工作目录
    return Path.cwd()


def get_actual_path(requested_path: str) -> Path:
    """
    获取实际文件路径
    
    对于只读资源（prompt、skills、characters），从资源目录读取
    对于可写目录（output、history），从工作目录读取
    """
    normalized = requested_path.replace('\\', '/')
    root = normalized.split('/')[0] if normalized and normalized != "." else ""
    
    # 只读资源目录
    readonly_roots = ["prompt", "skills", "characters"]
    
    if root in readonly_roots:
        # 从资源目录读取
        resource_dir = get_resource_base_dir()
        return resource_dir / requested_path
    else:
        # 从工作目录读取/写入
        return Path.cwd() / requested_path


class WriteRequest(BaseModel):
    """写入文件请求"""
    path: str
    content: str


class RenameRequest(BaseModel):
    """重命名请求"""
    old_path: str
    new_path: str


class CreateRequest(BaseModel):
    """创建文件/文件夹请求"""
    path: str
    type: str  # "file" or "folder"
    content: Optional[str] = ""


def validate_path(path: str) -> Path:
    """
    验证路径安全性
    
    Args:
        path: 请求的路径
        
    Returns:
        Path: 验证后的路径对象
        
    Raises:
        HTTPException: 路径不安全时抛出
    """
    # 规范化路径
    rel_str = path.replace('\\', '/')
    
    # 检查是否是允许的根目录文件
    if rel_str in ALLOWED_ROOT_FILES:
        return get_actual_path(rel_str)
    
    # 检查是否在允许的根目录下
    root = rel_str.split('/')[0] if rel_str != "." else ""
    
    if root and root not in ALLOWED_ROOTS:
        raise HTTPException(status_code=403, detail=f"不允许访问目录: {root}")
    
    # 获取实际路径
    actual_path = get_actual_path(rel_str)
    
    # 确保路径不会逃逸到父目录
    try:
        if root in ["prompt", "skills", "characters"]:
            # 只读资源：相对于资源目录
            resource_dir = get_resource_base_dir()
            actual_path.resolve().relative_to(resource_dir.resolve())
        else:
            # 可写目录：相对于工作目录
            actual_path.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail=f"路径超出允许范围: {path}")
    
    return actual_path


@router.get("/list")
def list_directory(path: str = Query(..., description="目录路径")) -> Dict[str, Any]:
    """列出目录内容"""
    try:
        # 特殊处理根目录请求
        if path == "." or path == "" or path == "/":
            # 返回允许访问的根目录列表
            items = []
            for root in ALLOWED_ROOTS:
                root_path = get_actual_path(root)
                if root_path.exists() and root_path.is_dir():
                    try:
                        stat = root_path.stat()
                        items.append({
                            "name": root,
                            "type": "folder",
                            "path": root,
                            "size": None,
                            "modified": stat.st_mtime
                        })
                    except (PermissionError, OSError):
                        continue
            items.sort(key=lambda x: x["name"].lower())
            return {"path": ".", "items": items}
        
        dir_path = validate_path(path)
        
        if not dir_path.exists():
            raise HTTPException(status_code=404, detail="目录不存在")
        
        if not dir_path.is_dir():
            raise HTTPException(status_code=400, detail="路径不是目录")
        
        items = []
        for item in dir_path.iterdir():
            try:
                stat = item.stat()
                # 计算相对路径
                rel_path = path.rstrip('/') + '/' + item.name
                items.append({
                    "name": item.name,
                    "type": "folder" if item.is_dir() else "file",
                    "path": rel_path,
                    "size": stat.st_size if item.is_file() else None,
                    "modified": stat.st_mtime
                })
            except (PermissionError, OSError):
                continue
        
        # 文件夹在前，文件在后，按名称排序
        items.sort(key=lambda x: (x["type"] != "folder", x["name"].lower()))
        
        return {
            "path": path,
            "items": items
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/read")
def read_file(path: str = Query(..., description="文件路径")) -> Dict[str, Any]:
    """读取文件内容"""
    try:
        file_path = validate_path(path)
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="文件不存在")
        
        if not file_path.is_file():
            raise HTTPException(status_code=400, detail="路径不是文件")
        
        # 尝试读取文本内容
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            # 二进制文件
            raise HTTPException(status_code=400, detail="无法读取二进制文件")
        
        return {
            "path": str(file_path.relative_to(Path.cwd())),
            "content": content,
            "size": file_path.stat().st_size
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/write")
def write_file(req: WriteRequest):
    """写入文件"""
    try:
        file_path = validate_path(req.path)
        
        # 确保父目录存在
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 写入内容
        file_path.write_text(req.content, encoding="utf-8")
        
        return {
            "success": True,
            "path": str(file_path.relative_to(Path.cwd())),
            "size": file_path.stat().st_size
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/delete")
def delete_path(path: str = Query(..., description="文件或目录路径")):
    """删除文件或目录"""
    try:
        target_path = validate_path(path)
        
        if not target_path.exists():
            raise HTTPException(status_code=404, detail="路径不存在")
        
        if target_path.is_dir():
            shutil.rmtree(target_path)
        else:
            target_path.unlink()
        
        return {"success": True, "message": f"已删除: {path}"}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rename")
def rename_path(req: RenameRequest):
    """重命名文件或目录"""
    try:
        old_path = validate_path(req.old_path)
        new_path = validate_path(req.new_path)
        
        if not old_path.exists():
            raise HTTPException(status_code=404, detail="原路径不存在")
        
        if new_path.exists():
            raise HTTPException(status_code=400, detail="目标路径已存在")
        
        old_path.rename(new_path)
        
        return {
            "success": True,
            "old_path": str(old_path.relative_to(Path.cwd())),
            "new_path": str(new_path.relative_to(Path.cwd()))
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/create")
def create_path(req: CreateRequest):
    """创建文件或目录"""
    try:
        target_path = validate_path(req.path)
        
        if target_path.exists():
            raise HTTPException(status_code=400, detail="路径已存在")
        
        if req.type == "folder":
            target_path.mkdir(parents=True)
        else:
            # 确保父目录存在
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(req.content or "", encoding="utf-8")
        
        return {
            "success": True,
            "path": str(target_path.relative_to(Path.cwd())),
            "type": req.type
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
