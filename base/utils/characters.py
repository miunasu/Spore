import os
import sys
from pathlib import Path
from typing import List, Dict, Optional
from ..logger import log_error


def _get_resource_dir() -> str:
    """
    获取资源目录路径
    
    PyInstaller 打包环境下，资源文件在 SPORE_RESOURCE_DIR 环境变量指定的目录
    开发环境下，资源文件在项目根目录
    """
    # 优先使用环境变量
    resource_dir = os.environ.get('SPORE_RESOURCE_DIR')
    if resource_dir and os.path.exists(resource_dir):
        return resource_dir
    
    # 开发环境：从 __file__ 推断项目根目录
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.dirname(base_dir)


def _characters_root() -> Optional[str]:
    from ..config import get_config
    resource_dir = _get_resource_dir()
    config = get_config()
    characters_dir = os.path.join(resource_dir, config.characters_dir)
    if os.path.isdir(characters_dir):
        return characters_dir
    return None


def list_character_documents() -> List[Dict[str, str]]:
    """列出 characters 目录下所有 Markdown 角色文档。"""
    root = _characters_root()
    if not root:
        return []

    docs: List[Dict[str, str]] = []
    try:
        for filename in sorted(os.listdir(root)):
            if not filename.lower().endswith(".md"):
                continue
            path = os.path.join(root, filename)
            if not os.path.isfile(path):
                continue
            docs.append(
                {
                    "name": os.path.splitext(filename)[0],
                    "path": path,
                }
            )
    except Exception as e:
        log_error("CHARACTER_LIST_ERROR", "Failed to list character documents", e, 
                 context={"characters_dir": str(characters_dir)})
        return []

    return docs


def load_character_document(character_name: str) -> Optional[Dict[str, str]]:
    """根据角色名称加载对应的 Markdown 文档内容。"""
    if not character_name:
        return None

    target = character_name.strip().lower()
    if not target:
        return None
    if target.endswith(".md"):
        target = target[:-3]

    docs = list_character_documents()
    for doc in docs:
        if doc["name"].lower() == target:
            try:
                with open(doc["path"], "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception as e:
                log_error("CHARACTER_READ_ERROR", f"Failed to read character file: {doc['name']}", e, 
                         context={"character_path": doc["path"]})
                return None
            return {"name": doc["name"], "path": doc["path"], "content": content}

    return None


def get_all_characters_summary() -> str:
    """获取所有可用角色的简介列表（用于{characters}占位符）。"""
    docs = list_character_documents()
    if not docs:
        return "暂无可用角色"
    
    parts: List[str] = []
    for doc in docs:
        parts.append(f"- {doc['name']}")
    
    return "\n".join(parts)
