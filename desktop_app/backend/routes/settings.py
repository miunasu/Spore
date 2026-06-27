"""
设置 API - 管理系统配置和 characters
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import os
import subprocess
import sys
from pathlib import Path

from ..core import get_instances, apply_runtime_config

router = APIRouter()


def _get_env_path() -> Path:
    """Return the .env file used by the desktop backend."""
    from base.config import _PROJECT_ROOT

    return _PROJECT_ROOT / '.env'


class CharacterSelectRequest(BaseModel):
    """选择角色请求"""
    character_name: str


class SettingsUpdateRequest(BaseModel):
    """更新设置请求"""
    default_character: Optional[str] = None


@router.get("/characters/list")
def list_characters() -> Dict[str, Any]:
    """
    获取所有可用角色列表
    
    Returns:
        {
            "success": true,
            "characters": [
                {"name": "Python专家", "path": "..."},
                ...
            ],
            "current": "Python专家" or null
        }
    """
    try:
        from base.utils.characters import list_character_documents, _characters_root
        from base.character_manager import get_selected_characters
        import os
        
        # 获取 characters 目录路径（用于调试）
        characters_root = _characters_root()
        
        # 获取所有角色（不再检查 enable_characters 配置）
        all_characters = list_character_documents()
        
        # 获取当前激活的角色
        current_characters = get_selected_characters()
        current_name = current_characters[0]["name"] if current_characters else None
        
        return {
            "success": True,
            "enabled": True,
            "characters": all_characters,
            "current": current_name,
            "debug": {
                "characters_root": characters_root,
                "characters_count": len(all_characters),
                "exists": os.path.exists(characters_root) if characters_root else False
            }
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "enabled": False,
            "characters": [],
            "current": None
        }


@router.post("/characters/select")
def select_character(request: CharacterSelectRequest) -> Dict[str, Any]:
    """
    选择/切换角色
    
    Args:
        request: 包含 character_name 的请求
    
    Returns:
        {
            "success": true,
            "message": "已选择角色: Python专家"
        }
    """
    try:
        from base.character_manager import select_character
        
        result = select_character(request.character_name)
        return result
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@router.post("/characters/remove")
def remove_character() -> Dict[str, Any]:
    """
    移除当前角色
    
    Returns:
        {
            "success": true,
            "message": "已移除角色: Python专家"
        }
    """
    try:
        from base.character_manager import remove_character, get_selected_characters
        
        # 获取当前角色
        current_characters = get_selected_characters()
        if not current_characters:
            return {
                "success": False,
                "error": "当前没有激活的角色"
            }
        
        character_name = current_characters[0]["name"]
        result = remove_character(character_name)
        return result
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@router.get("/settings")
def get_settings() -> Dict[str, Any]:
    """
    获取当前设置
    
    Returns:
        {
            "default_character": "Python专家",
            "context_mode": "auto",
            ...
        }
    """
    try:
        from base.config import get_config
        
        config = get_config()
        
        return {
            "success": True,
            "settings": {
                "default_character": config.default_character,
                "context_mode": config.context_mode,
                "max_output_tokens": config.max_output_tokens,
            }
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@router.post("/env/open")
def open_env_file() -> Dict[str, Any]:
    """Open the .env file currently used by Spore."""
    try:
        env_path = _get_env_path()

        if not env_path.exists():
            return {
                "success": False,
                "error": ".env 文件不存在"
            }

        if sys.platform == "win32":
            os.startfile(str(env_path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(env_path)])
        else:
            subprocess.Popen(["xdg-open", str(env_path)])

        return {
            "success": True,
            "path": str(env_path)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@router.post("/env/apply")
def apply_env_file() -> Dict[str, Any]:
    """Reload .env and apply runtime-safe settings to the current desktop backend."""
    try:
        return apply_runtime_config()
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@router.post("/settings/update")
def update_settings(request: SettingsUpdateRequest) -> Dict[str, Any]:
    """
    更新设置（写入 .env 文件）
    
    Args:
        request: 包含要更新的设置项
    
    Returns:
        {
            "success": true,
            "message": "设置已更新"
        }
    """
    try:
        from base.config import get_config
        
        config = get_config()
        env_path = _get_env_path()
        
        if not env_path.exists():
            return {
                "success": False,
                "error": ".env 文件不存在"
            }
        
        # 读取现有 .env 文件
        with open(env_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # 更新配置项
        updated_lines = []
        updated_keys = set()
        
        for line in lines:
            stripped = line.strip()
            
            # 更新 DEFAULT_CHARACTER
            if request.default_character is not None and stripped.startswith('DEFAULT_CHARACTER='):
                updated_lines.append(f'DEFAULT_CHARACTER={request.default_character}\n')
                updated_keys.add('DEFAULT_CHARACTER')
            else:
                updated_lines.append(line)
        
        # 如果配置项不存在，添加到文件末尾
        if request.default_character is not None and 'DEFAULT_CHARACTER' not in updated_keys:
            updated_lines.append(f'DEFAULT_CHARACTER={request.default_character}\n')
        
        # 写回文件
        with open(env_path, 'w', encoding='utf-8') as f:
            f.writelines(updated_lines)
        
        # 更新内存中的配置（需要重新加载）
        if request.default_character is not None:
            config.default_character = request.default_character
            apply_runtime_config()
        
        return {
            "success": True,
            "message": "设置已更新，部分设置需要重启后生效"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
