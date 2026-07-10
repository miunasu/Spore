import time
import json
import os
import re
import threading
from typing import Any, List, Dict, Optional
from datetime import datetime
from pathlib import Path


# 历史记录保存目录
HISTORY_DIR = "history"

# 自动保存目录（history 的子目录，与手动保存隔离，避免 FIFO 清理误删手动存档）
AUTOSAVE_DIR = os.path.join(HISTORY_DIR, "autosave")

# 自动保存队列容量，超出后先入先出删除最旧的
AUTOSAVE_MAX_COUNT = 10

# 自动保存写入/清理锁（桌面端多会话并发时保护 FIFO 清理）
_autosave_lock = threading.Lock()

# 自动保存文件名格式。FIFO 清理只认该格式：把某份自动保存重命名即视为“转正”，
# 之后不再被队列淘汰。
_AUTOSAVE_NAME_RE = re.compile(r"^auto_\d{4}-\d{2}-\d{2}_\d{6}_\d{6}(?:_(.+))?\.mem$")


def _ensure_history_dir():
    """确保 history 目录存在"""
    if not os.path.exists(HISTORY_DIR):
        os.makedirs(HISTORY_DIR)


def save_messages(messages: List[Dict[str, str]]):
    """保存对话历史到 history 目录"""
    _ensure_history_dir()
    filename = f"{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.mem"
    filepath = os.path.join(HISTORY_DIR, filename)
    
    with open(filepath, "w", encoding='utf-8') as f:
        json.dump(messages, f, ensure_ascii=False, indent=2)
    print(f"[对话已保存] 文件: {filepath}")
    return filepath


def load_messages(filename: str) -> List[Dict[str, str]]:
    """从 history 目录加载对话历史"""
    # 始终从 history 目录读取
    filepath = os.path.join(HISTORY_DIR, filename)
    
    with open(filepath, "r", encoding='utf-8') as f:
        return json.load(f)


def auto_save_messages(
    messages: List[Dict[str, str]],
    session_id: Optional[str] = None,
) -> Optional[str]:
    """自动保存对话上下文到 autosave 队列（先入先出，最多保留 AUTOSAVE_MAX_COUNT 份）。

    自动保存失败不应影响对话流程，任何异常都会被吞掉并返回 None。
    """
    if not messages:
        return None

    try:
        with _autosave_lock:
            os.makedirs(AUTOSAVE_DIR, exist_ok=True)

            timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S_%f')
            suffix = f"_{session_id}" if session_id else ""
            filepath = os.path.join(AUTOSAVE_DIR, f"auto_{timestamp}{suffix}.mem")

            with open(filepath, "w", encoding='utf-8') as f:
                json.dump(messages, f, ensure_ascii=False, indent=2)

            _prune_autosaves()
            return filepath
    except Exception as e:
        try:
            from .logger import log_error
            log_error("AUTOSAVE_ERROR", "Failed to auto save conversation context", e)
        except Exception:
            pass
        return None


def list_autosave_files() -> List[Dict[str, Any]]:
    """列出自动保存文件，按时间从新到旧排序。

    返回的每一项包含:
    - filename: 相对 history 目录的路径（可直接传给 load_messages）
    - path: 完整路径
    - mtime: 保存时间戳
    - session_id: 保存时的会话 ID（旧文件可能没有，为 None）
    """
    if not os.path.isdir(AUTOSAVE_DIR):
        return []

    entries: List[Dict[str, Any]] = []
    for name in os.listdir(AUTOSAVE_DIR):
        if not name.endswith('.mem'):
            continue
        path = os.path.join(AUTOSAVE_DIR, name)
        match = _AUTOSAVE_NAME_RE.match(name)
        entries.append({
            "filename": os.path.join("autosave", name),
            "path": path,
            "mtime": os.path.getmtime(path),
            "session_id": match.group(1) if match else None,
        })

    entries.sort(key=lambda e: (e["mtime"], e["path"]), reverse=True)
    return entries


def _prune_autosaves() -> None:
    """按先入先出清理 autosave 队列，只保留最新的 AUTOSAVE_MAX_COUNT 份。

    只清理符合自动保存命名格式的文件，重命名过的文件不受影响。
    """
    files = [
        os.path.join(AUTOSAVE_DIR, f)
        for f in os.listdir(AUTOSAVE_DIR)
        if _AUTOSAVE_NAME_RE.match(f)
    ]
    if len(files) <= AUTOSAVE_MAX_COUNT:
        return

    # 文件名内含微秒级时间戳，与修改时间双重排序保证顺序稳定
    files.sort(key=lambda p: (os.path.getmtime(p), p))
    for path in files[:-AUTOSAVE_MAX_COUNT]:
        try:
            os.remove(path)
        except OSError:
            pass


def get_latest_history_file() -> str:
    """获取最近的历史记录文件路径"""
    _ensure_history_dir()
    
    # 获取所有 .mem 文件
    mem_files = [f for f in os.listdir(HISTORY_DIR) if f.endswith('.mem')]
    
    if not mem_files:
        raise FileNotFoundError("没有找到历史记录文件")
    
    # 按修改时间排序，获取最新的
    mem_files.sort(key=lambda f: os.path.getmtime(os.path.join(HISTORY_DIR, f)), reverse=True)
    latest_file = mem_files[0]
    
    return os.path.join(HISTORY_DIR, latest_file)


    