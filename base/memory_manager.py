import time
import json
import os
import re
import threading
from typing import Any, List, Dict, Optional, Tuple
from datetime import datetime
from pathlib import Path


# 历史记录保存目录
HISTORY_DIR = "history"

# 自动保存目录（history 的子目录，与手动保存隔离，避免 FIFO 清理误删手动存档）
AUTOSAVE_DIR = os.path.join(HISTORY_DIR, "autosave")

# 短记忆容量：按「会话」计，最多保留最近 N 个会话
AUTOSAVE_MAX_COUNT = 10

# 自动保存写入/清理锁（桌面端多会话并发时保护读写与清理）
_autosave_lock = threading.Lock()

# 新版短记忆：一会话一文件。重命名后若不再匹配此格式，即视为“转正/保留”，不再被队列淘汰。
_SESSION_AUTOSAVE_NAME_RE = re.compile(r"^session_(.+)\.mem$")

# 旧版快照命名（时间戳 + 可选 session_id）。迁移后会清理。
_LEGACY_AUTOSAVE_NAME_RE = re.compile(
    r"^auto_\d{4}-\d{2}-\d{2}_\d{6}_\d{6}(?:_(.+))?\.mem$"
)


def _ensure_history_dir():
    """确保 history 目录存在"""
    if not os.path.exists(HISTORY_DIR):
        os.makedirs(HISTORY_DIR)


def _sanitize_session_id(session_id: Optional[str]) -> str:
    """将会话 ID 转为安全文件名片段。"""
    raw = (session_id or "default").strip() or "default"
    safe = re.sub(r"[^\w\-]+", "_", raw, flags=re.UNICODE)
    safe = safe.strip("._") or "default"
    return safe[:120]


def _session_autosave_filename(session_id: Optional[str]) -> str:
    return f"session_{_sanitize_session_id(session_id)}.mem"


def _session_id_from_autosave_name(name: str) -> Optional[str]:
    session_match = _SESSION_AUTOSAVE_NAME_RE.match(name)
    if session_match:
        return session_match.group(1)
    legacy_match = _LEGACY_AUTOSAVE_NAME_RE.match(name)
    if legacy_match:
        return legacy_match.group(1)
    return None


def save_messages(messages: List[Dict[str, str]]):
    """保存对话历史到 history 目录"""
    _ensure_history_dir()
    filename = f"{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.mem"
    filepath = os.path.join(HISTORY_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(messages, f, ensure_ascii=False, indent=2)
    print(f"[对话已保存] 文件: {filepath}")
    return filepath


def load_messages(filename: str) -> List[Dict[str, str]]:
    """从 history 目录加载对话历史"""
    # 始终从 history 目录读取
    filepath = os.path.join(HISTORY_DIR, filename)

    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def auto_save_messages(
    messages: List[Dict[str, str]],
    session_id: Optional[str] = None,
) -> Optional[str]:
    """按会话 upsert 短记忆，并只保留最近 AUTOSAVE_MAX_COUNT 个会话。

    - 同一 session_id 反复保存时覆盖同一文件（实时更新，不产生多份快照）
    - 不同会话各占一项；超出容量时淘汰最久未更新的会话
    - 自动保存失败不应影响对话流程，任何异常都会被吞掉并返回 None
    """
    if not messages:
        return None

    try:
        with _autosave_lock:
            os.makedirs(AUTOSAVE_DIR, exist_ok=True)
            _migrate_legacy_autosaves_locked()

            filename = _session_autosave_filename(session_id)
            filepath = os.path.join(AUTOSAVE_DIR, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(messages, f, ensure_ascii=False, indent=2)

            # 强制刷新 mtime，保证“最近活跃会话”排序稳定
            now = time.time()
            try:
                os.utime(filepath, (now, now))
            except OSError:
                pass

            _prune_autosaves_locked()
            return filepath
    except Exception as e:
        try:
            from .logger import log_error

            log_error("AUTOSAVE_ERROR", "Failed to auto save conversation context", e)
        except Exception:
            pass
        return None


def list_autosave_files() -> List[Dict[str, Any]]:
    """列出短记忆文件，按最近更新时间从新到旧排序。

    返回的每一项包含:
    - filename: 相对 history 目录的路径（可直接传给 load_messages）
    - path: 完整路径
    - mtime: 保存时间戳
    - session_id: 会话 ID（旧文件/已重命名文件可能为 None）
    """
    if not os.path.isdir(AUTOSAVE_DIR):
        return []

    with _autosave_lock:
        try:
            _migrate_legacy_autosaves_locked()
        except Exception:
            pass

        entries: List[Dict[str, Any]] = []
        for name in os.listdir(AUTOSAVE_DIR):
            if not name.endswith(".mem"):
                continue
            path = os.path.join(AUTOSAVE_DIR, name)
            if not os.path.isfile(path):
                continue
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            entries.append(
                {
                    "filename": os.path.join("autosave", name).replace("\\", "/"),
                    "path": path,
                    "mtime": mtime,
                    "session_id": _session_id_from_autosave_name(name),
                }
            )

        entries.sort(key=lambda e: (e["mtime"], e["path"]), reverse=True)
        return entries


def _managed_autosave_files_locked() -> List[Tuple[str, float]]:
    """返回受容量管理的短记忆文件 (path, mtime)。仅 session_*.mem。"""
    if not os.path.isdir(AUTOSAVE_DIR):
        return []

    managed: List[Tuple[str, float]] = []
    for name in os.listdir(AUTOSAVE_DIR):
        if not _SESSION_AUTOSAVE_NAME_RE.match(name):
            continue
        path = os.path.join(AUTOSAVE_DIR, name)
        if not os.path.isfile(path):
            continue
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        managed.append((path, mtime))
    return managed


def _migrate_legacy_autosaves_locked() -> None:
    """将旧版时间戳快照迁移为“一会话一文件”。

    - 同一 session_id 的多份 legacy 快照：保留最新一份写入 session_*.mem，其余删除
    - 无 session_id 的 orphan 快照：并入 session_default（仅当目标尚不存在时取最新）
    """
    if not os.path.isdir(AUTOSAVE_DIR):
        return

    by_session: Dict[str, List[Tuple[str, float]]] = {}
    orphans: List[Tuple[str, float]] = []

    for name in os.listdir(AUTOSAVE_DIR):
        match = _LEGACY_AUTOSAVE_NAME_RE.match(name)
        if not match:
            continue
        path = os.path.join(AUTOSAVE_DIR, name)
        if not os.path.isfile(path):
            continue
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        sid = match.group(1)
        if sid:
            by_session.setdefault(_sanitize_session_id(sid), []).append((path, mtime))
        else:
            orphans.append((path, mtime))

    def _absorb(session_key: str, candidates: List[Tuple[str, float]]) -> None:
        if not candidates:
            return
        candidates.sort(key=lambda item: (item[1], item[0]))
        target = os.path.join(AUTOSAVE_DIR, f"session_{session_key}.mem")
        newest_path, newest_mtime = candidates[-1]
        if not os.path.exists(target):
            try:
                os.replace(newest_path, target)
                try:
                    os.utime(target, (newest_mtime, newest_mtime))
                except OSError:
                    pass
            except OSError:
                # 改名失败则尝试复制内容
                try:
                    with open(newest_path, "r", encoding="utf-8") as src:
                        data = src.read()
                    with open(target, "w", encoding="utf-8") as dst:
                        dst.write(data)
                    os.remove(newest_path)
                except OSError:
                    pass
        # 删除该会话下剩余 legacy 快照（含已被 session 文件取代的最新份）
        for path, _ in candidates:
            if path == target:
                continue
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

    for session_key, candidates in by_session.items():
        _absorb(session_key, candidates)

    if orphans:
        _absorb("default", orphans)


def _prune_autosaves_locked() -> None:
    """只保留最近更新的 AUTOSAVE_MAX_COUNT 个会话短记忆。

    仅清理 session_*.mem；用户重命名后的文件不受影响。
    """
    managed = _managed_autosave_files_locked()
    if len(managed) <= AUTOSAVE_MAX_COUNT:
        return

    managed.sort(key=lambda item: (item[1], item[0]))
    for path, _ in managed[:-AUTOSAVE_MAX_COUNT]:
        try:
            os.remove(path)
        except OSError:
            pass


def _prune_autosaves() -> None:
    """兼容旧调用：在锁内执行清理。"""
    with _autosave_lock:
        _migrate_legacy_autosaves_locked()
        _prune_autosaves_locked()


def get_latest_history_file() -> str:
    """获取最近的历史记录文件路径"""
    _ensure_history_dir()

    # 获取所有 .mem 文件
    mem_files = [f for f in os.listdir(HISTORY_DIR) if f.endswith(".mem")]

    if not mem_files:
        raise FileNotFoundError("没有找到历史记录文件")

    # 按修改时间排序，获取最新的
    mem_files.sort(
        key=lambda f: os.path.getmtime(os.path.join(HISTORY_DIR, f)), reverse=True
    )
    latest_file = mem_files[0]

    return os.path.join(HISTORY_DIR, latest_file)
