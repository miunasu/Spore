"""
备份恢复管理器 (Backup & Restore Manager)

实现两层回滚机制：
1. 文件级回滚（细粒度）：Hook 所有文件写工具调用，操作前后哈希对比，
   内容变化才备份。首次备份存储完整文件（baseline），后续变化存储
   bsdiff4 二进制 patch（bsdiff4 不可用时自动回退为完整快照）。
2. 对话点回滚（粗粒度）：仅当某轮 LLM 回复的 ACTION 实际改动了
   被跟踪文件时创建 checkpoint，记录改动前所有文件的版本号，
   可同时回滚代码 + 对话历史（回到这条回复之前）。

存储结构:
    .spore/
    ├── backups/<path_hash>/        # 按文件路径哈希分组
    │   ├── baseline.full           # 首次备份时的原始文件
    │   ├── v0001.patch             # 第1次修改的二进制 diff
    │   ├── v0002.full              # 链断裂/定期重建的完整快照
    │   └── ...
    ├── metadata/file_history.json  # 文件路径 -> 版本历史映射
    └── checkpoints/<session>.json  # 对话点快照
"""
import hashlib
import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .logger import log_error
from .utils.path_validator import normalize_path_for_pathlib

try:
    import bsdiff4  # type: ignore
    _BSDIFF_AVAILABLE = True
except Exception:
    bsdiff4 = None  # type: ignore
    _BSDIFF_AVAILABLE = False

# 每累计 N 个版本强制存一次完整快照，限制 patch 链长度
_FULL_SNAPSHOT_INTERVAL = 20


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class BackupManager:
    """文件级增量备份 + 对话点快照"""

    def __init__(self, root_dir: Optional[str] = None):
        from .config import get_config, _PROJECT_ROOT
        config = get_config()
        base = root_dir or getattr(config, "backup_dir", ".spore")
        base_path = Path(base)
        if not base_path.is_absolute():
            base_path = Path(_PROJECT_ROOT) / base_path
        self.root = base_path
        # 移除全局路径，改为会话级动态获取
        # self.backups_dir 和 self.metadata_path 现在通过 _get_session_backup_dir 和 _get_session_metadata_path 获取
        self.checkpoints_dir = self.root / "checkpoints"
        self.audit_path = self.root / "security_audit.jsonl"

        self._lock = threading.RLock()
        # 元数据改为按会话缓存：{session_id: metadata_dict}
        self._metadata_cache: Dict[str, Dict[str, Any]] = {}
        self._checkpoint_counter = 0
        # 待提交的对话点上下文（按会话）：ACTION 执行前登记，
        # 本轮首次实际记录文件版本时提交为 checkpoint，轮末清除
        self._pending_rounds: Dict[str, Dict[str, Any]] = {}

    # 开关与限额动态读取当前配置，支持设置菜单"保存并应用"后热生效
    # （存储目录 root 保持进程内固定，运行中切换会导致元数据错位，需重启生效）
    @property
    def enabled(self) -> bool:
        from .config import get_config
        return getattr(get_config(), "backup_enabled", True)

    @property
    def max_file_bytes(self) -> int:
        from .config import get_config
        return getattr(get_config(), "backup_max_file_bytes", 50 * 1024 * 1024)

    @property
    def max_delete_files(self) -> int:
        from .config import get_config
        return getattr(get_config(), "backup_max_delete_files", 200)

    # ------------------------------------------------------------------
    # 会话级路径获取
    # ------------------------------------------------------------------
    def _get_session_backup_dir(self, session_id: Optional[str]) -> Path:
        """获取会话级备份目录"""
        if session_id:
            return self.root / "backups" / session_id
        # 后向兼容：无 session_id 时使用全局目录
        return self.root / "backups" / "__global__"
    
    def _get_session_metadata_path(self, session_id: Optional[str]) -> Path:
        """获取会话级元数据路径"""
        if session_id:
            return self.root / "metadata" / f"{session_id}_file_history.json"
        # 后向兼容：无 session_id 时使用全局文件
        return self.root / "metadata" / "file_history.json"

    # ------------------------------------------------------------------
    # 元数据
    # ------------------------------------------------------------------
    def _load_metadata(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """加载会话级元数据"""
        cache_key = session_id or "__global__"
        if cache_key in self._metadata_cache:
            return self._metadata_cache[cache_key]
        
        data: Dict[str, Any] = {}
        metadata_path = self._get_session_metadata_path(session_id)
        if metadata_path.is_file():
            try:
                with open(metadata_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                if isinstance(raw, dict):
                    data = raw
            except Exception as e:
                log_error("BACKUP_METADATA_LOAD_ERROR", f"Failed to load {metadata_path.name}", e)
        self._metadata_cache[cache_key] = data
        return data

    def _save_metadata(self, session_id: Optional[str] = None) -> None:
        """保存会话级元数据"""
        cache_key = session_id or "__global__"
        metadata_path = self._get_session_metadata_path(session_id)
        try:
            metadata_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = metadata_path.with_suffix(".json.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._metadata_cache.get(cache_key, {}), f, ensure_ascii=False, indent=1)
            tmp.replace(metadata_path)
        except Exception as e:
            log_error("BACKUP_METADATA_SAVE_ERROR", f"Failed to save {metadata_path.name}", e)

    @staticmethod
    def _normalize(path: str) -> str:
        try:
            return str(Path(normalize_path_for_pathlib(path)).resolve())
        except Exception:
            return str(path)

    @staticmethod
    def _path_hash(norm_path: str) -> str:
        return hashlib.sha256(norm_path.lower().encode("utf-8")).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Hook：写操作前后
    # ------------------------------------------------------------------
    WRITE_TOOLS = ("file", "edit")

    def extract_write_paths(self, tool_name: str, args: Dict[str, Any]) -> List[str]:
        """从工具参数中提取将被修改的文件路径列表；非写操作返回空列表。"""
        if not self.enabled:
            return []
        paths: List[str] = []
        if tool_name == "edit":
            p = args.get("file_path") or args.get("path")
            if p:
                paths.append(str(p))
        elif tool_name == "file":
            op = (args.get("type") or "read").lower()
            if op == "write":
                p = args.get("file_path") or args.get("path")
                if p:
                    paths.append(str(p))
            elif op == "delete":
                raw = args.get("paths", [])
                if isinstance(raw, str):
                    try:
                        parsed = json.loads(raw)
                        raw = parsed if isinstance(parsed, list) else [raw]
                    except json.JSONDecodeError:
                        raw = [raw]
                if isinstance(raw, list):
                    for p in raw:
                        paths.extend(self._expand_delete_target(str(p)))
        return paths

    def _expand_delete_target(self, path: str) -> List[str]:
        """删除目标可能是目录：展开为文件列表（受数量上限保护）。"""
        norm = self._normalize(path)
        p = Path(norm)
        if p.is_file():
            return [norm]
        if p.is_dir():
            files: List[str] = []
            try:
                for child in p.rglob("*"):
                    if child.is_file():
                        files.append(str(child))
                        if len(files) >= self.max_delete_files:
                            log_error(
                                "BACKUP_DELETE_TRUNCATED",
                                f"目录 {norm} 文件过多，仅备份前 {self.max_delete_files} 个文件",
                            )
                            break
            except Exception as e:
                log_error("BACKUP_DIR_WALK_ERROR", f"遍历目录失败: {norm}", e)
            return files
        return [norm]  # 不存在的路径也记录（可能是新建文件）

    def before_tool(self, tool_name: str, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """写操作执行前调用：读取原始内容。返回 token 供 after_tool 使用。"""
        if not self.enabled or tool_name not in self.WRITE_TOOLS:
            return None
        try:
            paths = self.extract_write_paths(tool_name, args)
        except Exception as e:
            log_error("BACKUP_EXTRACT_PATH_ERROR", f"提取写路径失败: {e}", e)
            return None
        if not paths:
            return None

        snapshot: Dict[str, Tuple[Optional[bytes], Optional[str]]] = {}
        for raw in paths:
            norm = self._normalize(raw)
            if norm in snapshot:
                continue
            content, digest = self._read_file_bytes(norm)
            snapshot[norm] = (content, digest)

        op = tool_name
        sub = args.get("type")
        if sub:
            op = f"{tool_name}:{sub}"
        # 记录发起写操作的会话，用于 rewind 的会话隔离
        try:
            from .session_context import get_current_conversation_id
            session_id = get_current_conversation_id()
        except Exception:
            session_id = None
        return {"op": op, "snapshot": snapshot, "session_id": session_id}

    def after_tool(self, token: Optional[Dict[str, Any]]) -> None:
        """写操作执行后调用：对比哈希，内容变化才记录版本。"""
        if not token:
            return
        op = token.get("op", "unknown")
        session_id = token.get("session_id")
        snapshot: Dict[str, Tuple[Optional[bytes], Optional[str]]] = token.get("snapshot", {})
        for norm, (before, before_hash) in snapshot.items():
            try:
                after, after_hash = self._read_file_bytes(norm)
                if before_hash == after_hash:
                    continue  # 内容未变化，不备份
                self._record_version(norm, before, before_hash, after, after_hash, op, session_id)
            except Exception as e:
                log_error("BACKUP_AFTER_TOOL_ERROR", f"记录备份版本失败: {norm}", e)

    def _read_file_bytes(self, norm_path: str) -> Tuple[Optional[bytes], Optional[str]]:
        """读取文件字节；不存在或超限返回 (None, None) / (None, 'oversized')。"""
        p = Path(norm_path)
        if not p.is_file():
            return None, None
        try:
            size = p.stat().st_size
            if size > self.max_file_bytes:
                return None, "oversized"
            content = p.read_bytes()
            return content, _sha256(content)
        except Exception as e:
            log_error("BACKUP_READ_ERROR", f"读取文件失败: {norm_path}", e)
            return None, None

    # ------------------------------------------------------------------
    # 版本记录与恢复
    # ------------------------------------------------------------------
    def _record_version(
        self,
        norm_path: str,
        before: Optional[bytes],
        before_hash: Optional[str],
        after: Optional[bytes],
        after_hash: Optional[str],
        op: str,
        session_id: Optional[str] = None,
    ) -> Optional[int]:
        """记录一个版本。返回版本 id。"""
        if before_hash == "oversized" or after_hash == "oversized":
            return None  # 超大文件不做备份

        with self._lock:
            # 使用会话级元数据
            meta = self._load_metadata(session_id)
            path_hash = self._path_hash(norm_path)
            entry = meta.get(norm_path)
            if entry is None:
                entry = {"path_hash": path_hash, "versions": []}
                meta[norm_path] = entry
            versions: List[Dict[str, Any]] = entry["versions"]
            version_id = len(versions) + 1

            # 使用会话级备份目录
            session_backup_dir = self._get_session_backup_dir(session_id)
            backup_dir = session_backup_dir / path_hash
            backup_dir.mkdir(parents=True, exist_ok=True)

            # 首个版本且原文件存在：先存 baseline（修改前的原始内容）
            baseline_path = backup_dir / "baseline.full"
            if not versions and before is not None and not baseline_path.exists():
                baseline_path.write_bytes(before)

            # 决定存储方式
            store = "full"
            if after is None:
                store = "delete"
            else:
                last_after_hash = versions[-1]["after_hash"] if versions else (
                    _sha256(before) if before is not None else None
                )
                chain_intact = before_hash is not None and before_hash == last_after_hash
                periodic_full = version_id % _FULL_SNAPSHOT_INTERVAL == 0
                if (
                    _BSDIFF_AVAILABLE
                    and before is not None
                    and chain_intact
                    and not periodic_full
                ):
                    store = "patch"

            # 写入备份文件
            if store == "patch":
                patch = bsdiff4.diff(before, after)  # type: ignore[union-attr]
                (backup_dir / f"v{version_id:04d}.patch").write_bytes(patch)
            elif store == "full":
                (backup_dir / f"v{version_id:04d}.full").write_bytes(after or b"")

            versions.append({
                "id": version_id,
                "ts": _now_iso(),
                "op": op,
                "store": store,
                "before_hash": before_hash,
                "after_hash": after_hash,
                "size": len(after) if after is not None else 0,
                "session": session_id,
            })
            # 使用会话级保存
            self._save_metadata(session_id)
            # 本轮首次实际改动文件：提交该轮登记的对话点快照
            self._commit_pending_checkpoint(session_id)
            return version_id

    def _reconstruct(self, norm_path: str, target_version: int, session_id: Optional[str] = None) -> Tuple[bool, Optional[bytes]]:
        """
        重建文件在指定版本时的内容。

        target_version=0 表示 baseline（首次备份前的原始内容）。
        返回 (成功, 内容)；内容为 None 表示该版本文件不存在（已删除/尚未创建）。
        """
        # 使用会话级元数据
        meta = self._load_metadata(session_id)
        entry = meta.get(norm_path)
        if entry is None:
            return False, None
        versions: List[Dict[str, Any]] = entry["versions"]
        # 使用会话级备份目录
        session_backup_dir = self._get_session_backup_dir(session_id)
        backup_dir = session_backup_dir / entry["path_hash"]
        baseline_path = backup_dir / "baseline.full"

        if target_version == 0:
            if baseline_path.exists():
                return True, baseline_path.read_bytes()
            # 无 baseline：文件在首次备份前不存在
            return True, None

        target = next((v for v in versions if v["id"] == target_version), None)
        if target is None:
            return False, None

        # 从最近的完整快照（或 baseline）开始向前应用 patch 链
        content: Optional[bytes] = baseline_path.read_bytes() if baseline_path.exists() else None
        start_idx = 0
        for i, v in enumerate(versions):
            if v["id"] > target_version:
                break
            if v["store"] in ("full", "delete"):
                start_idx = i  # 链可以从这里直接开始

        for v in versions[start_idx:]:
            if v["id"] > target_version:
                break
            store = v["store"]
            if store == "full":
                content = (backup_dir / f"v{v['id']:04d}.full").read_bytes()
            elif store == "delete":
                content = None
            else:  # patch
                if content is None or not _BSDIFF_AVAILABLE:
                    return False, None
                patch = (backup_dir / f"v{v['id']:04d}.patch").read_bytes()
                content = bsdiff4.patch(content, patch)  # type: ignore[union-attr]
        return True, content

    def restore_file(
        self,
        file_path: str,
        version_id: Optional[int] = None,
        steps: Optional[int] = None,
        record: bool = True,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        恢复文件到指定版本。

        version_id: 目标版本号（0 表示 baseline）
        steps: 回退 N 个版本（与 version_id 二选一）
        record: 是否把这次恢复记录为新版本（默认记录，支持"撤销恢复"）
        session_id: 发起恢复的会话（记录在恢复版本上，供 rewind 会话隔离）
        """
        norm = self._normalize(file_path)
        with self._lock:
            # 使用会话级元数据
            meta = self._load_metadata(session_id)
            entry = meta.get(norm)
            if entry is None:
                return {"ok": False, "error": f"没有该文件的备份记录: {norm}"}
            versions = entry["versions"]
            latest = versions[-1]["id"] if versions else 0

            if version_id is None:
                back = steps if steps is not None else 1
                version_id = max(0, latest - back)
            if version_id > latest:
                return {"ok": False, "error": f"版本号超出范围: {version_id} (最新 {latest})"}

            # 传递 session_id 到 _reconstruct
            ok, content = self._reconstruct(norm, version_id, session_id)
            if not ok:
                return {"ok": False, "error": f"重建版本内容失败: {norm} v{version_id}"}

            # 当前磁盘内容（用于记录恢复操作本身）
            cur_content, cur_hash = self._read_file_bytes(norm)

            try:
                p = Path(norm)
                if content is None:
                    if p.exists():
                        p.unlink()
                else:
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(content)
            except Exception as e:
                return {"ok": False, "error": f"写回文件失败: {e}"}

            if record:
                new_hash = _sha256(content) if content is not None else None
                if cur_hash != new_hash:
                    self._record_version(
                        norm, cur_content, cur_hash, content, new_hash,
                        op=f"restore:v{version_id}",
                        session_id=session_id,
                    )

            return {
                "ok": True,
                "path": norm,
                "restored_to_version": version_id,
                "deleted": content is None,
            }

    def get_history(self, file_path: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        """查看某文件的版本历史。"""
        norm = self._normalize(file_path)
        with self._lock:
            # 使用会话级元数据
            meta = self._load_metadata(session_id)
            entry = meta.get(norm)
            if entry is None:
                return {"ok": False, "error": f"没有该文件的备份记录: {norm}"}
            # 使用会话级备份目录
            session_backup_dir = self._get_session_backup_dir(session_id)
            return {
                "ok": True,
                "path": norm,
                "has_baseline": (session_backup_dir / entry["path_hash"] / "baseline.full").exists(),
                "versions": entry["versions"],
            }

    def list_tracked_files(self, session_id: Optional[str] = None) -> List[str]:
        with self._lock:
            return list(self._load_metadata(session_id).keys())

    # ------------------------------------------------------------------
    # 对话点快照 (Checkpoint)
    # ------------------------------------------------------------------
    def _checkpoint_file(self, session_id: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in (session_id or "default"))
        return self.checkpoints_dir / f"{safe}.json"

    def _load_checkpoints(self, session_id: str) -> List[Dict[str, Any]]:
        path = self._checkpoint_file(session_id)
        if path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    return data
            except Exception as e:
                log_error("CHECKPOINT_LOAD_ERROR", f"加载 checkpoint 失败: {session_id}", e)
        return []

    def _save_checkpoints(self, session_id: str, checkpoints: List[Dict[str, Any]]) -> None:
        try:
            path = self._checkpoint_file(session_id)
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".json.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(checkpoints, f, ensure_ascii=False, indent=1)
            tmp.replace(path)
        except Exception as e:
            log_error("CHECKPOINT_SAVE_ERROR", f"保存 checkpoint 失败: {session_id}", e)

    def create_checkpoint(
        self,
        session_id: str,
        message_count: int,
        llm_reply_count: int = 0,
        reply_preview: str = "",
        files: Optional[Dict[str, int]] = None,
    ) -> Optional[str]:
        """
        创建对话点快照。

        files 为快照记录的文件版本表（回滚目标）；不传则取当前所有
        被跟踪文件的最新版本。正常流程由 begin_round/_record_version
        在某轮 ACTION 实际改动文件时自动提交（files 为改动前的版本），
        rewind 该点即回到"这条回复之前"的状态。
        reply_preview 为该轮 LLM 回复的摘要，用于 UI 标识快照对应哪条回复。
        """
        if not self.enabled:
            return None
        with self._lock:
            if files is None:
                # 使用会话级元数据
                meta = self._load_metadata(session_id)
                files = {
                    path: (entry["versions"][-1]["id"] if entry["versions"] else 0)
                    for path, entry in meta.items()
                }
            checkpoints = self._load_checkpoints(session_id)

            # 与上一个 checkpoint 完全相同（消息数和文件版本都没变）则跳过
            if checkpoints:
                last = checkpoints[-1]
                if last.get("message_count") == message_count and last.get("files") == files:
                    return last.get("id")

            self._checkpoint_counter += 1
            cp_id = f"cp_{len(checkpoints) + 1:04d}"
            checkpoints.append({
                "id": cp_id,
                "ts": _now_iso(),
                "session_id": session_id,
                "message_count": message_count,
                "llm_reply_count": llm_reply_count,
                "reply_preview": (reply_preview or "")[:200],
                "files": files,
            })
            self._save_checkpoints(session_id, checkpoints)
            return cp_id

    # ------------------------------------------------------------------
    # 轮次挂钩：仅当 ACTION 实际改动文件时才提交对话点
    # ------------------------------------------------------------------
    @staticmethod
    def _round_key(session_id: Optional[str]) -> str:
        return session_id or "default"

    def begin_round(
        self,
        session_id: str,
        message_count: int,
        llm_reply_count: int = 0,
        reply_preview: str = "",
    ) -> None:
        """
        ACTION 执行前调用：登记待提交的对话点上下文（含改动前的文件版本表）。
        本轮内首次实际记录文件版本时提交为 checkpoint；没有文件改动则不产生快照。
        """
        if not self.enabled:
            return
        with self._lock:
            # 使用会话级元数据
            meta = self._load_metadata(session_id)
            files = {
                path: (entry["versions"][-1]["id"] if entry["versions"] else 0)
                for path, entry in meta.items()
            }
            self._pending_rounds[self._round_key(session_id)] = {
                "session_id": session_id,
                "message_count": message_count,
                "llm_reply_count": llm_reply_count,
                "reply_preview": reply_preview,
                "files": files,
            }

    def end_round(self, session_id: str) -> None:
        """ACTION 执行结束后调用：清除未提交的对话点上下文。"""
        with self._lock:
            self._pending_rounds.pop(self._round_key(session_id), None)

    def _commit_pending_checkpoint(self, session_id: Optional[str]) -> None:
        """本轮首次记录文件版本时提交对话点（在 _record_version 内、持锁状态下调用）。"""
        pending = self._pending_rounds.pop(self._round_key(session_id), None)
        if pending is None:
            return
        self.create_checkpoint(
            session_id=pending["session_id"],
            message_count=pending["message_count"],
            llm_reply_count=pending["llm_reply_count"],
            reply_preview=pending["reply_preview"],
            files=pending["files"],
        )

    def list_checkpoints(self, session_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return self._load_checkpoints(session_id)

    def clear_checkpoints(self, session_id: str) -> int:
        """
        清空指定会话的对话点快照。

        新建对话 / 清除记忆 / 删除会话时调用：对话历史已从零开始，
        旧 checkpoint 的 message_count 相对新对话没有意义，继续保留
        会导致跨对话 rewind 语义错乱。返回清除的快照数量。
        """
        with self._lock:
            count = len(self._load_checkpoints(session_id))
            path = self._checkpoint_file(session_id)
            try:
                if path.is_file():
                    path.unlink()
            except Exception as e:
                log_error("CHECKPOINT_CLEAR_ERROR", f"清空 checkpoint 失败: {session_id}", e)
                return 0
            return count

    def rewind(
        self,
        session_id: str,
        checkpoint_id: Optional[str] = None,
        steps: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        回滚到指定对话点：恢复所有文件到 checkpoint 时的版本。

        会话隔离：只回滚本会话在该对话点之后修改过的文件；
        仅被其它会话修改的文件不动（记入 skipped）。
        旧数据的版本记录没有 session 字段，视为本会话以保持兼容。

        返回 message_count 供调用方截断对话历史。
        checkpoint_id 与 steps（回退 N 个对话点）二选一，默认回退 1 个。
        """
        with self._lock:
            checkpoints = self._load_checkpoints(session_id)
            if not checkpoints:
                return {"ok": False, "error": "当前会话没有可用的对话点快照"}

            target: Optional[Dict[str, Any]] = None
            if checkpoint_id:
                target = next((c for c in checkpoints if c["id"] == checkpoint_id), None)
                if target is None:
                    return {"ok": False, "error": f"未找到对话点: {checkpoint_id}"}
            else:
                back = steps if steps is not None else 1
                idx = len(checkpoints) - back
                if idx < 0:
                    idx = 0
                target = checkpoints[idx]

            cp_files: Dict[str, int] = target.get("files", {})
            # 使用会话级元数据
            meta = self._load_metadata(session_id)

            restored: List[str] = []
            deleted: List[str] = []
            skipped: List[str] = []
            failed: List[Dict[str, str]] = []

            # 本会话跟踪的文件：恢复到 checkpoint 记录的版本；
            # checkpoint 之后才首次被修改的文件恢复到 v0（baseline / 不存在）
            for path, entry in meta.items():
                versions = entry["versions"]
                latest = versions[-1]["id"] if versions else 0
                target_v = cp_files.get(path, 0)
                if latest == target_v:
                    continue
                # 会话隔离：对话点之后的修改全部来自其它会话则跳过
                post = [v for v in versions if v["id"] > target_v]
                if post and not any(v.get("session") in (session_id, None) for v in post):
                    skipped.append(path)
                    continue
                result = self.restore_file(
                    path, version_id=target_v, record=True, session_id=session_id
                )
                if result.get("ok"):
                    if result.get("deleted"):
                        deleted.append(path)
                    else:
                        restored.append(path)
                else:
                    failed.append({"path": path, "error": result.get("error", "")})

            return {
                "ok": not failed,
                "checkpoint": target["id"],
                "ts": target["ts"],
                "message_count": target["message_count"],
                "restored": restored,
                "deleted": deleted,
                "skipped": skipped,
                "failed": failed,
            }


# ---------------------------------------------------------------------------
# 全局单例
# ---------------------------------------------------------------------------
_backup_manager: Optional[BackupManager] = None
_manager_lock = threading.Lock()


def get_backup_manager() -> BackupManager:
    global _backup_manager
    if _backup_manager is None:
        with _manager_lock:
            if _backup_manager is None:
                _backup_manager = BackupManager()
    return _backup_manager
