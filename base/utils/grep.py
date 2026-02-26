"""Utilities to run ripgrep searches as part of function calling."""
from __future__ import annotations

import os
import sys
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List
from ..logger import log_tool_error


def _get_rg_path() -> str:
    """
    获取 ripgrep 可执行文件路径
    
    PyInstaller 打包环境下，rg.exe 在可执行文件所在目录
    开发环境下，先检查项目根目录，再使用系统 PATH 中的 rg
    """
    if getattr(sys, 'frozen', False):
        # 打包环境：rg.exe 在可执行文件所在目录
        exe_dir = os.path.dirname(sys.executable)
        rg_path = os.path.join(exe_dir, 'rg.exe')
        if os.path.exists(rg_path):
            return rg_path
    else:
        # 开发环境：先检查项目根目录（当前文件的上上级目录）
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent.parent
        rg_path = project_root / 'rg.exe'
        if rg_path.exists():
            return str(rg_path)
    
    # 使用系统 PATH 中的 rg
    return "rg"


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _resolve_search_path(raw_path: Any) -> str:
    if not raw_path:
        return "."
    path_str = str(raw_path)
    try:
        path = Path(path_str).expanduser().resolve()
    except Exception:
        # Fall back to original string if resolution fails (rg will report error)
        return path_str
    return str(path)


def grep(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute ripgrep with the provided parameters and return structured output."""
    result: Dict[str, Any] = {
        "ok": False,
        "command": None,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "duration_sec": None,
        "args": params,
    }

    pattern = params.get("pattern")
    if not pattern or not isinstance(pattern, str):
        result["stderr"] = "pattern 参数缺失或类型错误"
        return result

    output_mode = params.get("output_mode", "files_with_matches")
    if output_mode not in {"content", "files_with_matches", "count"}:
        result["stderr"] = "output_mode 仅支持 content/files_with_matches/count"
        return result

    command: List[str] = [_get_rg_path()]

    # Output mode flags
    if output_mode == "files_with_matches":
        command.append("--files-with-matches")
    elif output_mode == "count":
        command.append("--count")

    glob = params.get("glob")
    if isinstance(glob, str) and glob:
        command.extend(["--glob", glob])

    type_filter = params.get("type")
    if isinstance(type_filter, str) and type_filter:
        command.extend(["--type", type_filter])

    if params.get("-i"):
        command.append("-i")

    if params.get("multiline"):
        command.extend(["-U", "--multiline", "--multiline-dotall"])

    if output_mode == "content":
        before = _coerce_int(params.get("-B"))
        if before is not None and before >= 0:
            command.extend(["-B", str(before)])

        after = _coerce_int(params.get("-A"))
        if after is not None and after >= 0:
            command.extend(["-A", str(after)])

        context = _coerce_int(params.get("-C"))
        if context is not None and context >= 0:
            command.extend(["-C", str(context)])

        if params.get("-n"):
            command.append("-n")

    command.append(pattern)

    search_path = _resolve_search_path(params.get("path"))
    if search_path:
        command.append(search_path)

    result["command"] = " ".join(shlex.quote(part) for part in command)

    start = time.time()
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as e:
        result["stderr"] = "未找到 rg (ripgrep) 命令，请确认已安装并在 PATH 中"
        log_tool_error("grep", "ripgrep command not found", params, e)
        return result
    except Exception as exc:
        result["stderr"] = f"执行异常: {exc}"
        log_tool_error("grep", f"Grep execution failed: {str(exc)}", params, exc)
        return result

    duration = time.time() - start
    stdout = proc.stdout
    stderr = proc.stderr

    head_limit = _coerce_int(params.get("head_limit"))
    if head_limit is not None and head_limit >= 0:
        stdout_lines = stdout.splitlines()
        stdout = "\n".join(stdout_lines[:head_limit])

    result["duration_sec"] = round(duration, 4)
    result["returncode"] = proc.returncode
    result["stdout"] = stdout
    result["stderr"] = stderr

    if proc.returncode == 0:
        result["ok"] = True
    elif proc.returncode == 1 and not stderr.strip():
        # ripgrep uses return code 1 to indicate "no matches"
        result["ok"] = True
        result["info"] = "未找到匹配"
    else:
        result["ok"] = False

    return result


__all__ = ["grep"]
