import os
import json
import difflib
import re
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List
from base.config import current_agent_name
from base.utils import terminal
from base.utils.path_validator import normalize_path_for_pathlib
from ..logger import log_error

def _set_error(result: Dict[str, Any], error_type: str, error_code: str, error_msg: str, suggestions: List[str] = None, debug_info: Dict = None):
    """设置错误信息（包括类型、代码、建议和调试信息）"""
    result["error"] = error_msg
    result["error_type"] = error_type
    result["error_code"] = error_code
    result["suggestions"] = suggestions or []
    result["debug_info"] = debug_info or {}
    return result


def write_text_file(
    path: str,
    content: str,
    encoding: Optional[str] = None,
    *,
    append: bool = False,
    verify_result: bool = True,
) -> Dict[str, Any]:
    """
    写入或覆盖创建文本文件。

    参数:
        path: 文件路径
        content: 要写入的内容
        encoding: 编码格式（None 表示使用默认 utf-8）
        append: 是否追加模式（True=追加，False=覆盖，默认 False）
        verify_result: 是否验证写入结果
    
    等价于 System_Io(action="write").
    
    注意：
        - 支持任意大小的文件写入
        - 对于超大文件，建议使用多次追加写入（append=True）以提高性能
    """
    result: Dict[str, Any] = {
        "ok": False,
        "action": "append" if append else "write",
        "path": path,
        "error": None,
        "error_type": None,
        "error_code": None,
        "suggestions": None,
        "debug_info": None,
        "data": None,
        "total_lines": None,
        "bytes_written": None,
        "encoding_used": None,
        "lines_modified": None,
        "verification": None,
    }

    try:
        # 规范化路径:合并多余反斜杠并转换为正斜杠,避免转义字符问题
        file_path = Path(normalize_path_for_pathlib(path)).resolve()
        used_encoding = encoding or 'utf-8'
        result["encoding_used"] = used_encoding

        if content is None:
            result["error"] = "write 操作需要提供 content"
            return result

        # 记录内容大小（用于调试和统计）
        content_size = len(content.encode(used_encoding))

        if file_path.parent:
            file_path.parent.mkdir(parents=True, exist_ok=True)

        # 追加或覆盖写入
        if append:
            # 追加模式
            with open(file_path, 'a', encoding=used_encoding) as f:
                f.write(content)
        else:
            # 覆盖模式
            file_path.write_text(content, encoding=used_encoding)
        
        result["bytes_written"] = len(content.encode(used_encoding))

        if verify_result:
            try:
                verify_content = file_path.read_text(encoding=used_encoding)
                if append:
                    # 追加模式：验证文件末尾是否包含追加的内容
                    if verify_content.endswith(content):
                        result["verification"] = "追加成功并已验证内容"
                    else:
                        result["verification"] = "追加成功但内容验证不一致"
                else:
                    # 覆盖模式：验证整个文件内容
                    if verify_content == content:
                        result["verification"] = "写入成功并已验证内容一致"
                    else:
                        result["verification"] = "写入成功但内容验证不一致"
            except Exception as e:
                result["verification"] = f"写入成功但验证失败: {e}"

        result["ok"] = True
        return result
    except Exception as exc:
        import traceback
        result["error"] = f"异常: {exc}\n详细信息: {traceback.format_exc()}"
        return result



def write_text(args: Dict[str, Any]) -> str:
    """处理 WriteText 工具调用，专门用于写入纯文本文件（基于 write_text_file 简化版）"""
    try:
        path = args.get("path")
        content = args.get("content")
        encoding = args.get("encoding")  # None 表示使用默认 utf-8
        append = args.get("append", False)  # 默认覆盖模式
        
        # 参数校验
        if not path:
            return json.dumps({"success": False, "error": "缺少参数: path"}, ensure_ascii=False)
        
        if content is None:
            return json.dumps({"success": False, "error": "缺少参数: content"}, ensure_ascii=False)
        
        # 文件后缀校验
        allowed_extensions = {'.txt', '.md', '.log', '.json', '.xml', '.yaml', '.yml', '.csv'}
        # 规范化路径:合并多余反斜杠并转换为正斜杠,避免转义字符问题
        file_path = Path(normalize_path_for_pathlib(path))
        file_extension = file_path.suffix.lower()
        
        if file_extension not in allowed_extensions:
            return json.dumps({
                "success": False,
                "error": f"不支持的文件格式: {file_extension}",
                "message": f"report_output 仅支持以下格式: {', '.join(sorted(allowed_extensions))}",
                "suggestion": "如需编写代码或其他复杂内容，请使用子 Agent 或其他专用工具"
            }, ensure_ascii=False)
        
        # 使用 Path 处理路径
        file_path = file_path.resolve()
        
        # 获取编码（使用参数或默认 utf-8）
        used_encoding = encoding or 'utf-8'
        
        # 确保父目录存在
        if file_path.parent:
            file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 写入文件
        if append:
            # 追加模式：读取原有内容再追加
            if file_path.exists():
                existing_content = file_path.read_text(encoding=used_encoding)
                new_content = existing_content + content
            else:
                new_content = content
            file_path.write_text(new_content, encoding=used_encoding)
        else:
            # 覆盖模式：直接写入
            file_path.write_text(content, encoding=used_encoding)
        
        # 计算字节数
        bytes_written = len(content.encode(used_encoding))
        
        return json.dumps({
            "success": True,
            "message": f"文件写入成功: {path}",
            "bytes_written": bytes_written,
            "encoding": used_encoding,
            "mode": "追加" if append else "覆盖"
        }, ensure_ascii=False)
            
    except PermissionError:
        return json.dumps({
            "success": False,
            "error": f"权限不足，无法写入文件: {path}"
        }, ensure_ascii=False)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": f"WriteText 执行异常: {str(e)}"
        }, ensure_ascii=False)




def delete_path(
    paths: list,
    *,
    verify_result: bool = True,
) -> Dict[str, Any]:
    """
    批量删除文件或文件夹（递归）
    
    Args:
        paths: 要删除的路径列表
        verify_result: 是否验证删除结果
        
    注意：
        - 命令行模式：通过input让用户输入y/n确认
        - Web模式：弹出确认对话框
    """
    # 确保 paths 是列表
    if isinstance(paths, str):
        paths = [paths]
    
    result: Dict[str, Any] = {
        "ok": False,
        "action": "delete",
        "paths": paths,
        "deleted": [],
        "failed": [],
        "error": None,
    }

    if not paths:
        result["error"] = "未提供要删除的路径"
        return result

    try:
        # 解析所有路径并检查存在性
        resolved_paths = []
        for p in paths:
            # 规范化路径:合并多余反斜杠并转换为正斜杠,避免转义字符问题
            file_path = Path(normalize_path_for_pathlib(p)).resolve()
            if file_path.exists():
                resolved_paths.append(file_path)
            else:
                result["failed"].append({"path": str(p), "error": "路径不存在"})
        
        if not resolved_paths:
            result["error"] = "所有路径都不存在"
            return result
        
        # 构建确认消息
        path_list_str = "\n".join(f"  - {p}" for p in resolved_paths)
        confirm_message = f"确定要删除以下 {len(resolved_paths)} 个路径吗？\n{path_list_str}"
        
        # 请求用户确认
        # 检查是否是桌面模式
        import os
        is_desktop_mode = os.environ.get('SPORE_DESKTOP_MODE') == '1'
        
        if is_desktop_mode:
            # 桌面模式：使用独立进程处理确认，不阻塞主进程 GIL
            from desktop_app.backend.confirm_manager import desktop_confirm
            confirmed = desktop_confirm(
                action_type="delete",
                title="批量删除确认",
                message=f"确定要删除以下 {len(resolved_paths)} 个路径吗？",
                details=[str(p) for p in resolved_paths]
            )
        else:
            # 命令行模式：使用input
            if current_agent_name == "Spore":
                # extra_line = 标题行(1) + 路径数量 + (y/n)行(1)
                terminal.extra_line += len(resolved_paths) + 2
            user_input = input(f"{confirm_message}\n(y/n) ")
            confirmed = user_input.lower() == "y"
        
        if not confirmed:
            result["error"] = "用户取消删除操作"
            return result
        
        # 执行删除
        import shutil
        for file_path in resolved_paths:
            try:
                if file_path.is_file():
                    file_path.unlink()
                elif file_path.is_dir():
                    shutil.rmtree(file_path)
                else:
                    result["failed"].append({"path": str(file_path), "error": "既不是文件也不是文件夹"})
                    continue
                
                # 验证删除结果
                if verify_result:
                    if file_path.exists():
                        result["failed"].append({"path": str(file_path), "error": "删除后验证失败"})
                        continue
                
                result["deleted"].append(str(file_path))
            except Exception as e:
                result["failed"].append({"path": str(file_path), "error": str(e)})
        
        # 设置最终状态
        if result["deleted"]:
            result["ok"] = True
            if result["failed"]:
                result["error"] = f"部分删除成功: {len(result['deleted'])} 成功, {len(result['failed'])} 失败"
        else:
            result["error"] = "所有删除操作都失败了"
        
        return result
    except Exception as exc:
        import traceback
        result["error"] = f"异常: {exc}\n详细信息: {traceback.format_exc()}"
        return result

import threading

# 全局文件修改标志字典，使用 agent_id 作为命名空间
# 结构: {agent_id: {file_path: modified_flag}}
_global_file_flags: Dict[str, Dict[str, bool]] = {}
_global_file_flags_lock = threading.Lock()

# 线程本地存储，用于存储当前线程的 agent_id
_thread_local = threading.local()


def set_current_agent_id(agent_id: str) -> None:
    """设置当前线程的 agent_id（用于文件修改标志的命名空间）"""
    _thread_local.agent_id = agent_id


def get_current_agent_id() -> Optional[str]:
    """获取当前线程的 agent_id"""
    return getattr(_thread_local, 'agent_id', None)


def _get_file_modified_flags() -> dict:
    """获取当前 agent 的文件修改标志字典"""
    agent_id = get_current_agent_id()
    if agent_id is None:
        # 如果没有设置 agent_id，使用线程 ID 作为后备方案
        agent_id = f"thread_{threading.current_thread().ident}"
    
    with _global_file_flags_lock:
        if agent_id not in _global_file_flags:
            _global_file_flags[agent_id] = {}
        return _global_file_flags[agent_id]


def _is_file_modified(file_path: str) -> bool:
    """
    检查文件是否被修改过或从未被读取
    
    返回True表示：
    1. 文件从未被Read过（不在字典中）
    2. 文件已被修改（在字典中且值为True）
    
    返回False表示：
    - 文件已被Read且未被修改（在字典中且值为False）
    """
    flags = _get_file_modified_flags()
    if file_path not in flags:
        # 文件从未被Read过
        return True
    return flags[file_path]


def _set_file_modified(file_path: str, modified: bool) -> None:
    """设置文件的修改状态"""
    flags = _get_file_modified_flags()
    flags[file_path] = modified


def clear_all_file_flags(agent_id: Optional[str] = None) -> None:
    """
    清空指定 agent 的所有文件修改标志
    
    Args:
        agent_id: Agent ID，如果为 None 则使用当前线程的 agent_id
    
    应该在以下时机调用：
    1. agent 完成任务时
    2. agent 被中断时
    """
    if agent_id is None:
        agent_id = get_current_agent_id()
        if agent_id is None:
            # 如果没有设置 agent_id，使用线程 ID 作为后备方案
            agent_id = f"thread_{threading.current_thread().ident}"
    
    with _global_file_flags_lock:
        if agent_id in _global_file_flags:
            _global_file_flags[agent_id].clear()
            del _global_file_flags[agent_id]


def read_text_file(
    file_path: str,
    *,
    offset: Optional[int] = None,
    limit: Optional[int] = None,
    encoding: Optional[str] = None,
    auto_detect_encoding: bool = True,
) -> Dict[str, Any]:
    """
    读取文本文件内容并按行输出，格式为 "行号<TAB>行内容"。

    - 默认从第 1 行开始读取，最多读取 2000 行。
    - 支持指定起始行 (offset，1-based) 和读取行数 (limit)。
    - 当行内容长度超过 2000 字符时会截断并在末尾追加省略号。
    """
    result: Dict[str, Any] = {
        "ok": False,
        "action": "read",
        "path": file_path,
        "error": None,
        "error_type": None,
        "error_code": None,
        "suggestions": None,
        "debug_info": None,
        "data": None,
        "total_lines": None,
        "bytes_written": None,
        "encoding_used": None,
        "lines_modified": None,
        "verification": None,
    }

    # 从配置获取默认值
    from ..config import get_config
    _config = get_config()
    DEFAULT_LIMIT = _config.file_read_default_limit
    MAX_LINE_LENGTH = _config.file_max_line_length

    try:
        # 规范化路径:合并多余反斜杠并转换为正斜杠,避免转义字符问题
        path = Path(normalize_path_for_pathlib(file_path)).resolve()
        resolved_path = str(path)  # 统一使用字符串路径，确保与 edit 函数一致
        
        if not path.exists():
            return _set_error(
                result,
                error_type="FILE_NOT_FOUND",
                error_code="E101",
                error_msg=f"文件不存在: {path}",
                suggestions=[
                    "确认文件路径是否正确",
                    "确保文件已创建",
                    "如果文件位于其他磁盘，请提供绝对路径",
                ],
            )

        if not path.is_file():
            return _set_error(
                result,
                error_type="NOT_A_FILE",
                error_code="E102",
                error_msg=f"路径不是文件: {path}",
                suggestions=[
                    "确认目标是文件而不是文件夹",
                    "如果需要列出目录，请使用系统命令",
                ],
            )

        used_encoding = _get_encoding(path, encoding, auto_detect_encoding)
        result["encoding_used"] = used_encoding

        content = _read_file_with_encoding(path, used_encoding, result)
        if content is None:
            return result

        lines = content.splitlines()
        total_lines = len(lines)
        result["total_lines"] = total_lines

        default_data = {
            "content": "",
            "lines_read": 0,
            "start_line": None,
            "end_line": None,
        }
        if total_lines == 0:
            result["ok"] = True
            result["data"] = default_data
            # 读取文件后，将该文件的修改标志设置为false（允许编辑）
            _set_file_modified(resolved_path, False)
            return result

        def _to_int(value: Optional[Any], name: str) -> Optional[int]:
            if value is None:
                return None
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                try:
                    return int(value.strip())
                except ValueError:
                    pass
            raise ValueError(f"{name} 需为整数")

        try:
            start_line = _to_int(offset, "offset") or 1
            limit_value = _to_int(limit, "limit")
        except ValueError as e:
            return _set_error(
                result,
                error_type="INVALID_ARGUMENT",
                error_code="E103",
                error_msg=str(e),
                suggestions=[
                    "offset 和 limit 需为正整数",
                    "如果不需要限制读取行数，可省略 limit",
                ],
            )

        if start_line < 1:
            return _set_error(
                result,
                error_type="INVALID_ARGUMENT",
                error_code="E104",
                error_msg=f"offset 需 >= 1，当前值: {start_line}",
                suggestions=[
                    "offset 表示起始行号（从 1 开始）",
                    "若需从文件开头读取，可省略 offset",
                ],
            )

        if limit_value is not None and limit_value <= 0:
            return _set_error(
                result,
                error_type="INVALID_ARGUMENT",
                error_code="E105",
                error_msg=f"limit 需 > 0，当前值: {limit_value}",
                suggestions=[
                    "limit 表示要读取的行数",
                    "若需读取默认行数，可省略 limit",
                ],
            )

        start_idx = start_line - 1
        if start_idx >= total_lines:
            return _set_error(
                result,
                error_type="RANGE_ERROR",
                error_code="E106",
                error_msg=f"offset 超出文件总行数 {total_lines}",
                suggestions=[
                    "检查 offset 是否正确",
                    "使用较小的 offset",
                    "先读取 total_lines 了解文件长度",
                ],
            )

        effective_limit = limit_value if limit_value is not None else DEFAULT_LIMIT
        end_idx = min(start_idx + effective_limit, total_lines)

        selected_lines = lines[start_idx:end_idx]

        def _format_line(idx: int, text: str) -> str:
            truncated = text
            if len(truncated) > MAX_LINE_LENGTH:
                truncated = truncated[:MAX_LINE_LENGTH] + "…"
            return f" {idx}\t{truncated}"

        formatted = [
            _format_line(start_line + i, line)
            for i, line in enumerate(selected_lines)
        ]

        start_line_value = start_line
        end_line_value = start_line + len(selected_lines) - 1
        data_payload = {
            "content": "\n".join(formatted),
            "lines_read": len(selected_lines),
            "start_line": start_line_value,
            "end_line": end_line_value,
        }
        result["debug_info"] = {
            "default_limit": DEFAULT_LIMIT,
            "limit_used": effective_limit,
        }
        result["ok"] = True
        result["data"] = data_payload
        # 读取文件后，将该文件的修改标志设置为false（允许编辑）
        _set_file_modified(resolved_path, False)
        return result
    except Exception as exc:
        import traceback
        result["error"] = f"异常: {exc}\n详细信息: {traceback.format_exc()}"
        return result


def edit_text_exact(
    file_path: str,
    *,
    old_string: str,
    new_string: str,
    replace_all: bool = False,
    encoding: Optional[str] = None,
    validate_syntax: bool = True,
    normalize_indent: bool = True,
) -> Dict[str, Any]:
    """
    精确字符串替换工具，要求在调用前通过 read_text_file 读取过目标文件。
    
    参数:
        file_path: 文件路径
        old_string: 要替换的旧字符串
        new_string: 替换后的新字符串
        replace_all: 是否替换所有匹配项
        encoding: 文件编码（None 表示使用默认 utf-8）
        validate_syntax: 是否验证语法（Python/C）
        normalize_indent: 是否自动标准化缩进（处理tab/空格混用）
    """
    result: Dict[str, Any] = {
        "ok": False,
        "action": "edit_exact",
        "path": file_path,
        "error": None,
        "error_type": None,
        "error_code": None,
        "suggestions": None,
        "debug_info": None,
        "data": None,
        "total_lines": None,
        "bytes_written": None,
        "encoding_used": None,
        "lines_modified": None,
        "verification": None,
    }

    # 检查文件是否被修改过
    # 规范化路径:合并多余反斜杠并转换为正斜杠,避免转义字符问题
    resolved_path = str(Path(normalize_path_for_pathlib(file_path)).resolve())
    if _is_file_modified(resolved_path):
        return _set_error(
            result,
            error_type="FILE_MODIFIED",
            error_code="E202",
            error_msg="文件已被修改，需要重新读取后才能继续编辑",
            suggestions=[
                "先调用 Read 工具重新读取文件内容，然后再次调用该工具",
            ],
        )

    if not old_string or old_string == new_string:
        return _set_error(
            result,
            error_type="INVALID_ARGUMENT",
            error_code="E201",
            error_msg="old_string 和 new_string 必须存在且不同",
            suggestions=[
                "确认 old_string 是否正确",
                "new_string 需与 old_string 不同",
            ],
        )

    try:
        path = Path(resolved_path)
        used_encoding = encoding or 'utf-8'
        result["encoding_used"] = used_encoding

        content = _read_file_with_encoding(path, used_encoding, result)
        if content is None:
            return result

        # 缩进标准化处理
        if normalize_indent:
            # 标准化文件内容和搜索字符串
            content_normalized = _normalize_indent(content, 'auto')
            old_string_normalized = _normalize_indent(old_string, 'auto')
            new_string_normalized = _normalize_indent(new_string, 'auto')
        else:
            content_normalized = content
            old_string_normalized = old_string
            new_string_normalized = new_string

        occurrences = content_normalized.count(old_string_normalized) if replace_all else (1 if old_string_normalized in content_normalized else 0)
        if occurrences == 0:
            return _set_error(
                result,
                error_type="STRING_NOT_FOUND",
                error_code="E203",
                error_msg="old_string 未在文件中找到",
                suggestions=[
                    "确认 old_string 与文件内容完全匹配",
                    "检查是否有缩进差异（tab vs 空格）",
                    "检查是否需要设置 replace_all",
                    "尝试设置 normalize_indent=true 自动处理缩进",
                ],
                debug_info={
                    "replace_all": replace_all,
                    "normalize_indent": normalize_indent,
                },
            )

        if not replace_all and occurrences > 1:
            return _set_error(
                result,
                error_type="NOT_UNIQUE",
                error_code="E204",
                error_msg="old_string 在文件中出现多次，若需全部替换请设置 replace_all=true",
                suggestions=[
                    "提供更具体的 old_string 或设置 replace_all",
                ],
                debug_info={"occurrences": occurrences},
            )

        # 执行替换
        new_content = content_normalized.replace(
            old_string_normalized, 
            new_string_normalized, 
            occurrences if replace_all else 1
        )
        
        # 语法验证
        if validate_syntax:
            file_ext = path.suffix.lower()
            is_valid = True
            error_msg = None
            
            if file_ext == '.py':
                is_valid, error_msg = _validate_python_syntax(new_content)
            elif file_ext in ['.c', '.h']:
                is_valid, error_msg = _validate_c_syntax(new_content, path)
            
            if not is_valid:
                return _set_error(
                    result,
                    error_type="SYNTAX_ERROR",
                    error_code="E205",
                    error_msg=f"修改后的代码存在语法错误: {error_msg}",
                    suggestions=[
                        "检查修改是否破坏了代码结构",
                        "确认括号、引号、分号等符号匹配",
                        "如果是误报，可设置 validate_syntax=false",
                    ],
                    debug_info={
                        "file_type": file_ext,
                        "validation_error": error_msg,
                    },
                )

        # 写入文件
        path.write_text(new_content, encoding=used_encoding)
        result["bytes_written"] = len(new_content.encode(used_encoding))
        sm = difflib.SequenceMatcher(None, content_normalized.splitlines(), new_content.splitlines())
        lines_modified = sum(
            (tag != 'equal') * (j2 - j1 if tag in ('replace', 'insert') else i2 - i1)
            for tag, i1, i2, j1, j2 in sm.get_opcodes()
        )
        result["lines_modified"] = lines_modified

        result["ok"] = True
        result["data"] = {
            "replacements": occurrences if replace_all else 1,
            "replace_all": replace_all,
        }

        try:
            verify_content = path.read_text(encoding=used_encoding)
            result["verification"] = "修改已应用并已验证" if verify_content == new_content else "修改已应用但验证不一致"
        except Exception as e:
            result["verification"] = f"修改已应用但验证失败: {e}"
        
        # 编辑成功后，将文件标记为已修改
        _set_file_modified(resolved_path, True)
        return result
    except Exception as exc:
        import traceback
        result["error"] = f"异常: {exc}\n详细信息: {traceback.format_exc()}"
        return result


def multi_edit_text(
    file_path: str,
    edits: List[Dict[str, Any]],
    *,
    encoding: Optional[str] = None,
    validate_syntax: bool = True,
    normalize_indent: bool = True,
) -> Dict[str, Any]:
    """
    批量精确字符串替换工具。所有替换按顺序应用，只要有一个失败则整体回滚。
    
    参数:
        file_path: 文件路径
        edits: 编辑操作列表
        encoding: 文件编码（None 表示使用默认 utf-8）
        validate_syntax: 是否验证语法（Python/C）
        normalize_indent: 是否自动标准化缩进（处理tab/空格混用）
    """
    result: Dict[str, Any] = {
        "ok": False,
        "action": "multi_edit",
        "path": file_path,
        "error": None,
        "error_type": None,
        "error_code": None,
        "suggestions": None,
        "debug_info": None,
        "data": None,
        "total_lines": None,
        "bytes_written": None,
        "encoding_used": None,
        "lines_modified": None,
        "verification": None,
    }

    # 检查文件是否被修改过
    # 规范化路径:合并多余反斜杠并转换为正斜杠,避免转义字符问题
    resolved_path = str(Path(normalize_path_for_pathlib(file_path)).resolve())
    if _is_file_modified(resolved_path):
        return _set_error(
            result,
            error_type="FILE_MODIFIED",
            error_code="E202",
            error_msg="文件已被修改，需要重新读取后才能继续编辑",
            suggestions=[
                "先调用 Read 工具重新读取文件内容，然后再次调用该工具",
            ],
        )

    if not isinstance(edits, list) or not edits:
        return _set_error(
            result,
            error_type="INVALID_ARGUMENT",
            error_code="E301",
            error_msg="edits 必须是非空列表",
            suggestions=[
                "提供至少一个编辑操作",
                "确认 edits 参数为数组",
            ],
        )

    try:
        path = Path(resolved_path)
        used_encoding = encoding or 'utf-8'
        result["encoding_used"] = used_encoding

        content = _read_file_with_encoding(path, used_encoding, result)
        if content is None:
            return result
        
        # 缩进标准化处理
        if normalize_indent:
            content = _normalize_indent(content, 'auto')
        
        # 保存标准化后的原始内容用于比较
        original_content = content
        
        total_replacements = 0

        for idx, edit in enumerate(edits, start=1):
            if not isinstance(edit, dict):
                return _set_error(
                    result,
                    error_type="INVALID_ARGUMENT",
                    error_code="E302",
                    error_msg=f"第 {idx} 个编辑不是对象",
                    suggestions=["确认每个 edit 都是对象"],
                )

            old_string = edit.get("old_string")
            new_string = edit.get("new_string")
            replace_all = bool(edit.get("replace_all", False))
            
            # 标准化编辑的字符串
            if normalize_indent:
                old_string = _normalize_indent(old_string, 'auto')
                new_string = _normalize_indent(new_string, 'auto')

            if not old_string or new_string is None:
                return _set_error(
                    result,
                    error_type="INVALID_ARGUMENT",
                    error_code="E303",
                    error_msg=f"第 {idx} 个编辑缺少 old_string 或 new_string",
                    suggestions=[
                        "提供完整的 old_string 和 new_string",
                        "确保 new_string 不为 None",
                    ],
                )

            if old_string == new_string:
                return _set_error(
                    result,
                    error_type="INVALID_ARGUMENT",
                    error_code="E304",
                    error_msg=f"第 {idx} 个编辑的 old_string 与 new_string 相同",
                    suggestions=[
                        "提供不同的替换内容",
                    ],
                )

            occurrences = content.count(old_string)
            if occurrences == 0:
                return _set_error(
                    result,
                    error_type="STRING_NOT_FOUND",
                    error_code="E305",
                    error_msg=f"第 {idx} 个编辑未找到 old_string",
                    suggestions=[
                        "确认 old_string 与文件内容完全匹配",
                        "注意空格和缩进需完全一致",
                        "检查是否有缩进差异（tab vs 空格）",
                        "尝试设置 normalize_indent=true 自动处理缩进",
                    ],
                    debug_info={
                        "edit_index": idx,
                        "replace_all": replace_all,
                        "normalize_indent": normalize_indent,
                        "old_string_preview": old_string[:80],
                    },
                )

            if not replace_all and occurrences > 1:
                return _set_error(
                    result,
                    error_type="NOT_UNIQUE",
                    error_code="E306",
                    error_msg=f"第 {idx} 个编辑的 old_string 在文件中出现多次，请设置 replace_all=true 或提供唯一内容",
                    suggestions=[
                        "提供更具体的 old_string",
                        "如需批量替换请设置 replace_all=true",
                    ],
                    debug_info={
                        "edit_index": idx,
                        "occurrences": occurrences,
                    },
                )

            replace_times = occurrences if replace_all else 1
            content = content.replace(old_string, new_string, replace_times)
            total_replacements += replace_times

        if content == original_content:
            return _set_error(
                result,
                error_type="NO_CHANGES",
                error_code="E307",
                error_msg="所有 edits 应用后内容无变化",
                suggestions=[
                    "检查 new_string 是否与原文本不同",
                    "确认 edits 顺序是否正确",
                ],
            )
        
        # 语法验证
        if validate_syntax:
            file_ext = path.suffix.lower()
            is_valid = True
            error_msg = None
            
            if file_ext == '.py':
                is_valid, error_msg = _validate_python_syntax(content)
            elif file_ext in ['.c', '.h']:
                is_valid, error_msg = _validate_c_syntax(content, path)
            
            if not is_valid:
                return _set_error(
                    result,
                    error_type="SYNTAX_ERROR",
                    error_code="E308",
                    error_msg=f"批量修改后的代码存在语法错误: {error_msg}",
                    suggestions=[
                        "检查批量修改是否破坏了代码结构",
                        "确认括号、引号、分号等符号匹配",
                        "逐个应用edits以定位问题",
                        "如果是误报，可设置 validate_syntax=false",
                    ],
                    debug_info={
                        "file_type": file_ext,
                        "validation_error": error_msg,
                        "edits_count": len(edits),
                    },
                )

        path.write_text(content, encoding=used_encoding)
        result["bytes_written"] = len(content.encode(used_encoding))
        sm = difflib.SequenceMatcher(None, original_content.splitlines(), content.splitlines())
        lines_modified = sum(
            (tag != 'equal') * (j2 - j1 if tag in ('replace', 'insert') else i2 - i1)
            for tag, i1, i2, j1, j2 in sm.get_opcodes()
        )
        result["lines_modified"] = lines_modified

        try:
            verify_content = path.read_text(encoding=used_encoding)
            result["verification"] = "修改已应用并已验证" if verify_content == content else "修改已应用但验证不一致"
        except Exception as e:
            result["verification"] = f"修改已应用但验证失败: {e}"

        result["ok"] = True
        result["data"] = {
            "edits_applied": len(edits),
            "total_replacements": total_replacements,
        }
        
        # 编辑成功后，将文件标记为已修改
        _set_file_modified(resolved_path, True)
        return result
    except Exception as exc:
        import traceback
        result["error"] = f"异常: {exc}\n详细信息: {traceback.format_exc()}"
        return result


def _detect_encoding(file_path: Path) -> str:
    """
    自动检测文件编码
    
    尝试顺序: utf-8 -> gbk -> gb2312 -> latin-1
    """
    encodings = ['utf-8', 'gbk', 'gb2312', 'latin-1', 'utf-16']
    
    for enc in encodings:
        try:
            with open(file_path, 'r', encoding=enc) as f:
                f.read()
            return enc
        except (UnicodeDecodeError, UnicodeError):
            continue
    
    # 默认返回 utf-8
    return 'utf-8'


def _validate_python_syntax(content: str) -> tuple[bool, Optional[str]]:
    """
    验证Python代码语法
    
    返回: (是否有效, 错误信息)
    """
    try:
        import ast
        ast.parse(content)
        return True, None
    except SyntaxError as e:
        return False, f"语法错误在第 {e.lineno} 行: {e.msg}"
    except Exception as e:
        return False, f"解析错误: {str(e)}"


def _validate_c_syntax(content: str, file_path: Path) -> tuple[bool, Optional[str]]:
    """
    验证C语言代码语法（使用gcc -fsyntax-only）
    
    返回: (是否有效, 错误信息)
    """
    import tempfile
    import subprocess
    
    try:
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False, encoding='utf-8') as f:
            temp_file = f.name
            f.write(content)
        
        # 运行gcc语法检查
        result = subprocess.run(
            ['gcc', '-fsyntax-only', temp_file],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # 清理临时文件
        try:
            Path(temp_file).unlink()
        except Exception as e:
            # 临时文件清理失败不影响主流程，但记录日志
            log_error("TEMP_FILE_CLEANUP_ERROR", f"Failed to cleanup temp file: {temp_file}", e)
        
        if result.returncode == 0:
            return True, None
        else:
            # 清理错误信息中的临时文件路径
            error_msg = result.stderr.replace(temp_file, str(file_path))
            return False, error_msg
    
    except FileNotFoundError:
        # gcc未安装，跳过验证
        return True, None
    except subprocess.TimeoutExpired:
        return False, "语法检查超时"
    except Exception as e:
        return False, f"语法检查异常: {str(e)}"


def _normalize_indent(text: str, target_indent: str = 'auto') -> str:
    """
    标准化文本缩进（tab <-> 空格转换）
    
    参数:
        text: 待处理文本
        target_indent: 目标缩进类型
            - 'auto': 自动检测主要缩进类型
            - 'space': 转换为空格（4个空格）
            - 'tab': 转换为制表符
    
    返回: 标准化后的文本
    """
    if not text:
        return text
    
    lines = text.split('\n')
    
    # 自动检测主要缩进类型
    if target_indent == 'auto':
        space_count = 0
        tab_count = 0
        
        for line in lines:
            if line.startswith('    '):  # 4个空格
                space_count += 1
            elif line.startswith('\t'):
                tab_count += 1
        
        # 使用多数类型
        target_indent = 'space' if space_count >= tab_count else 'tab'
    
    # 执行转换
    if target_indent == 'space':
        # Tab -> 4 空格
        normalized_lines = [line.replace('\t', '    ') for line in lines]
    elif target_indent == 'tab':
        # 4 空格 -> Tab
        normalized_lines = []
        for line in lines:
            # 替换行首的空格组（每4个空格替换为1个tab）
            leading_spaces = len(line) - len(line.lstrip(' '))
            tab_count = leading_spaces // 4
            remaining_spaces = leading_spaces % 4
            normalized_line = '\t' * tab_count + ' ' * remaining_spaces + line.lstrip(' ')
            normalized_lines.append(normalized_line)
    else:
        normalized_lines = lines
    
    return '\n'.join(normalized_lines)


def _read_file_with_encoding(file_path: Path, encoding: str, result: Dict[str, Any]) -> Optional[str]:
    """
    使用指定编码读取文件，失败时设置错误信息
    
    返回: 文件内容，失败返回None并设置result中的错误
    """
    try:
        return file_path.read_text(encoding=encoding)
    except UnicodeDecodeError as e:
        _set_error(
            result,
            error_type="ENCODING_ERROR",
            error_code="E003",
            error_msg=f"编码错误 ({encoding}): {str(e)[:100]}",
            suggestions=[
                "启用自动编码检测: auto_detect_encoding=true",
                "尝试其他编码: encoding=gbk 或 encoding=gb2312",
                "对于Windows文本文件，尝试 encoding=gbk",
                "对于UTF-8文件，确保文件确实是UTF-8编码",
                "使用文本编辑器查看文件的实际编码"
            ],
            debug_info={
                "tried_encoding": encoding,
                "file_size": file_path.stat().st_size
            }
        )
        return None


def _get_encoding(file_path: Path, encoding: Optional[str], auto_detect: bool) -> str:
    """
    获取文件编码（优化版：仅在需要时检测）
    
    优先级:
    1. 明确指定的encoding
    2. 自动检测（仅当文件存在且auto_detect=True）
    3. 默认utf-8
    """
    # 如果明确指定了编码，直接使用
    if encoding is not None:
        return encoding
    
    # 仅在需要自动检测时才检测
    if auto_detect and file_path.exists() and file_path.is_file():
        return _detect_encoding(file_path)
    
    # 默认编码
    return 'utf-8'


 
