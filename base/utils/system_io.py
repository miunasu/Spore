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
            # 追加模式：确保不会粘连（文件末尾无换行时自动补充）
            with open(file_path, 'a', encoding=used_encoding) as f:
                # 检查文件末尾是否有换行符
                if file_path.exists() and file_path.stat().st_size > 0:
                    with open(file_path, 'rb') as check_f:
                        check_f.seek(-1, 2)  # 定位到最后一个字节
                        last_byte = check_f.read(1)
                        if last_byte not in (b'\n', b'\r') and not content.startswith('\n'):
                            f.write('\n')
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
        - 拦截开关启用时：需要用户确认（命令行模式通过input，Web模式弹窗）
        - 拦截开关关闭时：直接删除，不需要确认
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

        # 检查是否需要用户确认
        from ..config import get_config
        _cfg = get_config()
        need_confirmation = _cfg.is_intercept_enabled("file_delete")

        if need_confirmation:
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
    精确字符串替换工具。
    
    参数:
        file_path: 文件路径
        old_string: 要替换的旧字符串
        new_string: 替换后的新字符串
        replace_all: 是否替换所有匹配项
        encoding: 文件编码（None 表示使用默认 utf-8）
        validate_syntax: 是否验证语法（Python/C）
        normalize_indent: 精确匹配失败时是否启用缩进容错匹配
            （自动兜底 tab/空格缩进差异、行尾空白差异，只替换匹配块，不改动文件其他部分）
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

    # 规范化路径:合并多余反斜杠并转换为正斜杠,避免转义字符问题
    resolved_path = str(Path(normalize_path_for_pathlib(file_path)).resolve())

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

        # 匹配策略：先精确匹配；失败且 normalize_indent 开启时启用缩进容错匹配
        # （兜底 tab/空格缩进差异、行尾空白差异），只替换匹配到的文本块，不改动文件其他部分
        match_strategy = "exact"
        flex_matches: List[str] = []
        occurrences = content.count(old_string)

        if occurrences == 0 and normalize_indent:
            flex_matches = _find_flexible_matches(content, old_string)
            if flex_matches:
                match_strategy = "indent_tolerant"
                occurrences = len(flex_matches)

        if occurrences == 0:
            return _set_error(
                result,
                error_type="STRING_NOT_FOUND",
                error_code="E203",
                error_msg="old_string 未在文件中找到（已尝试缩进容错匹配）" if normalize_indent else "old_string 未在文件中找到",
                suggestions=[
                    "确认 old_string 与文件内容完全匹配（可先 read 该区域核对）",
                    "old_string 的行内容可能与文件不一致（缩进差异已自动容错，无需担心 tab/空格）",
                    "若仍无法匹配，可改用 type=line 按行号编辑",
                ],
                debug_info={
                    "replace_all": replace_all,
                    "normalize_indent": normalize_indent,
                    "first_line_found_at_lines": _locate_first_line_hint(content, old_string),
                },
            )

        if not replace_all and occurrences > 1:
            return _set_error(
                result,
                error_type="NOT_UNIQUE",
                error_code="E204",
                error_msg="old_string 在文件中出现多次，若需全部替换请设置 replace_all=true",
                suggestions=[
                    "提供更具体的 old_string（增加上下文行）或设置 replace_all",
                ],
                debug_info={"occurrences": occurrences, "match_strategy": match_strategy},
            )

        # 执行替换
        if match_strategy == "exact":
            new_content = content.replace(
                old_string,
                new_string,
                occurrences if replace_all else 1,
            )
        else:
            # 容错匹配：替换文件中实际存在的原文块，
            # 并将 new_string 的缩进适配为该文本块的实际缩进风格
            new_content = content
            blocks = list(dict.fromkeys(flex_matches)) if replace_all else [flex_matches[0]]
            for block in blocks:
                adapted_new = _normalize_indent(
                    new_string, _detect_block_indent_style(block, content)
                )
                new_content = new_content.replace(
                    block, adapted_new, -1 if replace_all else 1
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

        # 换行完整性检查（仅 .py）——在写入前拦截 CONTENT 块传输时丢失 \n 的情况
        if validate_syntax:
            merge_check = _check_merged_lines(new_string, path.suffix.lower())
            if merge_check is not None:
                merge_msg, merge_suspects = merge_check
                return _set_error(
                    result,
                    error_type="NEWLINE_MISMATCH",
                    error_code="E206",
                    error_msg=f"new_string 中检测到疑似换行符丢失，未写入。{merge_msg}",
                    suggestions=[
                        "重新生成此 edit，在 CONTENT 块中确保每个 except/elif/else/finally 独占一行",
                        "检查 CONTENT 块内容，不要把两行代码写到同一行",
                        "若确认内容正确（如关键字出现在字符串内），可设置 validate_syntax=false 跳过此检查",
                    ],
                    debug_info={
                        "suspicious_line_count": len(merge_suspects),
                        "suspicious_lines": [
                            {"lineno": ln, "text": txt} for ln, txt in merge_suspects[:10]
                        ],
                        "new_string_line_count": len(new_string.splitlines()),
                    },
                )

        # 写入文件
        path.write_text(new_content, encoding=used_encoding)
        result["bytes_written"] = len(new_content.encode(used_encoding))
        sm = difflib.SequenceMatcher(None, content.splitlines(), new_content.splitlines())
        lines_modified = sum(
            (tag != 'equal') * (j2 - j1 if tag in ('replace', 'insert') else i2 - i1)
            for tag, i1, i2, j1, j2 in sm.get_opcodes()
        )
        result["lines_modified"] = lines_modified

        result["ok"] = True
        result["data"] = {
            "replacements": occurrences if replace_all else 1,
            "replace_all": replace_all,
            "match_strategy": match_strategy,
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
        normalize_indent: 精确匹配失败时是否启用缩进容错匹配
            （自动兜底 tab/空格缩进差异、行尾空白差异，只替换匹配块，不改动文件其他部分）
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

    # 规范化路径:合并多余反斜杠并转换为正斜杠,避免转义字符问题
    resolved_path = str(Path(normalize_path_for_pathlib(file_path)).resolve())

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

        # 保存原始内容用于比较（不做任何全文件缩进重写，保持文件原有风格）
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

            # 换行完整性检查（仅 .py）——在应用替换前拦截行合并问题
            if validate_syntax:
                merge_check = _check_merged_lines(new_string, path.suffix.lower())
                if merge_check is not None:
                    merge_msg, merge_suspects = merge_check
                    return _set_error(
                        result,
                        error_type="NEWLINE_MISMATCH",
                        error_code="E309",
                        error_msg=f"第 {idx} 个编辑的 new_string 中检测到疑似换行符丢失，未写入。{merge_msg}",
                        suggestions=[
                            "重新生成此 edit，在 CONTENT 块中确保每个 except/elif/else/finally 独占一行",
                            "检查 CONTENT 块内容，不要把两行代码写到同一行",
                            "若确认内容正确，可设置 validate_syntax=false 跳过此检查",
                        ],
                        debug_info={
                            "edit_index": idx,
                            "suspicious_line_count": len(merge_suspects),
                            "suspicious_lines": [
                                {"lineno": ln, "text": txt} for ln, txt in merge_suspects[:10]
                            ],
                            "new_string_line_count": len(new_string.splitlines()),
                        },
                    )

            # 匹配策略：先精确匹配；失败且 normalize_indent 开启时启用缩进容错匹配
            match_strategy = "exact"
            flex_matches: List[str] = []
            occurrences = content.count(old_string)

            if occurrences == 0 and normalize_indent:
                flex_matches = _find_flexible_matches(content, old_string)
                if flex_matches:
                    match_strategy = "indent_tolerant"
                    occurrences = len(flex_matches)

            if occurrences == 0:
                return _set_error(
                    result,
                    error_type="STRING_NOT_FOUND",
                    error_code="E305",
                    error_msg=f"第 {idx} 个编辑未找到 old_string（已尝试缩进容错匹配）" if normalize_indent else f"第 {idx} 个编辑未找到 old_string",
                    suggestions=[
                        "确认 old_string 与文件内容完全匹配（可先 read 该区域核对）",
                        "缩进差异（tab/空格）已自动容错，请检查行内容本身是否一致",
                        "注意 edits 按顺序应用，前面的编辑可能已改变了本编辑要匹配的内容",
                        "若仍无法匹配，可改用 type=line 按行号编辑",
                    ],
                    debug_info={
                        "edit_index": idx,
                        "replace_all": replace_all,
                        "normalize_indent": normalize_indent,
                        "old_string_preview": old_string[:80],
                        "first_line_found_at_lines": _locate_first_line_hint(content, old_string),
                    },
                )

            if not replace_all and occurrences > 1:
                return _set_error(
                    result,
                    error_type="NOT_UNIQUE",
                    error_code="E306",
                    error_msg=f"第 {idx} 个编辑的 old_string 在文件中出现多次，请设置 replace_all=true 或提供唯一内容",
                    suggestions=[
                        "提供更具体的 old_string（增加上下文行）",
                        "如需批量替换请设置 replace_all=true",
                    ],
                    debug_info={
                        "edit_index": idx,
                        "occurrences": occurrences,
                        "match_strategy": match_strategy,
                    },
                )

            if match_strategy == "exact":
                replace_times = occurrences if replace_all else 1
                content = content.replace(old_string, new_string, replace_times)
            else:
                # 容错匹配：替换文件中实际存在的原文块，
                # 并将 new_string 的缩进适配为该文本块的实际缩进风格
                blocks = list(dict.fromkeys(flex_matches)) if replace_all else [flex_matches[0]]
                for block in blocks:
                    adapted_new = _normalize_indent(
                        new_string, _detect_block_indent_style(block, content)
                    )
                    content = content.replace(block, adapted_new, -1 if replace_all else 1)
            total_replacements += occurrences if replace_all else 1

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


def edit_text_lines(
    file_path: str,
    *,
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
    mode: str = "replace",
    content: Optional[str] = None,
    encoding: Optional[str] = None,
    validate_syntax: bool = True,
) -> Dict[str, Any]:
    """
    按行号编辑文件。适用于字符串匹配困难的场景（如大量重复内容、特殊字符）。

    参数:
        file_path: 文件路径
        start_line: 起始行号（1-based，与 read 输出的行号一致，必需）
        end_line: 结束行号（含），默认等于 start_line
        mode: 编辑模式
            - replace: 用 content 替换 start_line~end_line 的行
            - insert_before: 在 start_line 之前插入 content
            - insert_after: 在 start_line 之后插入 content
            - delete: 删除 start_line~end_line 的行（无需 content）
        content: 新内容（可多行；delete 模式外必需）
        encoding: 文件编码（None 表示使用默认 utf-8）
        validate_syntax: 是否验证语法（Python/C）

    注意: 编辑后行号会变化，后续行号编辑前建议重新 read。
    """
    result: Dict[str, Any] = {
        "ok": False,
        "action": "edit_lines",
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
        "warning": None,
    }

    # 规范化路径:合并多余反斜杠并转换为正斜杠,避免转义字符问题
    resolved_path = str(Path(normalize_path_for_pathlib(file_path)).resolve())

    valid_modes = ("replace", "insert_before", "insert_after", "delete")
    if mode not in valid_modes:
        return _set_error(
            result,
            error_type="INVALID_ARGUMENT",
            error_code="E401",
            error_msg=f"无效的 mode: {mode}",
            suggestions=[f"mode 需为以下之一: {', '.join(valid_modes)}"],
        )

    def _to_int(value: Any, name: str) -> Optional[int]:
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
        start = _to_int(start_line, "start_line")
        end = _to_int(end_line, "end_line")
    except ValueError as e:
        return _set_error(
            result,
            error_type="INVALID_ARGUMENT",
            error_code="E402",
            error_msg=str(e),
            suggestions=["start_line 和 end_line 需为正整数（1-based）"],
        )

    if start is None or start < 1:
        return _set_error(
            result,
            error_type="INVALID_ARGUMENT",
            error_code="E402",
            error_msg=f"start_line 必须提供且 >= 1，当前值: {start}",
            suggestions=["start_line 表示起始行号（从 1 开始，与 read 输出一致）"],
        )

    end = end if end is not None else start
    if end < start:
        return _set_error(
            result,
            error_type="INVALID_ARGUMENT",
            error_code="E402",
            error_msg=f"end_line ({end}) 不能小于 start_line ({start})",
            suggestions=["end_line 表示结束行号（含），需 >= start_line"],
        )

    if mode != "delete" and content is None:
        return _set_error(
            result,
            error_type="INVALID_ARGUMENT",
            error_code="E403",
            error_msg=f"{mode} 模式需要提供 content（新内容）",
            suggestions=["提供 content 参数；仅 delete 模式可省略"],
        )

    try:
        path = Path(resolved_path)
        used_encoding = encoding or 'utf-8'
        result["encoding_used"] = used_encoding

        if not path.exists() or not path.is_file():
            return _set_error(
                result,
                error_type="FILE_NOT_FOUND",
                error_code="E404",
                error_msg=f"文件不存在: {path}",
                suggestions=["确认文件路径是否正确"],
            )

        file_content = _read_file_with_encoding(path, used_encoding, result)
        if file_content is None:
            return result

        had_trailing_newline = file_content.endswith('\n')
        lines = file_content.split('\n')
        if had_trailing_newline:
            lines.pop()  # 去掉 split 产生的末尾空元素
        if file_content == '':
            lines = []
        total_lines = len(lines)

        # 行号范围校验（insert_before 允许 total_lines+1 表示追加到末尾）
        max_start = total_lines + 1 if mode == "insert_before" else total_lines
        if start > max_start or (mode in ("replace", "delete") and end > total_lines):
            return _set_error(
                result,
                error_type="RANGE_ERROR",
                error_code="E405",
                error_msg=f"行号超出范围: start_line={start}, end_line={end}, 文件共 {total_lines} 行",
                suggestions=[
                    "先 read 文件确认行号",
                    "insert_before 模式的 start_line 最大可为 总行数+1（追加到末尾）",
                ],
                debug_info={"total_lines": total_lines, "mode": mode},
            )

        # 换行完整性检查（仅 .py）——在写入前拦截 CONTENT 块传输时丢失 \n 的情况
        if validate_syntax and mode != "delete" and content:
            merge_check = _check_merged_lines(content, path.suffix.lower())
            if merge_check is not None:
                merge_msg, merge_suspects = merge_check
                return _set_error(
                    result,
                    error_type="NEWLINE_MISMATCH",
                    error_code="E408",
                    error_msg=f"content 中检测到疑似换行符丢失（未写入）。{merge_msg}",
                    suggestions=[
                        "重新生成此 edit，在 CONTENT 块中确保每个 except/elif/else/finally 独占一行",
                        "检查 CONTENT 块内容，不要把两行代码写到同一行",
                        "若确认内容正确（如关键字出现在字符串内），可设置 validate_syntax=false 跳过此检查",
                    ],
                    debug_info={
                        "suspicious_line_count": len(merge_suspects),
                        "suspicious_lines": [
                            {"lineno": ln, "text": txt} for ln, txt in merge_suspects[:10]
                        ],
                        "content_line_count": len(content.splitlines()),
                    },
                )

        # 准备新内容行（去掉一个末尾换行符，避免意外引入空行）
        new_lines: List[str] = []
        if mode != "delete":
            text = content[:-1] if content.endswith('\n') else content
            new_lines = text.split('\n')

        # 应用编辑
        old_slice: List[str] = []
        if mode == "replace":
            old_slice = lines[start - 1:end]
            lines[start - 1:end] = new_lines
            new_region_start = start
        elif mode == "insert_before":
            lines[start - 1:start - 1] = new_lines
            new_region_start = start
        elif mode == "insert_after":
            lines[start:start] = new_lines
            new_region_start = start + 1
        else:  # delete
            old_slice = lines[start - 1:end]
            del lines[start - 1:end]
            new_region_start = start

        new_content = '\n'.join(lines)
        if had_trailing_newline and lines:
            new_content += '\n'

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
                    error_code="E406",
                    error_msg=f"修改后的代码存在语法错误（未写入）: {error_msg}",
                    suggestions=[
                        "检查新内容的缩进是否与上下文一致",
                        "确认行号范围是否正确（是否多删/少删了行）",
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
        result["total_lines"] = len(lines)
        result["lines_modified"] = max(len(old_slice), len(new_lines))

        def _preview(preview_lines: List[str], first_no: int, cap: int = 20) -> str:
            shown = preview_lines[:cap]
            text = '\n'.join(f" {first_no + i}\t{l}" for i, l in enumerate(shown))
            if len(preview_lines) > cap:
                text += f"\n ...（共 {len(preview_lines)} 行，已截断）"
            return text

        result["data"] = {
            "mode": mode,
            "start_line": start,
            "end_line": end,
            "lines_removed": len(old_slice),
            "lines_inserted": len(new_lines),
            "old_content_preview": _preview(old_slice, start) if old_slice else "",
            "new_content_preview": _preview(new_lines, new_region_start) if new_lines else "",
        }

        # 行号编辑依赖最新的行号信息：若文件在上次 read 后已被修改（或从未 read），给出提醒
        if _is_file_modified(resolved_path):
            result["warning"] = "该文件自上次 read 后已被修改或从未 read，行号可能不准确，建议 read 核对结果"

        try:
            verify_content = path.read_text(encoding=used_encoding)
            result["verification"] = "修改已应用并已验证" if verify_content == new_content else "修改已应用但验证不一致"
        except Exception as e:
            result["verification"] = f"修改已应用但验证失败: {e}"

        result["ok"] = True
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


# Python 子句关键字——它们必须位于语句行首（允许前置空白）。
# 若出现在同行非首位的非空白字符之后，几乎可以确定是 CONTENT 块
# 传输时 \n token 丢失导致相邻行被拼在了一起。
_PY_CLAUSE_KW = (
    'except ',   # except Exception as e:
    'except:',   # bare except:
    'elif ',     # elif condition:
    'else:',     # else: 子句（有冒号；三元 'else ' 不在检测范围）
    'finally:',  # finally:
)


def _check_merged_lines(
    text: str,
    file_ext: str,
) -> Optional[tuple[str, list]]:
    """检测 new_string 中是否存在换行符丢失导致的行合并。

    专为 CONTENT 块传输时模型偶发的 \\n token 丢失而设计。
    仅对 .py 文件启用：检查是否有 except / elif / else: / finally: 等
    必须位于行首的子句关键字出现在行中非首位的非空白字符之后。

    返回:
        None             — 未发现问题
        (msg, suspects)  — (问题描述, [(lineno, line_text), ...])

    注意：对包含这些关键字作为字符串字面量内容的行存在极低概率误报，
    可通过 validate_syntax=false 绕过。
    """
    if file_ext != '.py':
        return None

    all_lines = text.splitlines()
    suspects: list[tuple[int, str]] = []

    for lineno, line in enumerate(all_lines, 1):
        for kw in _PY_CLAUSE_KW:
            idx = line.find(kw)
            if idx < 0:
                continue
            before = line[:idx]
            if not before.lstrip():
                continue  # 关键字位于行首（允许缩进空白）
            # 粗略排除注释行：# 出现在关键字之前
            comment_pos = line.find('#')
            if 0 <= comment_pos < idx:
                continue
            suspects.append((lineno, line))
            break  # 一行只需报一次

    if not suspects:
        return None

    # 生成带上下文的可读描述
    ctx_blocks: list[str] = []
    for lineno, line in suspects[:5]:
        parts: list[str] = []
        if lineno > 1:
            parts.append(f"  {lineno - 1:>4}: {all_lines[lineno - 2]}")
        parts.append(f">>>{lineno:>4}: {line}  ← 疑似行合并")
        if lineno < len(all_lines):
            parts.append(f"  {lineno + 1:>4}: {all_lines[lineno]}")
        ctx_blocks.append("\n".join(parts))

    more = f"（另有 {len(suspects) - 5} 处）" if len(suspects) > 5 else ""
    msg = (
        f"new_string 中检测到 {len(suspects)} 处疑似换行符丢失"
        f"（CONTENT 块传输问题）{more}，"
        f"以下行包含必须位于行首的 Python 子句关键字：\n\n" +
        "\n\n".join(ctx_blocks)
    )
    return msg, suspects


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
        # Windows 创建标志：防止终端闪屏
        creation_flags = 0
        if os.name == "nt":
            creation_flags = 0x08000000 | subprocess.CREATE_NEW_PROCESS_GROUP
        
        result = subprocess.run(
            ['gcc', '-fsyntax-only', temp_file],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=creation_flags,
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


def _normalize_line_for_match(line: str) -> str:
    """
    将单行标准化用于容错匹配：
    - 行首缩进中的 tab 展开为 4 空格（消除 tab/空格缩进差异）
    - 去除行尾空白（消除行尾空格/tab 差异）
    行内容本身保持不变。
    """
    stripped = line.lstrip(' \t')
    leading = line[:len(line) - len(stripped)]
    return leading.replace('\t', '    ') + stripped.rstrip()


def _detect_block_indent_style(block: str, fallback_text: str = "") -> str:
    """
    检测文本块的缩进风格，返回 'tab' 或 'space'。
    块内没有缩进行时回退到 fallback_text（通常传整个文件内容），默认 'space'。
    """
    for text in (block, fallback_text):
        if not text:
            continue
        for line in text.split('\n'):
            ws = line[:len(line) - len(line.lstrip(' \t'))]
            if '\t' in ws:
                return 'tab'
            if ws.startswith('    '):
                return 'space'
    return 'space'


def _find_flexible_matches(content: str, old_string: str) -> List[str]:
    """
    缩进容错匹配（精确匹配失败时的兜底）。

    常见失败原因是 old_string 使用 tab 缩进而文件实际使用空格缩进（或反之），
    以及行尾空白差异。此函数按行滑动窗口，比较标准化后的行内容
    （行首 tab 展开为 4 空格 + 去除行尾空白），找到匹配窗口后返回
    文件中【实际存在的原文块】列表——调用方可直接对原文块做精确替换，
    完全不改动文件的其他部分。

    返回: 匹配到的原文块列表（每个窗口一项，可能包含重复文本）
    """
    content_lines = content.split('\n')
    old_lines = old_string.split('\n')
    n = len(old_lines)
    if n == 0 or n > len(content_lines):
        return []

    norm_old = [_normalize_line_for_match(l) for l in old_lines]
    norm_content = [_normalize_line_for_match(l) for l in content_lines]

    matches: List[str] = []
    for i in range(len(content_lines) - n + 1):
        if norm_content[i:i + n] == norm_old:
            matches.append('\n'.join(content_lines[i:i + n]))
    return matches


def _locate_first_line_hint(content: str, old_string: str, max_hits: int = 5) -> List[int]:
    """
    匹配失败时的调试辅助：在文件中查找 old_string 首个非空行（strip 后比较）
    出现的行号（1-based），帮助 agent 定位应该编辑的位置。
    """
    first_line = ""
    for l in old_string.split('\n'):
        if l.strip():
            first_line = l.strip()
            break
    if not first_line:
        return []
    hits = [
        i + 1
        for i, line in enumerate(content.split('\n'))
        if line.strip() == first_line
    ]
    return hits[:max_hits]


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


 
