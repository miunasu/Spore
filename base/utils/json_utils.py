import json
import re
from typing import Optional, Dict, Any, Tuple
from ..logger import log_llm_validation_error, log_tool_error, log_info


def _tool_result_log_context(tool_result: Any) -> Dict[str, Any]:
    context: Dict[str, Any] = {"result": tool_result}
    if isinstance(tool_result, str):
        context["result_length"] = len(tool_result)
    return context


def _text_tail(text: str, limit: int = 2000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def _is_powershell_progress_noise(stderr: str) -> bool:
    stripped = stderr.strip()
    return (
        stripped.startswith("#< CLIXML")
        and '<Obj S="progress"' in stripped
        and '<S S="Error">' not in stripped
    )


def _format_execute_command_error(result_data: Dict[str, Any]) -> str:
    returncode = result_data.get("returncode")
    stderr = result_data.get("stderr") or ""
    stdout = result_data.get("stdout") or ""
    hints = result_data.get("hints") or []

    if stderr and not _is_powershell_progress_noise(stderr):
        message = stderr
    else:
        message = (
            result_data.get("error")
            or result_data.get("message")
            or f"Command execution failed (exit code {returncode})"
        )
        if stdout:
            message = f"{message}\nstdout tail:\n{_text_tail(stdout)}"

    if hints:
        if isinstance(hints, list):
            hint_text = "\n".join(str(hint) for hint in hints)
        else:
            hint_text = str(hints)
        message = f"{message}\nHint:\n{hint_text}"

    return message


def _strip_think_tags(text: str) -> str:
    """
    移除文本中的 <think>...</think> 标签及其内容。
    某些 API 代理会在响应中添加思考过程。
    """
    # 移除 <think>...</think> 标签（支持多行，非贪婪匹配）
    return re.sub(r'<think>.*?</think>\s*', '', text, flags=re.DOTALL)


def parse_json_object(text: str) -> Optional[Dict]:
    """
    尝试从文本中解析出 JSON 对象（dict），使用与 json_query 相同的解析策略。
    1) 先移除 <think>...</think> 标签
    2) 尝试整体解析
    3) 失败则去掉 ``` 包裹或提取第一个完整的 {...} 片段解析
    
    返回:
        解析成功返回 dict 对象；失败返回 None
    """
    if not text:
        return None
    
    # 移除 <think>...</think> 标签
    text = _strip_think_tags(text)
    
    # 直接整体解析
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError as e:
        pass
    except Exception:
        pass
    
    # 去除代码块围栏 (```json ... ``` 或 ``` ... ```)
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            # 找到开始行：跳过第一行的 ```json 或 ```
            start_line = 1
            # 找到结束行：跳过最后一行的 ```
            end_line = len(lines) - 1
            
            # 提取中间的内容
            inner = "\n".join(lines[start_line:end_line]).strip()
            
            # 尝试解析提取的内容
            try:
                obj = json.loads(inner)
                if isinstance(obj, dict):
                    return obj
            except Exception:
                # 如果还是失败，继续尝试后续方法
                pass
    
    # 提取第一个完整的 JSON 对象（匹配括号对）
    try:
        # 找到第一个 {
        start_idx = text.find('{')
        if start_idx == -1:
            return None
        
        # 从第一个 { 开始，匹配括号对找到对应的 }
        bracket_count = 0
        in_string = False
        escape_next = False
        
        for i in range(start_idx, len(text)):
            char = text[i]
            
            # 处理字符串内的字符（忽略字符串内的括号）
            if escape_next:
                escape_next = False
                continue
            
            if char == '\\':
                escape_next = True
                continue
            
            if char == '"':
                in_string = not in_string
                continue
            
            if in_string:
                continue
            
            # 不在字符串内时，计数括号
            if char == '{':
                bracket_count += 1
            elif char == '}':
                bracket_count -= 1
                
                # 找到匹配的右括号
                if bracket_count == 0:
                    json_str = text[start_idx:i+1]
                    try:
                        obj = json.loads(json_str)
                        if isinstance(obj, dict):
                            return obj
                    except Exception:
                        pass
                    break
    except Exception:
        pass
    
    return None


def json_query(text: str, key: str) -> Optional[str]:
    """
    从模型文本中提取 JSON 的指定字段。
    1) 先尝试整体解析
    2) 失败则去掉 ``` 包裹或提取第一个 {...} 片段解析
    3) 若字段值不是字符串，则返回其 JSON 字符串
    """
    obj = parse_json_object(text)
    if obj and key in obj:
        val = obj[key]
        return val if isinstance(val, str) else json.dumps(val, ensure_ascii=False)
    
    if key != "reply" and key != "Status" and key != "summary":
        print(f"未能找到json元素:{key}\n完整json:{text}")
    return None


def validate_json_response(
    response: str,
    messages: list,
    agent_name: Optional[str] = None,
    error_message: Optional[str] = None
) -> tuple[Optional[Dict], bool]:
    """
    统一的JSON响应验证器，处理LLM响应的JSON解析和错误处理。
    
    参数:
        response: LLM的响应文本
        messages: 消息列表，如果验证失败会自动添加错误消息
        agent_name: 代理名称（用于日志前缀，可选）
        error_message: 自定义错误消息（可选），默认使用标准提示
    
    返回:
        (parsed_json, is_valid): 元组，包含解析后的JSON对象和验证是否成功的标志
        - parsed_json: 成功时返回Dict，失败时返回None
        - is_valid: True表示验证成功，False表示失败
    """
    parsed_json = parse_json_object(response)
    
    # 总是先添加 LLM 的回复到对话历史
    messages.append({
        "role": "assistant",
        "content": response
    })
    
    if parsed_json is None:
        # JSON解析失败 - 必定记录日志
        log_llm_validation_error(
            "INVALID_JSON",
            f"{'[' + agent_name + '] ' if agent_name else ''}LLM response is not valid JSON format",
            llm_response=response,
            expected_format="Valid JSON object with 'Status' and 'reply' fields"
        )
        
        # 添加错误消息（使用自定义或标准消息）
        if error_message is None:
            error_message = "发送的信息不是完整json格式，请保证发送的信息是json格式"
        
        messages.append({
            "role": "user",
            "content": error_message
        })
        
        return None, False
    
    return parsed_json, True


def check_tool_result_error(tool_result: str) -> Tuple[bool, Optional[str]]:
    """
    检查工具返回结果是否包含错误
    
    工具可能返回 JSON 格式的错误响应而不是抛出异常，例如：
    - {"success": false, "error": "..."}
    - {"Status": "Error", "error": "..."}
    - {"ok": false, "error": "..."}
    
    Args:
        tool_result: 工具返回的结果字符串
        
    Returns:
        (is_error, error_msg): 元组
        - is_error: True 表示检测到错误
        - error_msg: 错误消息，如果没有错误则为 None
    """
    if not isinstance(tool_result, str):
        return False, None
    
    try:
        result_data = json.loads(tool_result)
        
        if not isinstance(result_data, dict):
            return False, None
        
        # 检查 success: false 格式
        if result_data.get("success") is False:
            error_msg = result_data.get("error") or result_data.get("message") or "未知错误"
            return True, error_msg
        
        # 检查 Status: Error 格式
        if result_data.get("Status") == "Error":
            error_msg = result_data.get("error") or result_data.get("message") or "未知错误"
            return True, error_msg
        
        # 检查 ok: false 格式（execute_command 使用此格式）
        if result_data.get("ok") is False:
            # execute_command 特殊处理：returncode=1 且无 stderr 可能只是"无匹配结果"
            # 例如 findstr/grep 找不到匹配时返回 1，这不是真正的错误
            returncode = result_data.get("returncode")
            stderr = result_data.get("stderr", "")
            stdout = result_data.get("stdout", "")
            
            # 如果 returncode=1 且没有 stderr，可能是搜索类命令无结果，不算错误
            if returncode == 1 and not stderr and not stdout:
                return False, None
            
            # Build an actionable command error without losing stdout context.
            error_msg = _format_execute_command_error(result_data)
            return True, error_msg
        
        return False, None
        
    except (json.JSONDecodeError, TypeError, AttributeError):
        return False, None


def _extract_tool_action(tool_name: str, args: Dict[str, Any]) -> str:
    """
    从工具参数中提取具体操作，生成更有意义的日志描述
    统一格式：工具名 子操作 关键参数

    Args:
        tool_name: 工具名称
        args: 工具参数字典

    Returns:
        格式化的工具操作描述，例如 "file read config.json" 或 "edit single target.txt"
    """
    try:
        # args 可能是字符串格式的 JSON，需要先解析
        if isinstance(args, str):
            args_dict = json.loads(args)
        elif isinstance(args, dict):
            args_dict = args
        else:
            return tool_name

        import os

        # file 工具：file <type> <file_path>
        # type: read/write/delete
        if tool_name == "file":
            operation = args_dict.get("type", "unknown")
            file_path = args_dict.get("file_path") or args_dict.get("path", "")
            if file_path:
                filename = os.path.basename(file_path)
                return f"file → {operation} → {filename}"
            # delete 操作可能用 paths 参数
            paths = args_dict.get("paths", [])
            if operation == "delete" and paths:
                count = len(paths) if isinstance(paths, list) else 1
                return f"file → delete → {count}files"
            return f"file → {operation}"

        # edit 工具：edit <type> [mode] <file_path>
        # type: single/multi/line
        # mode (line时): replace/insert_before/insert_after/delete
        elif tool_name == "edit":
            edit_type = args_dict.get("type", "single")
            file_path = args_dict.get("file_path", "")
            filename = os.path.basename(file_path) if file_path else ""

            if edit_type == "line":
                mode = args_dict.get("mode", "replace")
                return f"edit → line → {mode} → {filename}"
            elif edit_type == "multi":
                edits_count = len(args_dict.get("edits", []))
                return f"edit → multi → {edits_count}edits → {filename}"
            else:  # single
                return f"edit → single → {filename}"

        # execute_command 工具：execute_command <command>
        elif tool_name == "execute_command":
            command = args_dict.get("command", "")
            if command:
                # 处理多行命令标记
                if "@SPORE:CONTENT" in command:
                    return "execute_command multiline"
                # 提取命令的第一个单词
                first_word = command.split()[0] if command.split() else "command"
                # 截断过长的命令
                if len(first_word) > 30:
                    first_word = first_word[:30] + "..."
                return f"execute_command → {first_word}"
            return "execute_command"

        # Grep 工具：Grep <pattern>
        elif tool_name == "Grep":
            pattern = args_dict.get("pattern", "")
            if pattern:
                short_pattern = pattern[:25] + "..." if len(pattern) > 25 else pattern
                return f"Grep → {short_pattern}"
            return "Grep"

        # skill_query 工具：skill_query <skill_name>
        elif tool_name == "skill_query":
            skill_name = args_dict.get("skill_name", "")
            return f"skill_query → {skill_name}" if skill_name else "skill_query"

        # web_browser 工具：web_browser <action> <target>
        # action: visit/search
        elif tool_name == "web_browser":
            action = args_dict.get("action", "")
            target = args_dict.get("target", "")
            if action and target:
                short_target = target[:40] + "..." if len(target) > 40 else target
                return f"web_browser → {action} → {short_target}"
            elif action:
                return f"web_browser → {action}"
            return "web_browser"

        # multi_agent_dispatch 工具：multi_agent_dispatch <tasks_count>
        elif tool_name == "multi_agent_dispatch":
            tasks = args_dict.get("tasks", [])
            tasks_count = len(tasks) if isinstance(tasks, list) else 0
            if tasks_count > 0:
                return f"multi_agent_dispatch → {tasks_count}tasks"
            return "multi_agent_dispatch"

        # check_subagent_status 工具：无参数
        elif tool_name == "check_subagent_status":
            return "check_subagent_status"

        # 通用处理：优先提取 type/action/operation/method，然后提取关键参数
        sub_action = None
        for key in ["type", "action", "operation", "method"]:
            if key in args_dict:
                sub_action = args_dict[key]
                break

        # 提取关键参数（优先级顺序）
        key_param = None
        for param_key in ["name", "skill_name", "query", "target", "path", "file_path", "url", "description"]:
            if param_key in args_dict:
                value = args_dict[param_key]
                if value:
                    # 对于路径类参数，只显示文件名
                    if param_key in ["path", "file_path"]:
                        value = os.path.basename(value)
                    # 截断过长的值
                    key_param = str(value)[:30] + "..." if len(str(value)) > 30 else str(value)
                    break

        # 组合输出
        if sub_action and key_param:
            return f"{tool_name} → {sub_action} → {key_param}"
        elif sub_action:
            return f"{tool_name} → {sub_action}"
        elif key_param:
            return f"{tool_name} → {key_param}"

        # 如果没有找到任何子操作或参数，直接返回工具名
        return tool_name

    except (json.JSONDecodeError, TypeError, AttributeError, KeyError):
        return tool_name


def log_tool_result(tool_name: str, tool_result: str, args: Dict[str, Any]) -> None:
    """
    记录工具执行结果日志，自动检测错误并记录

    Args:
        tool_name: 工具名称
        tool_result: 工具返回的结果字符串
        args: 工具参数
    """
    is_error, error_msg = check_tool_result_error(tool_result)

    if is_error:
        # 工具执行失败 - 提取操作并显示错误
        action_desc = _extract_tool_action(tool_name, args)
        # 截断过长的错误信息
        short_error = error_msg[:50] + "..." if len(error_msg) > 50 else error_msg
        error_log = f"{action_desc} → ERROR: {short_error}"
        log_tool_error(tool_name, error_log, args, context=_tool_result_log_context(tool_result))
    else:
        # 额外检查 execute_command 的 returncode
        try:
            result_data = json.loads(tool_result) if isinstance(tool_result, str) else tool_result
            if isinstance(result_data, dict):
                if tool_name == "execute_command" and result_data.get("ok") is False:
                    action_desc = _extract_tool_action(tool_name, args)
                    error_code = result_data.get('returncode', -1)
                    error_log = f"{action_desc} → ERROR: exit code {error_code}"
                    log_tool_error(
                        tool_name,
                        error_log,
                        args,
                        context=_tool_result_log_context(tool_result),
                    )
                    return
        except (json.JSONDecodeError, TypeError):
            pass

        # 工具执行成功 - 提取并显示具体操作
        action_desc = _extract_tool_action(tool_name, args)
        log_info(action_desc, context={"tool_name": tool_name}, args=args)
