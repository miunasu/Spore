import json
import re
from typing import Optional, Dict, Any, Tuple
from ..logger import log_llm_validation_error, log_tool_error, log_info


def _strip_think_tags(text: str) -> str:
    """
    移除文本中的 <think>...</think> 标签及其内容。
    某些 API 代理（如 packyapi）会在响应中添加思考过程。
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
            
            # 有 stderr 时使用 stderr 作为错误信息
            if stderr:
                error_msg = stderr
            else:
                error_msg = result_data.get("error") or result_data.get("message") or "命令执行失败"
            return True, error_msg
        
        return False, None
        
    except (json.JSONDecodeError, TypeError, AttributeError):
        return False, None


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
        log_tool_error(tool_name, error_msg, args, context={"result": tool_result[:500]})
    else:
        # 额外检查 execute_command 的 returncode
        try:
            result_data = json.loads(tool_result) if isinstance(tool_result, str) else tool_result
            if isinstance(result_data, dict):
                if tool_name == "execute_command" and result_data.get("ok") is False:
                    log_tool_error(
                        tool_name, 
                        f"命令执行失败 (exit code {result_data.get('returncode', -1)})", 
                        args
                    )
                    return
        except (json.JSONDecodeError, TypeError):
            pass
        
        # 工具执行成功
        log_info(f"Tool executed successfully: {tool_name}", context={"tool_name": tool_name}, args=args)
