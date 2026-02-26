"""
对话循环处理器

处理主要的对话循环逻辑，包括消息管理、子agent恢复、LLM交互等。
使用文本协议（ACTION / RESULT / FINAL_RESPONSE）与 LLM 交互。
"""
import json
import time
from typing import Dict, Any, Optional

from .state_manager import ConversationState
from .tools import TOOL_HANDLERS, TOOL_DEFINITIONS
from .text_protocol import ProtocolManager, ParsedAction, is_standalone_marker
from .utils import (
    json_query, 
    validate_json_response, 
    clear_todo_block, 
    get_last_todo_content,
    clear_last_todo_content,
    count_tokens,
    parse_json_object,
    todo_print,
    log_tool_result,
)
from .todo_manager import todo_write
from .logger import log_error, log_tool_error
from AutoAgent import end_check
from AutoAgent.supervisor import supervisor
from .utils import terminal
from . import config as _config

class ConversationLoop:
    """对话循环处理器"""
    
    def __init__(
        self, 
        state: ConversationState, 
        ipc_manager, 
        config,
        system_prompt: str,
        tool_names: list = None  # 主agent的工具名称列表
    ):
        self.state = state
        self.ipc_manager = ipc_manager
        self.config = config
        self.system_prompt = system_prompt
        self.tool_names = tool_names  # 用于重新加载prompt时使用
        
        # 初始化文本协议管理器
        self.protocol_manager = ProtocolManager()
    
    def manage_context_length(self) -> None:
        """管理对话历史长度"""
        current_tokens = count_tokens(self.state.messages)
        # 加上 system prompt 和预留的 completion tokens
        system_tokens = count_tokens(self.system_prompt) if self.system_prompt else 0
        total_tokens = current_tokens + system_tokens
        max_tokens = self.config.context_max_tokens

        # 无论是超限还是逼近极限，都优先检查并删除超大消息
        warning_threshold = max_tokens * self.config.context_warning_threshold
        
        if total_tokens > warning_threshold:
            # 先尝试删除超大消息
            if self._remove_oversized_last_message():
                # 重新计算token数
                current_tokens = count_tokens(self.state.messages)
                total_tokens = current_tokens + system_tokens
                terminal.extra_line += 1
                print(f"[系统] 已删除超大消息，当前 {total_tokens} 个token（含system prompt）")
        
        # 删除超大消息后，如果仍然接近或超过上限，开始压缩
        if total_tokens > warning_threshold:
            print(f"[系统] 对话历史接近上限（{total_tokens}/{max_tokens}），开始压缩记忆...")
            
            # 调用 LLM 对记忆进行总结压缩
            summary = self._compress_memory()
            
            if summary:
                # 清空旧记忆，保留总结
                print(f"[系统] 记忆已压缩，保留总结内容")
                self.state.messages = [
                    {
                        "role": "user",
                        "content": f"以下是之前对话的总结：\n\n{summary}\n\n请基于这个总结继续对话。"
                    }
                ]
            else:
                # 如果压缩失败，使用原有的删除策略
                print(f"[系统] 记忆压缩失败，使用传统删除策略")
                while total_tokens > max_tokens:
                    self.state.messages.pop(0)
                    current_tokens = count_tokens(self.state.messages)
                    total_tokens = current_tokens + system_tokens
            
            # 重新计算最终的token数
            current_tokens = count_tokens(self.state.messages)
            total_tokens = current_tokens + system_tokens
            print(f"[系统] 对话历史已压缩：消息 {current_tokens} + system {system_tokens} = {total_tokens} tokens")
            terminal.extra_line += 3

    def _remove_oversized_last_message(self) -> bool:
        """
        检查并删除最后一条超大消息（文本协议版本）
        
        返回:
            如果删除了消息返回True，否则返回False
        """
        if not self.state.messages:
            return False
        
        # 获取最后一条消息
        last_msg = self.state.messages[-1]
        last_msg_tokens = count_tokens([last_msg])
        
        # 设置单条消息的最大token数（从配置读取比例）
        max_single_msg_tokens = self.config.context_max_tokens * self.config.max_single_message_ratio
        
        if last_msg_tokens <= max_single_msg_tokens:
            return False
        
        print(f"[系统] 检测到超大消息（{last_msg_tokens} tokens），开始处理...")
        
        # 检查是否是 RESULT 消息（user 角色，包含独占一行的 @SPORE:RESULT）
        if last_msg.get("role") == "user" and is_standalone_marker(last_msg.get("content", ""), "@SPORE:RESULT"):
            # 删除 RESULT 消息
            self.state.messages.pop()
            print(f"[系统] 已删除超大的工具返回消息")
            
            # 查找并删除对应的 assistant 消息（包含 ACTION 块）
            for i in range(len(self.state.messages) - 1, -1, -1):
                msg = self.state.messages[i]
                if msg.get("role") == "assistant" and is_standalone_marker(msg.get("content", ""), "@SPORE:ACTION"):
                    # 尝试解析 ACTION 块获取工具信息
                    action = self.protocol_manager.action_parser.parse(msg.get("content", ""))
                    tool_name = action.tool_name if action else "未知工具"
                    tool_args = str(action.parameters) if action else "{}"
                    
                    # 删除 assistant 消息
                    self.state.messages.pop(i)
                    print(f"[系统] 已删除对应的工具调用请求消息")
                    
                    # 添加通知消息
                    notice = f"[系统通知] 你刚才调用了工具 {tool_name}，参数：{tool_args}。但工具返回的内容过大（{last_msg_tokens} tokens），已被系统删除。请使用更精确的查询参数来限制输出，例如：\n- 使用更具体的搜索关键词\n- 限制搜索范围或文件类型\n- 只查看关键部分而非全部内容"
                    self.state.messages.append({
                        "role": "user",
                        "content": notice
                    })
                    terminal.extra_line += 4
                    print(f"[系统] 已添加超限通知消息")
                    return True
            
            # 如果没找到对应的 assistant 消息，也添加通知
            notice = f"[系统通知] 工具返回的内容过大（{last_msg_tokens} tokens），已被系统删除。请使用更精确的查询参数来限制输出。"
            self.state.messages.append({
                "role": "user",
                "content": notice
            })
            terminal.extra_line += 2
            return True
        
        # 如果是 assistant 消息过大
        elif last_msg.get("role") == "assistant":
            self.state.messages.pop()
            print(f"[系统] 已删除超大的 assistant 消息（{last_msg_tokens} tokens）")
            
            notice = "[系统通知] 你上一条回复内容过大，已被系统删除。请用更简洁的方式回复。或进行多次对话，分次输出。"
            self.state.messages.append({
                "role": "user",
                "content": notice
            })
            terminal.extra_line += 2
            return True
        
        # 其他类型的消息（如 user），不删除
        terminal.extra_line += 1
        return False

    def _preprocess_messages_for_compression(self, messages: list) -> list:
        """
        预处理消息列表，将工具调用转换为易读的自然语言格式（文本协议版本）
        
        参数:
            messages: 原始消息列表
        
        返回:
            处理后的消息列表
        """
        processed = []
        i = 0
        while i < len(messages):
            msg = messages[i]
            role = msg.get("role")
            content = msg.get("content", "")
            
            if role == "assistant" and is_standalone_marker(content, "@SPORE:ACTION"):
                # 处理包含 ACTION 块的 assistant 消息
                content_parts = []
                
                # 解析 ACTION 块
                action = self.protocol_manager.action_parser.parse(content)
                if action:
                    # 提取 ACTION 之前的文本
                    action_pos = content.find("@SPORE:ACTION")
                    if action_pos > 0:
                        prefix = content[:action_pos].strip()
                        if prefix:
                            content_parts.append(prefix)
                    
                    # 简化参数显示
                    args_str = str(action.parameters)
                    if len(args_str) > 200:
                        args_str = args_str[:200] + "..."
                    content_parts.append(f"[执行操作: {action.tool_name}({args_str})]")
                else:
                    content_parts.append(content[:500] + "..." if len(content) > 500 else content)
                
                # 查找对应的 RESULT 消息
                j = i + 1
                while j < len(messages):
                    next_msg = messages[j]
                    if next_msg.get("role") == "user" and is_standalone_marker(next_msg.get("content", ""), "@SPORE:RESULT"):
                        result_content = next_msg.get("content", "")
                        # 提取 RESULT 内容
                        result_start = result_content.find("@SPORE:RESULT")
                        if result_start >= 0:
                            result_text = result_content[result_start + len("@SPORE:RESULT"):].strip()
                            # 截断过长的结果
                            if len(result_text) > 500:
                                result_text = result_text[:500] + "...(内容已截断)"
                            content_parts.append(f"[工具返回: {result_text}]")
                        j += 1
                        break
                    j += 1
                
                # 创建合并后的消息
                processed.append({
                    "role": "assistant",
                    "content": "\n".join(content_parts)
                })
                
                # 跳过已处理的 RESULT 消息
                i = j
                continue
            
            elif role == "user" and is_standalone_marker(content, "@SPORE:RESULT"):
                # 单独的 RESULT 消息（没有对应的 ACTION），转换格式
                result_start = content.find("@SPORE:RESULT")
                result_text = content[result_start + len("@SPORE:RESULT"):].strip() if result_start >= 0 else content
                if len(result_text) > 500:
                    result_text = result_text[:500] + "...(内容已截断)"
                processed.append({
                    "role": "assistant",
                    "content": f"[工具返回: {result_text}]"
                })
            
            elif role == "assistant":
                # 普通 assistant 消息
                if len(content) > 500:
                    content = content[:500] + "...(内容已截断)"
                processed.append({
                    "role": "assistant",
                    "content": content
                })
            
            else:
                # user 消息或其他，直接保留（但截断过长内容）
                if len(content) > 500:
                    content = content[:500] + "...(内容已截断)"
                processed.append({
                    "role": role,
                    "content": content
                })
            
            i += 1
        
        return processed

    def _compress_memory(self) -> Optional[str]:
        """
        使用 LLM 压缩对话记忆
        
        返回:
            压缩后的总结文本，如果失败返回 None
        """
        try:
            # 构建压缩提示
            compress_prompt = [
                {
                    "role": "user",
                    "content": """请仔细阅读以下对话历史，并生成一个全面的总结。总结应该包括：
1. 讨论的主要话题和关键信息
2. 重要的决策和结论
3. 待完成或正在进行的任务
4. 需要记住的关键上下文信息
5. 一定要全面，不要遗漏任何重要的信息，可以输出较长的总结。
6. 直接输出你的总结，使用自然语言描述，不要包含任何代码、函数调用标记或JSON格式
请用中文总结，保持简洁明了，重点突出核心内容。"""
                }
            ]
            
            # 添加当前的对话历史（排除system消息），并预处理工具调用
            history_to_compress = self._preprocess_messages_for_compression(
                [msg for msg in self.state.messages if msg.get("role") != "system"]
            )
            
            print(f"[系统] 正在压缩 {len(history_to_compress)} 条对话记录...")
            
            # 发送压缩请求（不使用工具调用）
            request_id = self.ipc_manager.send_chat_request(
                messages=compress_prompt + history_to_compress,
                model=self.config.get_model(),
                temperature=0.3,  # 使用较低温度以获得更稳定的总结
                system="你是一个专业的对话总结助手，擅长提炼对话的核心内容和关键信息，你不会遗漏任何重要的信息。",
                tool_calls=False,  # 不需要工具调用
                tools=None
            )
            
            # 等待响应
            response = self.ipc_manager.get_chat_response(request_id=request_id, timeout=60)
            
            if response is None or response.get("status") != "success":
                print(f"[系统] 记忆压缩请求失败或超时")
                terminal.extra_line += 2
                return None
            
            # 提取总结内容
            reply_data = response.get("data", {})
            summary = reply_data.get("content", "")
            
            if not summary or len(summary.strip()) == 0:
                terminal.extra_line += 2
                print(f"[系统] 未能获取有效的总结内容")
                return None
            
            print(f"[系统] 记忆压缩完成，总结长度：{len(summary)} 字符")
            terminal.extra_line += 2
            return summary.strip()
            
        except Exception as e:
            terminal.extra_line += 2
            print(f"[系统] 记忆压缩过程出错：{e}")
            log_error("MEMORY_COMPRESSION_ERROR", "Failed to compress memory", e)
            return None
    
    def fix_incomplete_messages(self) -> None:
        """
        修复不完整的消息（文本协议版本）
        
        检查是否有 assistant 消息包含 ACTION 块但没有对应的 RESULT 响应
        """
        for i in range(len(self.state.messages) - 1, -1, -1):
            msg = self.state.messages[i]
            if msg.get("role") == "assistant":
                content = msg.get("content", "")
                # 检查是否包含 ACTION 块
                if is_standalone_marker(content, "@SPORE:ACTION"):
                    # 检查后续是否有 RESULT 响应
                    has_response = False
                    for j in range(i + 1, len(self.state.messages)):
                        next_msg = self.state.messages[j]
                        if next_msg.get("role") == "user" and is_standalone_marker(next_msg.get("content", ""), "@SPORE:RESULT"):
                            has_response = True
                            break
                    
                    if not has_response:
                        # 在该 assistant 消息后插入中断 RESULT
                        result_text = self.protocol_manager.format_interrupt()
                        self.state.messages.insert(i + 1, {
                            "role": "user",
                            "content": result_text
                        })
                        break
    
    def send_chat_request(self) -> Optional[Dict]:
        """
        发送聊天请求并获取响应
        
        返回:
            响应字典，如果失败或中断返回None
        """
        # 只在中断后的第一次请求前清空队列，避免干扰 supervisor 等其他模块
        if getattr(self, '_interrupted_flag', False):
            self.ipc_manager.clear_queues()
            self._interrupted_flag = False
        
        # 每次请求前重新加载 system_prompt，确保动态内容（TODO、角色、目录等）是最新的
        from .prompt_loader import load_system_prompt
        from .tools import TOOL_DEFINITIONS
        
        base_prompt = load_system_prompt()
        if base_prompt and self.tool_names:
            # 使用指定的工具子集注入协议
            tool_definitions = {name: TOOL_DEFINITIONS[name] for name in self.tool_names if name in TOOL_DEFINITIONS}
            current_system_prompt = self.protocol_manager.inject_protocol(base_prompt, tool_definitions)
        elif base_prompt:
            # 没有指定工具列表，使用全部工具
            current_system_prompt = self.protocol_manager.inject_protocol(base_prompt, TOOL_DEFINITIONS)
        else:
            current_system_prompt = self.system_prompt
        
        # 发送请求并获取 request_id - 纯文本模式，不使用 function calling
        request_id = self.ipc_manager.send_chat_request(
            messages=self.state.messages,
            model=self.config.get_model(),
            temperature=self.config.get_temperature("main"),
            system=current_system_prompt,
            tool_calls=False,  # 文本协议不使用 function calling
            tools=None
        )
        
        # 使用 request_id 等待响应
        response = self.ipc_manager.get_chat_response(request_id=request_id)
        
        if response is None or response.get("status") == "cancelled":
            print("Spore> 对话中断，请继续")
            return None
        
        if response.get("status") == "error":
            error_msg = response.get('data')
            print(f"Spore> [错误] {error_msg}")
            log_error("LLM_API_ERROR", f"Chat process returned error: {error_msg}")
            return None
        
        return response
    
    def handle_action(self, action: ParsedAction, prefix_text: Optional[str] = None) -> Optional[str]:
        """
        处理 ACTION 块中的工具调用（文本协议）
        
        参数:
            action: 解析后的 ACTION 数据
            prefix_text: ACTION 块之前的文本内容（用于显示）
        
        返回:
            如果需要中断循环返回 "break"，如果需要继续返回 "continue"，否则返回 None
        """
        # 清除上次的TODO显示
        last_todo_content = get_last_todo_content()
        if last_todo_content != "":
            clear_todo_block(last_todo_content)
            clear_last_todo_content()
        
        tool_name = action.tool_name
        args = action.parameters
        
        # 显示 LLM 的说明内容（如果有，过滤掉 TODO 块）
        if prefix_text:
            content = self._filter_todo_block(prefix_text)
            if content:
                if content.endswith(":") or content.endswith("："):
                    content = content[:-1] + "。"
                print(f"{_config.current_agent_name}> {content}")
        
        # 显示 TODO
        if _config.current_agent_name == "Spore" and tool_name != "multi_agent_dispatch":
            todo_print()
        
        # 添加 assistant 消息到对话历史（包含完整的 ACTION 块）
        assistant_content = prefix_text + "\n\n" + action.raw_text if prefix_text else action.raw_text
        self.state.messages.append({
            "role": "assistant",
            "content": assistant_content
        })
        
        # 获取工具处理器
        handler = TOOL_HANDLERS.get(tool_name)
        
        if handler is None:
            # 工具未找到
            result_text = self.protocol_manager.format_not_found(tool_name)
            log_tool_error(tool_name, "未找到工具处理器", args,
                          context={"available_tools": list(TOOL_HANDLERS.keys()), "requested_tool": tool_name})
        else:
            try:
                # 某些工具不限时
                no_timeout_tools = ["multi_agent_dispatch", "delete_path"]
                
                if tool_name in no_timeout_tools:
                    tool_result = handler(args)
                else:
                    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
                    from base.utils.system_io import set_current_agent_id, get_current_agent_id
                    
                    tool_timeout = self.config.tool_execution_timeout
                    current_agent_id = get_current_agent_id() or "main_agent"
                    
                    def execute_with_agent_id():
                        # 在工作线程中设置 agent_id
                        set_current_agent_id(current_agent_id)
                        return handler(args)
                    
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(execute_with_agent_id)
                        try:
                            tool_result = future.result(timeout=tool_timeout)
                        except FuturesTimeoutError:
                            print(f"[警告] 工具 {tool_name} 执行超时（{tool_timeout}秒）")
                            future.cancel()
                            tool_result = None
                            result_text = self.protocol_manager.format_error(
                                f"工具执行超时: {tool_name} 执行超过{tool_timeout}秒",
                                tool_name
                            )
                            log_tool_error(tool_name, "工具执行超时", args)
                
                # 如果工具返回 None，表示被中断或超时
                if tool_result is None:
                    # 检查是否已设置 result_text（超时会设置，中断不会）
                    is_timeout = 'result_text' in locals()
                    
                    if not is_timeout:
                        # 没有设置 result_text，说明是中断
                        result_text = self.protocol_manager.format_interrupt(tool_name)
                    
                    self.state.messages.append({
                        "role": "user",
                        "content": result_text
                    })
                    
                    # 区分中断和超时：
                    # - 超时：继续让 LLM 看到超时信息并做出回应
                    # - 中断：直接结束对话循环
                    return "continue" if is_timeout else "break"
                
                # 格式化工具结果
                result_text = self.protocol_manager.format_result(tool_result, tool_name)
                
                # 记录工具执行日志
                self._log_tool_result(tool_name, tool_result, args)
                
            except Exception as e:
                result_text = self.protocol_manager.format_error(str(e), tool_name)
                log_tool_error(tool_name, f"工具执行异常: {str(e)}", args, e)
        
        # 添加 RESULT 到对话历史（作为 user 消息）
        self.state.messages.append({
            "role": "user",
            "content": result_text
        })
        
        # 保存临时消息
        self.state.save_temp_messages()
        
        return "continue"
    
    def _get_tool_names_list(self) -> str:
        """
        获取工具名称列表（只列名称）
        
        Returns:
            工具名称列表字符串
        """
        tool_names = list(TOOL_DEFINITIONS.keys())
        return "\n".join(f"- {name}" for name in tool_names)
    
    def _filter_todo_block(self, text: str) -> str:
        """
        过滤掉文本中的 @SPORE:TODO 块
        
        Args:
            text: 原始文本
            
        Returns:
            过滤后的文本
        """
        if not text or "@SPORE:TODO" not in text:
            return text
        
        # 找到 TODO 块的位置
        todo_pos = text.find("@SPORE:TODO")
        
        # TODO 块之前的内容
        before_todo = text[:todo_pos].strip()
        
        # TODO 块之后的内容（找到下一个 ### 或结束）
        after_todo_start = todo_pos + len("@SPORE:TODO")
        remaining = text[after_todo_start:]
        
        # 找到 TODO 块的结束位置（下一个 ### 标记或文本结束）
        next_section = remaining.find("\n###")
        if next_section >= 0:
            after_todo = remaining[next_section + 1:].strip()  # +1 跳过换行符
        else:
            after_todo = ""
        
        # 合并前后内容
        result = before_todo
        if after_todo:
            result = result + "\n" + after_todo if result else after_todo
        
        return result.strip()
    
    def _log_tool_result(self, tool_name: str, tool_result: str, args: Dict[str, Any]) -> None:
        """记录工具执行结果日志"""
        log_tool_result(tool_name, tool_result, args)
    
    def _update_todo_from_response(self, reply: str) -> None:
        """
        从 LLM 响应中解析 TODO 块并更新任务状态
        
        Args:
            reply: LLM 响应文本
        """
        tasks = self.protocol_manager.parse_todo_from_response(reply)
        if tasks:
            # 更新 TODO
            todo_write(tasks)
    
    def validate_and_check_response(self, reply: str) -> Optional[str]:
        """
        验证响应并检查状态（文本协议版本）
        
        使用 ProtocolManager 解析响应，检测 ACTION、FINAL_RESPONSE 或继续状态
        同时解析 TODO 块并更新任务状态
        
        参数:
            reply: LLM响应内容
        
        返回:
            如果需要中断循环返回 "break"，如果需要继续返回 "continue"，否则返回 None
        """
        # 解析并更新 TODO（如果 LLM 回复中包含 @SPORE:TODO）
        self._update_todo_from_response(reply)
        
        # 使用 ProtocolManager 解析响应
        parsed = self.protocol_manager.parse_response(reply)
        
        # 特殊值，表示上次有 ACTION
        ACTION_MARKER = "__ACTION__"
        
        if parsed.response_type == "action":
            # 有 ACTION 块，执行工具
            self._no_action_count = 0  # 重置无 ACTION 计数器
            # 标记本次有 ACTION
            self.state.last_answer = ACTION_MARKER
            # 如果有 REPLY 内容，先显示
            if parsed.reply_content:
                print(f"{_config.current_agent_name}> {parsed.reply_content}")
            return self.handle_action(parsed.action, parsed.prefix_text)
        
        elif parsed.response_type == "final":
            # 检测到 FINAL_RESPONSE，任务完成
            self._no_action_count = 0  # 重置无 ACTION 计数器
            # 优先显示 REPLY 内容，否则显示 prefix_text（过滤掉 TODO 块）
            display_text = parsed.reply_content
            if not display_text and parsed.prefix_text:
                display_text = self._filter_todo_block(parsed.prefix_text)
            if display_text:
                print(f"{_config.current_agent_name}> {display_text}")
            
            # 添加 assistant 消息到对话历史（使用 add_assistant_message 增加计数）
            self.state.add_assistant_message(reply)
            
            # 清理状态
            self.state.restore_temp_messages()
            todo_write([])
            clear_last_todo_content()
            self.state.last_answer = ""  # 重置
            return "break"
        
        else:
            # continue 类型：既没有 ACTION 也没有 FINAL_RESPONSE
            # 优先使用 REPLY 内容
            current_answer = parsed.reply_content or parsed.prefix_text or reply.strip()
            # 过滤掉只包含 < 或 <<< 等不完整标记的情况
            display_answer = ""
            if current_answer and current_answer.strip('<> \n'):
                # 移除末尾可能的不完整标记，并过滤 TODO 块
                display_answer = self._filter_todo_block(current_answer.rstrip('<').strip())
            
            # 增加无 ACTION 计数器
            if not hasattr(self, '_no_action_count'):
                self._no_action_count = 0
            self._no_action_count += 1
            
            # 检测是否应该结束
            should_end = False
            
            # 只有当上次和本次都没有 ACTION 时才调用 supervisor
            last = self.state.last_answer if self.state.last_answer else ""
            if last != ACTION_MARKER and last != "":
                # 上次没有 ACTION，本次也没有 ACTION，调用 supervisor
                if supervisor(last, current_answer):
                    should_end = True
            
            if should_end:
                # 检测到循环或结束，打印内容并结束
                if display_answer:
                    print(f"{_config.current_agent_name}> {display_answer}")
                
                self.state.messages.append({
                    "role": "assistant",
                    "content": reply
                })
                self.state.restore_temp_messages()
                todo_write([])
                clear_last_todo_content()
                self.state.last_answer = ""  # 重置
                return "break"
            
            # 不结束，打印内容并继续
            
            # 先清除之前的TODO显示（如果有）
            last_todo = get_last_todo_content()
            if last_todo != "":
                clear_todo_block(last_todo)
                clear_last_todo_content()
            
            if display_answer:
                print(f"{_config.current_agent_name}> {display_answer}")
            
            # 显示 TODO（如果有）
            if _config.current_agent_name == "Spore":
                todo_print()
            
            # 更新 last_answer（本次没有 ACTION，记录回复内容）
            self.state.last_answer = current_answer
            
            # 添加 assistant 消息（使用 add_assistant_message 增加计数）
            self.state.add_assistant_message(reply)
            
            return "continue"
    
    def handle_keyboard_interrupt(self) -> None:
        """处理键盘中断"""
        print("\nInterrupt LLM...")
        clear_last_todo_content()
        todo_write([])
        
        # 发送中断命令
        self.ipc_manager.interrupt_current_request()
        
        # 第一次清空队列
        self.ipc_manager.clear_queues()
        
        # 等待 Chat 进程处理中断命令并可能发送响应
        time.sleep(0.3)
        
        # 第二次清空队列，确保清除 Chat 进程在中断后发送的任何响应
        cleared = self.ipc_manager.clear_queues()
        if cleared > 0:
            # 如果还有残留数据，再等待一下并清空
            time.sleep(0.1)
            self.ipc_manager.clear_queues()
        
        # 清理打断时产生的残留消息
        self._cleanup_interrupted_messages()
        
        # 重置状态变量
        self.state.last_answer = ""
        self.state.current_answer = ""
        
        # 设置中断标志，下次发送请求前会再次清空队列
        self._interrupted_flag = True
        
        print("Spore> 对话已中断，请继续")
    
    def _cleanup_interrupted_messages(self) -> None:
        """清理打断时产生的残留消息（文本协议版本）"""
        if not self.state.messages:
            return
        
        last_msg = self.state.messages[-1]
        
        # 情况1：最后一条是 RESULT 消息，说明工具执行已完成
        if last_msg.get("role") == "user" and is_standalone_marker(last_msg.get("content", ""), "@SPORE:RESULT"):
            pass  # 保留完整的工具响应
        
        # 情况2：最后一条是 assistant 消息
        elif last_msg.get("role") == "assistant":
            content = last_msg.get("content", "")
            
            # 检查是否包含 FINAL_RESPONSE，说明是完整回复
            if is_standalone_marker(content, "@SPORE:FINAL@"):
                pass  # 保留完整的最终响应
            
            # 检查是否包含未完成的 ACTION 块
            elif is_standalone_marker(content, "@SPORE:ACTION"):
                # 有 ACTION 但没有对应的 RESULT，移除
                self.state.messages.pop()
            
            # 空内容或不完整的响应
            elif not content.strip():
                self.state.messages.pop()
