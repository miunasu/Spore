"""
对话循环处理器

处理主要的对话循环逻辑，包括消息管理、子agent恢复、LLM交互等。
使用文本协议（ACTION_SINGLE / ACTION_SEQUENCE / ACTION_PARALLEL / RESULT / STOP_REASON）与 LLM 交互。
"""
import json
import time
import os
import uuid
import contextvars
import threading
from typing import Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from .state_manager import ConversationState
from .tools import CURRENT_ACTION_BLOCK_MODE, TOOL_HANDLERS, TOOL_DEFINITIONS
from .text_protocol import ProtocolManager, ParsedAction, ParsedActionBlock, is_standalone_marker, has_stop_reason_marker, is_stop_reason_line
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
from .utils.terminal import safe_print
from .utils.system_io import set_current_agent_id, get_current_agent_id
from .todo_manager import todo_write
from .memory_manager import auto_save_messages
from .logger import log_error, log_tool_error
from .prompt_loader import load_system_prompt
from .session_context import get_current_conversation_id
from AutoAgent.supervisor import supervisor
from .utils import terminal
from . import config as _config


class ConversationLoop:
    """对话循环处理器"""

    # 可选的事件回调（由上层注入，例如桌面后端的任务循环）。
    # 签名: event_emitter(event_name: str, data: dict) -> None
    # None 时零行为，CLI 模式不受影响。base/ 不直接依赖 websocket 模块（分层约束）。
    event_emitter = None

    def __init__(
        self, 
        session_manager,  # 改为接收 session_manager 而不是单个 state
        ipc_manager, 
        config,
        system_prompt: str,
        tool_names: list = None  # 主agent的工具名称列表
    ):
        self.session_manager = session_manager  # 保存 session_manager
        self.ipc_manager = ipc_manager
        self.config = config
        self.system_prompt = system_prompt
        self.session_id = None
        self.tool_names = tool_names  # 用于重新加载prompt时使用
        
        # 初始化文本协议管理器
        self.protocol_manager = ProtocolManager()
        self._request_id_lock = threading.Lock()
        self._current_request_id: Optional[str] = None
        
        # 初始化 Learning 系统（情景记忆检索）
        # 这两个字段必须在 try 之外赋值：即使 EpisodicRetriever 构造失败，
        # 后续任务完成分支也会读取它们
        self._task_start_query = None  # 记录任务开始时的用户查询
        self._task_start_time = None   # 记录任务开始时间
        self._no_action_count: int = 0  # 连续无 ACTION 的计数器
        try:
            if not config.embedding_api_key:
                self.retriever = None
            else:
                from learning import EpisodicRetriever
                self.retriever = EpisodicRetriever()
        except Exception as e:
            # Learning 模块不可用时降级运行
            self.retriever = None
            log_error("LEARNING_INIT_ERROR", f"Failed to initialize learning system: {e}", e)
    
    @property
    def state(self):
        """动态获取当前会话状态。

        Desktop: session_manager is MultiSessionManager (.current).
        CLI: first arg may be a bare ConversationState (no .current).
        """
        sm = self.session_manager
        if hasattr(sm, "current"):
            return sm.current
        return sm

    def _resolve_effective_mode(self) -> str:
        """Resolve concrete tool baseline mode for this session."""
        from .tool_policy import effective_mode_name

        context_mode = getattr(self.state, "context_mode", "strong_context")
        # selected_auto_mode is set by desktop/CLI when context_mode == auto
        selected = getattr(self.state, "selected_auto_mode", None) or getattr(self, "_selected_auto_mode", None)
        return effective_mode_name(context_mode, selected)

    def _get_session_tool_policy(self):
        """Normalized tool policy for the effective mode (honors global/session scope)."""
        from .tool_policy import resolve_mode_policy

        mode = self._resolve_effective_mode()
        policies = getattr(self.state, "tool_policies", None) or {}
        return mode, resolve_mode_policy(mode, policies)

    def _get_current_tool_names(self) -> list:
        """Return enabled top-level tools for the session mode + policy."""
        from .tool_policy import resolve_enabled_tool_names

        mode, policy = self._get_session_tool_policy()
        return resolve_enabled_tool_names(mode, policy)

    def _get_current_tool_definitions(self) -> dict:
        """Return filtered TOOL_DEFINITIONS (including sub-tool enums)."""
        from .tool_policy import filter_tool_definitions

        mode, policy = self._get_session_tool_policy()
        return filter_tool_definitions(mode, policy)

    def _conversation_id_for_context(self) -> Optional[str]:
        return getattr(self, "session_id", None) or get_current_conversation_id()

    @staticmethod
    def _checkpoint_reply_preview(reply: str, parsed_reply: Optional[str]) -> str:
        """
        为对话点快照生成回复摘要：优先用解析出的 REPLY 文本；
        纯 ACTION 轮取协议块之外的自然语言，全部为空则返回空串。
        """
        text = (parsed_reply or "").strip()
        if not text:
            parts = []
            in_block = False
            for line in (reply or "").splitlines():
                s = line.strip()
                if s.startswith("@SPORE:") and s.endswith("_START"):
                    in_block = True
                    continue
                if s.startswith("@SPORE:") and s.endswith("_END"):
                    in_block = False
                    continue
                if in_block or s.startswith("@SPORE:") or s.startswith("### RULE_REMINDER"):
                    continue
                if s:
                    parts.append(s)
            text = " ".join(parts)
        return " ".join(text.split())[:200]

    def _emit_event(self, event: str, data: Dict[str, Any]) -> None:
        """通过注入的回调发出结构化事件；未注入时零行为，异常不影响主流程。"""
        emitter = getattr(self, "event_emitter", None)
        if emitter is None:
            return
        try:
            emitter(event, data)
        except Exception as e:
            log_error("EVENT_EMITTER_ERROR", f"Event emitter failed for event '{event}': {e}", e)

    def manage_context_length(self) -> None:
        """
        管理对话历史长度
        
        使用 LLM 返回的精确 input_tokens 判断是否超出限制。
        Desktop 模式：优先用 state.last_context_tokens（含缓存命中的真实上下文规模）
        CLI 模式：需要在调用后检查
        """
        # Desktop 模式：检查 state 中的 token 统计
        if os.environ.get('SPORE_DESKTOP_MODE') == '1':
            # last_input_tokens 在 Anthropic 口径下不含 cache_read/cache_creation，
            # 命中缓存时会小到个位数，只看它压缩永远不会触发
            current_tokens = getattr(self.state, 'last_context_tokens', 0) or getattr(
                self.state, 'last_input_tokens', 0
            )
            if current_tokens == 0:
                # API 没给可用的 token 统计（第三方中转常见）：退回本地估算，
                # 否则上下文压缩这条防线在整个 Desktop 模式下等于不存在
                current_tokens = self._estimate_context_tokens()
            if current_tokens == 0:
                return
        else:
            # CLI 模式：使用 tiktoken 估算当前 context token 数
            current_tokens = count_tokens(self.state.messages)
            if current_tokens == 0:
                return
        
        max_tokens = self.config.context_max_tokens
        warning_threshold = max_tokens * self.config.context_warning_threshold
        
        if current_tokens > warning_threshold:
            print(f"[系统] 对话历史接近上限（{current_tokens}/{max_tokens}），开始压缩记忆...")
            
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
                # 重置 token 统计
                self.state.last_input_tokens = 0
                self.state.last_output_tokens = 0
                self.state.last_context_tokens = 0
                self.state.cumulative_input_tokens = 0
                self.state.cumulative_output_tokens = 0
            else:
                # 如果压缩失败，使用删除策略
                print(f"[系统] 记忆压缩失败，删除最旧的消息")
                if len(self.state.messages) > 1:
                    self.state.messages.pop(0)
            
            terminal.extra_line += 2

    def _estimate_context_tokens(self) -> int:
        """本地估算当前上下文 token 数。

        API 不返回可用 usage（第三方中转很常见）时的兜底。tiktoken 缺失时按
        字符数粗估——宁可粗糙，也好过压缩机制完全失效直到撞上下文上限。
        """
        try:
            return count_tokens(self.state.messages)
        except Exception:
            pass
        try:
            chars = sum(
                len(msg.get("content") or "")
                for msg in self.state.messages
                if isinstance(msg, dict) and isinstance(msg.get("content"), str)
            )
            # 中英混排经验值：约 2.5 字符/token
            return int(chars / 2.5)
        except Exception:
            return 0

    def _check_and_handle_oversized_tool_result(self) -> bool:
        """
        检查工具返回结果是否超大，如果超大则删除并通知
        
        返回:
            如果删除了消息返回True，否则返回False
        """
        if not self.state.messages:
            return False
        
        # 获取最后一条消息
        last_msg = self.state.messages[-1]
        
        # 只检查 RESULT 消息（user 角色，包含独占一行的 @SPORE:RESULT）
        if not (last_msg.get("role") == "user" and is_standalone_marker(last_msg.get("content", ""), "@SPORE:RESULT")):
            return False
        
        last_msg_tokens = count_tokens([last_msg])
        
        # 设置单条消息的最大token数（从配置读取比例）
        max_single_msg_tokens = self.config.context_max_tokens * self.config.max_single_message_ratio
        
        if last_msg_tokens <= max_single_msg_tokens:
            return False
        
        print(f"[系统] 检测到超大工具返回（{last_msg_tokens} tokens），开始处理...")
        
        # 删除 RESULT 消息
        self.state.messages.pop()
        print(f"[系统] 已删除超大的工具返回消息")
        
        # 查找并删除对应的 assistant 消息（包含 ACTION 块）
        for i in range(len(self.state.messages) - 1, -1, -1):
            msg = self.state.messages[i]
            if msg.get("role") == "assistant" and self._parse_action_block_from_message(msg.get("content", "")) is not None:
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

    def _parse_action_block_from_message(self, content: str) -> Optional[ParsedActionBlock]:
        parsed = self.protocol_manager.parse_response(content)
        if parsed.response_type == "action":
            return parsed.action_block
        return None

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
            
            if role == "assistant" and self._parse_action_block_from_message(content) is not None:
                # 处理包含 ACTION 块的 assistant 消息
                content_parts = []
                
                # 解析 ACTION 块
                action_block = self._parse_action_block_from_message(content)
                if action_block:
                    # 提取 ACTION 之前的文本
                    action_pos = min([p for p in [content.find("@SPORE:ACTION_SINGLE_START"), content.find("@SPORE:ACTION_SEQUENCE_START"), content.find("@SPORE:ACTION_PARALLEL_START")] if p >= 0], default=-1)
                    if action_pos > 0:
                        prefix = content[:action_pos].strip()
                        if prefix:
                            content_parts.append(prefix)
                    
                    # 简化参数显示
                    args_str = str([a.parameters for a in action_block.actions])
                    if len(args_str) > 200:
                        args_str = args_str[:200] + "..."
                    _first = action_block.first_action
                    _tool_name = _first.tool_name if _first is not None else "unknown"
                    content_parts.append(f"[执行操作: {_tool_name}({args_str})]")
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

        1. 清掉历史中的空消息 —— 空 assistant 消息会让之后每一轮请求都被 400 拒掉
        2. 检查是否有 assistant 消息包含 ACTION 块但没有对应的 RESULT 响应
        """
        dropped = self.state.drop_blank_messages()
        if dropped:
            log_error(
                "HISTORY_BLANK_MESSAGES_DROPPED",
                f"从对话历史中清理了 {dropped} 条空消息",
                context={"remaining": len(self.state.messages)},
            )

        for i in range(len(self.state.messages) - 1, -1, -1):
            msg = self.state.messages[i]
            if msg.get("role") == "assistant":
                content = msg.get("content", "")
                # 检查是否包含 ACTION 块
                if self._parse_action_block_from_message(content) is not None:
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
    
    # 空回复的协议层重试上限。
    # chat 进程内部已按 API 层重试过一次（_MAX_EMPTY_ATTEMPTS），但那是**同一份请求**
    # 原样重发；空回复多半是"思考把输出额度吃光、一个正文块都没产出"，只有把
    # format_empty_response 反馈注入历史、让请求内容真的变了，模型才有机会换个输出
    # 方式。每次重试都要付全额 token（且会与 chat 进程的重试相乘），所以必须有界。
    MAX_EMPTY_RESPONSE_RETRIES = 2

    def send_chat_request(
        self,
        conversation_id: Optional[str] = None,
        expected_epoch: Optional[int] = None,
    ) -> Optional[Dict]:
        """
        发送聊天请求并获取响应（空回复在协议层做有界重试）

        对调用方的契约不变：要么返回一条含正文的成功响应，要么返回 None
        （中断 / API 错误 / 模型拒答 / 空回复重试耗尽）。空回复的重试之所以放在
        这一层而不是交给调用方，是因为只有这里同时握着 interrupt_epoch 与对话历史：
        重试前必须校验中断世代，注入的反馈也必须能在放弃本轮时原样撤掉。

        参数:
            conversation_id: 会话ID，用于绑定 request_id（Desktop 模式）
            expected_epoch: 期望的中断世代。与 state.interrupt_epoch 不一致说明本轮
                已被用户中断，不再重试（CLI 不传，靠 Ctrl+C 的 KeyboardInterrupt 打断）。

        返回:
            响应字典，如果失败或中断返回None
        """
        # 新的用户轮次开始时清掉上一轮残留的连续截断计数
        self._reset_round_streaks()

        # 本方法注入历史的反馈消息（按对象身份记录）。放弃本轮时原样撤掉：
        # 一轮连正文都没拿到、却在历史里留下"请重新输出"的反馈是纯噪音；Desktop 侧
        # 的 _rollback_interrupted_round 本来也会把它回滚，CLI 与之保持一致。
        injected_feedback: list = []
        empty_attempt = 0

        while True:
            response = self._send_chat_request_once(
                conversation_id=conversation_id,
                expected_epoch=expected_epoch,
                # 规则提醒只在首次尝试时追加：llm_reply_count 在重试期间不变，
                # 每次重试都追加会把同一段提醒往历史里反复堆。
                inject_rule_reminder=(empty_attempt == 0),
            )

            if response is None or response.get("status") == "cancelled":
                print("Spore> 对话中断，请继续")
                self._drop_injected_feedback(injected_feedback)
                return None

            status = response.get("status")

            if status == "error":
                error_msg = response.get('data')
                print(f"Spore> [错误] {error_msg}")
                log_error("LLM_API_ERROR", f"Chat process returned error: {error_msg}")
                self._drop_injected_feedback(injected_feedback)
                return None

            # refusal：模型明确拒答，重发同样的历史只会拿到同样的拒答，不重试。
            if status == "refusal":
                self._log_no_usable_reply(status, response)
                print("Spore> [提示] 模型拒绝回答本轮请求，请补充说明或换个问法后重试")
                self._drop_injected_feedback(injected_feedback)
                return None

            # empty_response：一个正文块都没收到。绝不能把空内容写进历史（写进去
            # 之后每一轮请求都会被 API 以"消息为空或无效"400 拒掉），改为注入
            # @SPORE:RESULT 反馈后重发，让模型知道上一轮的输出丢了。
            if status == "empty_response":
                empty_attempt += 1
                self._log_no_usable_reply(status, response, attempt=empty_attempt)

                if empty_attempt > self.MAX_EMPTY_RESPONSE_RETRIES:
                    print(
                        f"Spore> [提示] 模型连续 {empty_attempt} 次未返回任何内容，已停止本轮。"
                        f"建议提高 MAX_OUTPUT_TOKENS 或降低思考预算后重试"
                    )
                    self._drop_injected_feedback(injected_feedback)
                    return None

                # 中断优先于重试：重试会用新的 request_id，之前 interrupt 打下的
                # tombstone 拦不住它，必须在这里显式停手。
                if self._round_interrupted(expected_epoch):
                    self._drop_injected_feedback(injected_feedback)
                    return None

                print(
                    f"Spore> [提示] 模型未返回任何内容，正在重试"
                    f"（{empty_attempt}/{self.MAX_EMPTY_RESPONSE_RETRIES}）..."
                )
                feedback = {
                    "role": "user",
                    "content": self.protocol_manager.format_empty_response(attempt=empty_attempt),
                }
                self.state.messages.append(feedback)
                injected_feedback.append(feedback)
                continue

            # Desktop 模式：从响应中提取 usage 并更新 state 的 token 统计
            if os.environ.get('SPORE_DESKTOP_MODE') == '1':
                reply_data = response.get("data", {})
                usage = reply_data.get("usage", {})
                if usage:
                    # Chat 进程已把各 SDK 的 usage 规范化为这两个 API 字段；
                    # Desktop 统计直接使用它们，避免别名回退造成重复或口径漂移。
                    input_tokens = usage.get("input_tokens", 0)
                    output_tokens = usage.get("output_tokens", 0)
                    # context_tokens 含缓存命中，是判断上下文规模的唯一可靠口径
                    context_tokens = usage.get("context_tokens", 0) or input_tokens
                    if input_tokens > 0 or output_tokens > 0:
                        self.state.update_token_stats(input_tokens, output_tokens, context_tokens)

            return response

    def _round_interrupted(self, expected_epoch: Optional[int]) -> bool:
        """本轮是否已被用户中断（仅 Desktop 传 expected_epoch；CLI 走 KeyboardInterrupt）。"""
        if expected_epoch is None:
            return False
        return getattr(self.state, "interrupt_epoch", expected_epoch) != expected_epoch

    def _drop_injected_feedback(self, injected: list) -> None:
        """撤掉本轮注入的反馈消息。

        只在反馈消息仍处于历史末尾（且是同一个对象）时弹出；中途若已追加了别的
        消息就立即停手 —— 宁可在历史里留一条噪音，也不能误删真实内容。
        """
        while injected:
            message = injected.pop()
            if self.state.messages and self.state.messages[-1] is message:
                self.state.messages.pop()
            else:
                break

    def _log_no_usable_reply(
        self,
        status: str,
        response: Dict[str, Any],
        attempt: Optional[int] = None,
    ) -> None:
        """记录"没拿到可用正文"的诊断上下文；失败静默，不挡主流程。"""
        try:
            data = response.get("data") or {}
            context = {
                "api_stop_reason": data.get("api_stop_reason"),
                "finish_state": data.get("finish_state"),
                "usage": data.get("usage"),
                "max_tokens": data.get("max_tokens"),
            }
            if attempt is not None:
                context["protocol_retry_attempt"] = attempt
                context["protocol_retry_limit"] = self.MAX_EMPTY_RESPONSE_RETRIES
            log_error(
                "LLM_NO_USABLE_REPLY",
                f"Chat process returned status={status}",
                context=context,
            )
        except Exception:
            pass

    def _send_chat_request_once(
        self,
        conversation_id: Optional[str] = None,
        expected_epoch: Optional[int] = None,
        inject_rule_reminder: bool = True,
    ) -> Optional[Dict]:
        """发起一次请求并等待响应，原样返回 chat 进程的结果（不解释 status）。

        状态语义的处理全部留给 send_chat_request，这样"要么真实响应、要么 None"
        的对外契约只有一个地方在维护。
        """
        # 每次请求前重新加载 system_prompt，确保动态内容（TODO、角色、目录等）是最新的
        from .prompt_loader import load_system_prompt
        from .tools import TOOL_DEFINITIONS
        
        base_prompt = load_system_prompt()
        current_tool_names = self._get_current_tool_names()

        # 检查是否需要注入规则提醒（防止长对话遗忘）
        # 基于 LLM 回复次数触发
        from .rule_reminder import should_remind, get_rule_reminder
        if inject_rule_reminder and should_remind(self.state.llm_reply_count, self.config.rule_reminder_interval):
            reminder = get_rule_reminder(
                short=self.config.rule_reminder_short,
                tool_names=current_tool_names,
            )
            # 将提醒追加到最后一条用户消息中
            if self.state.messages and self.state.messages[-1]["role"] == "user":
                self.state.messages[-1]["content"] += f"\n\n{reminder}"

        if base_prompt:
            # Use filtered tool definitions (mode baseline + session policy, sub-tools)
            tool_definitions = self._get_current_tool_definitions()
            
            # 注入 Learning 系统的历史上下文（情景记忆检索）
            learning_context = ""
            if self.retriever is not None and self.state.messages:
                try:
                    # 获取最后一条用户消息作为查询
                    last_user_msg = next((m for m in reversed(self.state.messages) if m["role"] == "user"), None)
                    if last_user_msg:
                        user_query = last_user_msg["content"]
                        # 记录任务开始的查询（用于后续记录）
                        if not self._task_start_query:
                            self._task_start_query = user_query
                            self._task_start_time = time.time()
                        
                        # 检索相关历史（限制3条，避免占用过多token）
                        learning_context = self.retriever.get_injection_context(
                            user_query=user_query,
                            task_type="general_task",
                            max_episodes=3
                        )
                        if learning_context:
                            learning_context = f"\n\n## 相关历史经验\n{learning_context}\n"
                except Exception as e:
                    log_error("LEARNING_RETRIEVAL_ERROR", f"Failed to retrieve learning context: {e}", e)
            
            current_system_prompt = self.protocol_manager.inject_protocol(
                base_prompt + learning_context,
                tool_definitions,
            )
        else:
            current_system_prompt = self.system_prompt
        
        # 生成带会话 ID 的 request_id（Desktop 模式）
        import uuid
        if conversation_id:
            request_id = f"{conversation_id}_{uuid.uuid4()}"
        else:
            request_id = str(uuid.uuid4())
        
        # 在请求入队前公布精确 ID，确保 interrupt 与 enqueue 并发时也能先写 tombstone。
        with self._request_id_lock:
            self._current_request_id = request_id

        if expected_epoch is not None and self.state.interrupt_epoch != expected_epoch:
            self.ipc_manager.cancel_request(request_id)

        try:
            stream_enabled = bool(getattr(self.config, "llm_stream_enabled", True))

            def _on_stream(data: Dict[str, Any]) -> None:
                self._emit_event("llm_chunk", data)

            request_id = self.ipc_manager.send_chat_request(
                messages=self.state.messages,
                model=self.config.get_model(),
                system=current_system_prompt,
                tool_calls=False,
                tools=None,
                request_id=request_id,
                stream=stream_enabled,
                stream_callback=_on_stream if stream_enabled else None,
            )
            response = self.ipc_manager.get_chat_response(request_id=request_id)
        finally:
            with self._request_id_lock:
                if self._current_request_id == request_id:
                    self._current_request_id = None

        return response

    def _execute_single_action(self, action: ParsedAction) -> Dict[str, Any]:
        """Execute one parsed tool call, emit a tool_result event, and return a structured status."""
        execution = self._execute_single_action_impl(action)
        self._emit_event("tool_result", {
            "tool_name": execution.get("tool_name"),
            "status": execution.get("status"),
        })
        return execution

    def _execute_single_action_impl(self, action: ParsedAction) -> Dict[str, Any]:
        """Execute one parsed tool call and return a structured status."""
        tool_name = action.tool_name
        args = action.parameters

        # Session/mode tool policy guard (top-level + sub-tools)
        try:
            from .tool_policy import check_action_allowed
            mode, policy = self._get_session_tool_policy()
            denied = check_action_allowed(tool_name, args or {}, mode, policy)
            if denied:
                log_tool_error(
                    tool_name,
                    denied,
                    args,
                    context={"mode": mode, "policy_denied": True},
                )
                return {
                    "status": "error",
                    "tool_name": tool_name,
                    "arguments": args,
                    "error": denied,
                }
        except Exception as policy_err:
            return {
                "status": "error",
                "tool_name": tool_name,
                "arguments": args,
                "error": f"Tool policy check failed: {policy_err}",
            }

        handler = TOOL_HANDLERS.get(tool_name)

        if handler is None:
            log_tool_error(
                tool_name,
                "Tool handler not found",
                args,
                context={"available_tools": list(TOOL_HANDLERS.keys()), "requested_tool": tool_name},
            )
            return {"status": "error", "tool_name": tool_name, "arguments": args, "error": f"Tool not found: {tool_name}"}

        # 安全守卫：execute_command 执行前做两阶段风险检测（阻塞式）
        # 未命中高危策略的命令由守卫内部转交安全 Agent 异步研判意图+恶意
        if tool_name == "execute_command":
            try:
                from .security_guard import guard_shell_command
                session_id = self._conversation_id_for_context()
                epoch = getattr(self.state, "interrupt_epoch", None)
                denied_by_guard = guard_shell_command(
                    args or {}, emit=self._emit_event,
                    session_id=session_id, interrupt_epoch=epoch,
                )
            except Exception as guard_err:
                log_error("SECURITY_GUARD_ERROR", f"安全守卫检测异常: {guard_err}", guard_err)
                denied_by_guard = None
            if denied_by_guard:
                return {
                    "status": "error",
                    "tool_name": tool_name,
                    "arguments": args,
                    "error": denied_by_guard,
                }

        # 备份钩子：文件写操作前记录原始内容（操作后哈希对比，变化才备份）
        backup_token = None
        try:
            from .backup_manager import get_backup_manager
            backup_token = get_backup_manager().before_tool(tool_name, args or {})
        except Exception as backup_err:
            log_error("BACKUP_HOOK_ERROR", f"备份钩子(before)异常: {backup_err}", backup_err)

        try:
            no_timeout_tools = ["multi_agent_dispatch", "file"]
            if tool_name == "execute_command":
                try:
                    if int((args or {}).get("timeout")) == 0:
                        no_timeout_tools.append(tool_name)
                except (TypeError, ValueError):
                    pass
            timed_out = False

            if tool_name in no_timeout_tools:
                tool_result = handler(args)
            else:
                tool_timeout = self.config.tool_execution_timeout
                current_agent_id = get_current_agent_id() or "main_agent"

                parent_context = contextvars.copy_context()

                def execute_with_agent_id():
                    set_current_agent_id(current_agent_id)
                    return parent_context.run(handler, args)

                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(execute_with_agent_id)
                    try:
                        tool_result = future.result(timeout=tool_timeout)
                    except FuturesTimeoutError:
                        future.cancel()
                        timed_out = True
                        tool_result = None
                        log_tool_error(tool_name, "Tool execution timeout", args)

            if tool_result is None:
                if timed_out:
                    return {"status": "timeout", "tool_name": tool_name, "arguments": args, "error": f"Tool timed out: {tool_name}"}
                return {"status": "interrupted", "tool_name": tool_name, "arguments": args, "error": f"Tool interrupted: {tool_name}"}

            self._log_tool_result(tool_name, tool_result, args)
            return {"status": "success", "tool_name": tool_name, "arguments": args, "result": tool_result}
        except Exception as e:
            log_tool_error(tool_name, f"Tool execution failed: {str(e)}", args, e)
            return {"status": "error", "tool_name": tool_name, "arguments": args, "error": str(e)}
        finally:
            # 备份钩子：操作后对比哈希，内容变化才记录版本（含删除）
            if backup_token is not None:
                try:
                    from .backup_manager import get_backup_manager
                    get_backup_manager().after_tool(backup_token)
                except Exception as backup_err:
                    log_error("BACKUP_HOOK_ERROR", f"备份钩子(after)异常: {backup_err}", backup_err)

    def _format_single_execution_result(self, execution: Dict[str, Any]) -> str:
        status = execution.get("status")
        tool_name = execution.get("tool_name")
        if status == "success":
            return self.protocol_manager.format_result(execution.get("result"), tool_name)
        if status == "interrupted":
            return self.protocol_manager.format_interrupt(tool_name)
        return self.protocol_manager.format_error(execution.get("error", "Tool execution timeout"), tool_name)

    def handle_action_block(
        self,
        action_block: ParsedActionBlock,
        prefix_text: Optional[str] = None,
        full_reply: Optional[str] = None,
        protocol_warning: Optional[str] = None,
    ) -> Optional[str]:
        """Execute ACTION_SINGLE, ACTION_SEQUENCE, or ACTION_PARALLEL."""
        self._emit_event("tool_call", {
            "tool_name": action_block.first_action.tool_name if action_block.first_action else "",
            "mode": action_block.mode,
            "tool_names": [a.tool_name for a in action_block.actions],
        })

        # 块级批量意图分析：块内多条 shell 命令合并为一次 LLM 研判（异步、不阻塞执行）。
        # 单条命令仍走 guard 内的逐条分析路径；已认领的命令 guard 会自动跳过。
        shell_commands = [
            a.parameters.get("command") for a in action_block.actions
            if a.tool_name == "execute_command"
            and isinstance(a.parameters.get("command"), str)
        ]
        if len(shell_commands) >= 2:
            try:
                from AutoAgent.security_agent import analyze_commands_async
                session_id = self._conversation_id_for_context()
                epoch = getattr(self.state, "interrupt_epoch", None)
                analyze_commands_async(
                    shell_commands, self._emit_event,
                    session_id=session_id, interrupt_epoch=epoch,
                )
            except Exception as e:
                log_error("SECURITY_AGENT_DISPATCH_ERROR", "批量意图研判派发失败", e)

        last_todo_content = get_last_todo_content()
        if last_todo_content != "":
            clear_todo_block(last_todo_content)
            clear_last_todo_content()

        if prefix_text:
            content = self._filter_todo_block(prefix_text)
            if content:
                if content.endswith(":") or content.endswith("?"):
                    content = content[:-1] + "?"
                safe_print(f"{_config.current_agent_name}> {content}")

        first_tool = action_block.first_action.tool_name if action_block.first_action else ""
        if _config.current_agent_name == "Spore" and first_tool != "multi_agent_dispatch":
            todo_print()

        assistant_content = full_reply or (prefix_text + "\n\n" + action_block.raw_text if prefix_text else action_block.raw_text)
        self.state.messages.append({"role": "assistant", "content": assistant_content})

        def _execute_in_block_mode(action: ParsedAction) -> Dict[str, Any]:
            token = CURRENT_ACTION_BLOCK_MODE.set(action_block.mode)
            try:
                return self._execute_single_action(action)
            finally:
                CURRENT_ACTION_BLOCK_MODE.reset(token)

        should_break = False
        if action_block.mode == "single":
            execution = _execute_in_block_mode(action_block.first_action)
            result_text = self._format_single_execution_result(execution)
            should_break = execution.get("status") == "interrupted"
            if (
                execution.get("status") == "success"
                and execution.get("tool_name") == "multi_agent_dispatch"
            ):
                try:
                    dispatch_payload = json.loads(execution.get("result") or "")
                except (TypeError, ValueError):
                    dispatch_payload = None
                if (
                    isinstance(dispatch_payload, dict)
                    and dispatch_payload.get("dispatch_mode") == "async"
                ):
                    # 派发 RESULT 已写入历史后直接结束当前任务，不再额外请求一轮 LLM。
                    should_break = True
                    self.state.last_answer = ""

        elif action_block.mode == "sequence":
            results = []
            stopped_at = None
            for action in action_block.actions:
                execution = _execute_in_block_mode(action)
                step_result = {
                    "step": action.step_index,
                    "tool_name": action.tool_name,
                    "status": execution.get("status"),
                }
                if "result" in execution:
                    step_result["result"] = execution["result"]
                if "error" in execution:
                    step_result["error"] = execution["error"]
                results.append(step_result)

                if execution.get("status") != "success":
                    stopped_at = action.step_index
                    should_break = execution.get("status") == "interrupted"
                    break

            result_text = self.protocol_manager.format_result({
                "mode": "sequence",
                "stop_on_error": True,
                "stopped_at": stopped_at,
                "results": results,
            }, "ACTION_SEQUENCE")

        else:
            results = {}
            max_workers = max(1, len(action_block.actions))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for action in action_block.actions:
                    ctx = contextvars.copy_context()
                    futures.append((executor.submit(ctx.run, _execute_in_block_mode, action), action))
                for future, action in futures:
                    execution = future.result()
                    task_id = action.task_id or action.tool_name
                    entry = {
                        "task_id": task_id,
                        "tool_name": action.tool_name,
                        "status": execution.get("status"),
                    }
                    if "result" in execution:
                        entry["result"] = execution["result"]
                    if "error" in execution:
                        entry["error"] = execution["error"]
                    results[task_id] = entry
                    if execution.get("status") == "interrupted":
                        should_break = True

            result_text = self.protocol_manager.format_result({"mode": "parallel", "results": results}, "ACTION_PARALLEL")

        result_text = self.protocol_manager.append_protocol_warning(result_text, protocol_warning)
        self.state.messages.append({"role": "user", "content": result_text})
        self._check_and_handle_oversized_tool_result()
        self.state.save_temp_messages()
        # 工具执行完成后实时更新该会话短记忆
        auto_save_messages(self.state.messages, session_id=self._conversation_id_for_context())

        return "break" if should_break else "continue"

    def _get_tool_names_list(self) -> str:
        """
        获取工具名称列表（只列名称）
        
        Returns:
            工具名称列表字符串
        """
        tool_names = self._get_current_tool_names()
        return "\n".join(f"- {name}" for name in tool_names)
    
    def _filter_todo_block(self, text: str) -> str:
        """
        过滤掉文本中的 TODO 协议块
        
        Args:
            text: 原始文本
            
        Returns:
            过滤后的文本
        """
        if not text or "@SPORE:TODO_START" not in text:
            return text
        
        # 找到 TODO 块的位置
        todo_pos = text.find("@SPORE:TODO_START")
        
        # TODO 块之前的内容
        before_todo = text[:todo_pos].strip()
        
        # TODO 块之后的内容（找到下一个 ### 或结束）
        after_todo_start = todo_pos + len("@SPORE:TODO_START")
        remaining = text[after_todo_start:]
        
        # 找到 TODO 块的结束位置（使用 @SPORE:TODO_END 标记）
        _end_marker = "@SPORE:TODO_END"
        next_section = remaining.find(_end_marker)
        if next_section >= 0:
            after_todo = remaining[next_section + len(_end_marker):].strip()
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
            todo_write(tasks, session_id=self._conversation_id_for_context())
            self._emit_event("todo_update", {"tasks": tasks})
    
    # 连续截断上限：超过就停下来交还给用户，避免"截断→重发→再截断"无限烧 token
    MAX_TRUNCATION_STREAK = 3

    # 连续截断计数与它所属的用户轮次。
    # 必须写成类属性：Desktop 的 SessionConversationLoop 不调用本类 __init__，
    # 放在 __init__ 里对它等于不存在（这也是下面仍用 getattr 兜底的原因）。
    _truncation_streak: int = 0
    _streak_user_seq: Optional[int] = None

    def _reset_round_streaks(self) -> None:
        """用户开启新一轮对话时，清掉上一轮残留的连续截断计数。

        _handle_truncated_reply 只在"收到完整回复"和"达到上限"两处重置计数。
        若上一轮在计数未清零时因中断/API 错误提前结束，残留的计数会让新一轮第一次
        截断就直接撞上限、白白终止本轮。以用户消息条数的变化作为新轮次的判据
        （追加 RESULT / 反馈这类系统消息不会改变它）。诊断类逻辑，失败静默。
        """
        try:
            seq = getattr(self.state, "user_message_count", None)
            if seq is None:
                return
            if self._streak_user_seq != seq:
                self._streak_user_seq = seq
                self._truncation_streak = 0
        except Exception:
            pass

    def _handle_truncated_reply(
        self,
        reply: str,
        parsed: "ParsedResponse",
        meta: Dict[str, Any],
    ) -> str:
        """处理被输出上限截断的回复。

        关键点：
        - 不执行其中的 ACTION。半截的 CONTENT 参数会把被砍断的内容写进文件。
        - 保留这条不完整的助手回复。删掉它，模型只能从头重写整份内容，
          必然再次撞上限；留着它，模型才能"接着上次的位置继续写"。
        - 反馈用 OutputTruncated 而非 ProtocolError。报成协议错误会让模型以为
          自己标识符写错了，从而原样重发同一份超长内容 —— 这正是死循环的成因。
        - 连续截断到上限就停手，把决定权交还用户。
        """
        streak = getattr(self, "_truncation_streak", 0) + 1
        self._truncation_streak = streak

        log_error(
            "LLM_REPLY_TRUNCATED",
            f"LLM 回复被截断（连续第 {streak} 次）",
            context={
                "api_stop_reason": meta.get("api_stop_reason"),
                "finish_state": meta.get("finish_state"),
                "truncation_source": meta.get("truncation_source"),
                "truncation_hint": meta.get("truncation_hint"),
                "usage": meta.get("usage"),
                "max_tokens": meta.get("max_tokens"),
                "reply_length": len(reply or ""),
            },
        )

        if parsed.reply_content:
            safe_print(f"{_config.current_agent_name}> {parsed.reply_content}")

        if streak >= self.MAX_TRUNCATION_STREAK:
            safe_print(
                f"{_config.current_agent_name}> [提示] 回复连续 {streak} 次被输出上限截断，已停止本轮。"
                f"建议提高 MAX_OUTPUT_TOKENS，或把任务拆小后重试。"
            )
            self._truncation_streak = 0
            self.state.add_assistant_message(reply)
            auto_save_messages(self.state.messages, session_id=self._conversation_id_for_context())
            self.state.last_answer = ""
            return "break"

        result_text = self.protocol_manager.format_truncated(
            attempt=streak,
            api_stop_reason=meta.get("api_stop_reason"),
            max_output_tokens=meta.get("max_tokens"),
        )
        # 助手回复写不进历史（空内容被 add_assistant_message 拒掉）时绝不能只追加
        # RESULT：那会让历史里出现一条无主的反馈，模型完全不知道在说哪次输出。
        # 正常路径下 reply 已被 validate_and_check_response 保证非空，这里只兜底。
        if not self.state.add_assistant_message(reply):
            log_error(
                "TRUNCATED_REPLY_NOT_RECORDED",
                "截断回复内容为空，未写入历史，本轮直接结束",
                context={"api_stop_reason": meta.get("api_stop_reason")},
            )
            self._truncation_streak = 0
            self.state.last_answer = ""
            return "break"
        self.state.messages.append({"role": "user", "content": result_text})
        auto_save_messages(self.state.messages, session_id=self._conversation_id_for_context())
        return "continue"

    def validate_and_check_response(
        self,
        reply: str,
        reply_meta: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        验证响应并检查状态（文本协议版本）

        使用 ProtocolManager 解析响应，检测 ACTION、STOP_REASON 或继续状态
        同时解析 TODO 块并更新任务状态

        参数:
            reply: LLM响应内容
            reply_meta: chat 进程给出的健康信息（truncated / api_stop_reason /
                finish_state / usage / max_tokens）。缺省表示传输状态未知；
                协议结构仍由 ProtocolManager 独立校验。

        返回:
            如果需要中断循环返回 "break"，如果需要继续返回 "continue"，否则返回 None
        """
        meta = reply_meta or {}

        # 空回复：绝不能写进历史（写进去会让后续每一轮都被 400 拒掉），
        # 也没有任何可解析内容，直接结束本轮交还用户。
        if not reply or not reply.strip():
            log_error(
                "EMPTY_LLM_REPLY",
                "LLM 返回空回复，已丢弃且未写入对话历史",
                context={
                    "api_stop_reason": meta.get("api_stop_reason"),
                    "finish_state": meta.get("finish_state"),
                    "usage": meta.get("usage"),
                },
            )
            safe_print(f"{_config.current_agent_name}> [提示] 模型未返回任何内容，本轮已跳过，请重试或换个问法")
            self.state.last_answer = ""
            return "break"

        # 解析并更新 TODO（如果 LLM 回复中包含 TODO 协议块）
        self._update_todo_from_response(reply)

        # 使用 ProtocolManager 解析响应（把 API 层的截断结论一并交给协议层，
        # 否则未闭合的协议块会被误报成"标识符写错了"）
        truncated_flag = meta.get("truncated") if "truncated" in meta else None
        parsed = self.protocol_manager.parse_response(reply, truncated=truncated_flag)

        # 截断处理必须在 ACTION 执行之前：半截的 CONTENT 块一旦被当作正常参数执行，
        # 会把被砍断的内容真的写进文件。
        is_truncated = bool(parsed.truncated)
        if is_truncated:
            return self._handle_truncated_reply(reply, parsed, meta)

        # 正常回复：重置连续截断计数
        self._truncation_streak = 0

        # 特殊值，表示上次有 ACTION
        ACTION_STATE_MARKER = "__ACTION__"

        if parsed.response_type == "action":
            if parsed.action_block is None:
                result_text = self.protocol_manager.format_parse_error("ACTION 块解析失败")
                self.state.messages.append({"role": "assistant", "content": reply})
                self.state.messages.append({"role": "user", "content": result_text})
                auto_save_messages(self.state.messages, session_id=self._conversation_id_for_context())
                return "continue"
            # 有 ACTION 块，执行工具
            self._no_action_count = 0  # 重置无 ACTION 计数器
            # 标记本次有 ACTION
            self.state.last_answer = ACTION_STATE_MARKER
            # 如果有 REPLY 内容，先显示
            if parsed.reply_content:
                safe_print(f"{_config.current_agent_name}> {parsed.reply_content}")
            # 对话点快照：登记本轮上下文（message_count 为回复追加前的消息数），
            # 仅当 ACTION 实际改动了被跟踪文件时才提交为 checkpoint，
            # rewind 该点即回到"这条回复之前"
            from .backup_manager import get_backup_manager
            checkpoint_session = self._conversation_id_for_context() or "default"
            try:
                get_backup_manager().begin_round(
                    session_id=checkpoint_session,
                    message_count=len(self.state.messages),
                    llm_reply_count=self.state.llm_reply_count,
                    reply_preview=self._checkpoint_reply_preview(reply, parsed.reply_content),
                )
            except Exception as checkpoint_err:
                log_error("CHECKPOINT_ERROR", f"登记对话点快照失败: {checkpoint_err}", checkpoint_err)
            try:
                return self.handle_action_block(
                    parsed.action_block,
                    parsed.prefix_text,
                    reply,
                    protocol_warning=parsed.protocol_warning,
                )
            finally:
                try:
                    get_backup_manager().end_round(checkpoint_session)
                except Exception:
                    pass
        
        elif parsed.response_type == "protocol_error":
            result_text = self.protocol_manager.format_protocol_error(parsed.protocol_error)
            self.state.messages.append({
                "role": "assistant",
                "content": reply
            })
            self.state.messages.append({
                "role": "user",
                "content": result_text
            })
            auto_save_messages(self.state.messages, session_id=self._conversation_id_for_context())
            return "continue"
        
        elif parsed.response_type == "final":
            # 检测到 STOP_REASON，任务完成
            self._no_action_count = 0  # 重置无 ACTION 计数器
            # 优先显示 REPLY 内容，否则显示 prefix_text（过滤掉 TODO 块）
            display_text = parsed.reply_content
            if not display_text and parsed.prefix_text:
                display_text = self._filter_todo_block(parsed.prefix_text)
            if display_text:
                safe_print(f"{_config.current_agent_name}> {display_text}")
            
            # 添加 assistant 消息到对话历史（使用 add_assistant_message 增加计数）
            self.state.add_assistant_message(reply)

            # 回合完成：按会话 upsert 短记忆（最近 10 个会话）
            auto_save_messages(self.state.messages, session_id=self._conversation_id_for_context())
            
            # Learning 系统：记录任务执行结果
            if self.retriever is not None and self._task_start_query:
                try:
                    # 收集工具调用记录
                    tool_calls = []
                    for msg in self.state.messages:
                        if msg.get("role") == "assistant":
                            action = self._parse_action_block_from_message(msg.get("content", ""))
                            if action:
                                tool_calls.append({
                                    "tool": action.tool_name,
                                    "args": action.parameters
                                })
                    
                    # 记录任务执行
                    self.retriever.record_task_execution(
                        task_type="general_task",
                        user_query=self._task_start_query,
                        # ParsedResponse 上没有 stop_reason_text 字段，写它会在
                        # display_text 为空时抛 AttributeError（被下面的 except 吞掉，
                        # 表现为这条经验静默丢失）。终止原因的正确字段是 final_content。
                        output_data={"final_reply": display_text or parsed.final_content or ""},
                        outcome="success",
                        tool_calls=tool_calls,
                        salience=0.7  # 默认显著性
                    )
                except Exception as e:
                    log_error("LEARNING_RECORD_ERROR", f"Failed to record task execution: {e}", e)
                finally:
                    # 重置任务追踪
                    self._task_start_query = None
                    self._task_start_time = None

            # 清理状态
            self.state.restore_temp_messages()
            todo_write([], session_id=self._conversation_id_for_context())
            clear_last_todo_content()
            self.state.last_answer = ""  # 重置
            return "break"
        
        else:
            # continue 类型：既没有 ACTION 也没有 STOP_REASON
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
            
            # 如果存在协议warning，不调用supervisor，直接继续纠正
            if not parsed.protocol_warning:
                # 只有当上次和本次都没有 ACTION 时才调用 supervisor
                last = self.state.last_answer if self.state.last_answer else ""
                if last != ACTION_STATE_MARKER and last != "":
                    # 上次没有 ACTION，本次也没有 ACTION，调用 supervisor
                    if supervisor(last, current_answer):
                        should_end = True
            
            if should_end:
                # 检测到循环或结束，打印内容并结束
                if display_answer:
                    safe_print(f"{_config.current_agent_name}> {display_answer}")
                
                self.state.messages.append({
                    "role": "assistant",
                    "content": reply
                })

                # 回合完成（supervisor 判定结束）：按会话 upsert 短记忆
                auto_save_messages(self.state.messages, session_id=self._conversation_id_for_context())

                self.state.restore_temp_messages()
                todo_write([], session_id=self._conversation_id_for_context())
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
                safe_print(f"{_config.current_agent_name}> {display_answer}")
            
            # 显示 TODO（如果有）
            if _config.current_agent_name == "Spore":
                todo_print()
            
            # 更新 last_answer（本次没有 ACTION，记录回复内容）
            self.state.last_answer = current_answer
            
            # 添加 assistant 消息（使用 add_assistant_message 增加计数）
            recorded = self.state.add_assistant_message(reply)

            # 无工具可拼 RESULT 时，仍把软警告回给 LLM。
            # 只有助手回复真的写进历史才追加：否则历史里会多出一条无主的 user 消息，
            # 与前一条 user 消息连在一起，模型也看不懂在警告哪次输出。
            # （reply 非空已由上方空回复分支保证，这里是兜底。）
            if parsed.protocol_warning and recorded:
                self.state.messages.append({
                    "role": "user",
                    "content": f"[协议警告] {parsed.protocol_warning}",
                })
            
            # 多轮 ACTION/继续过程中也实时更新该会话短记忆
            auto_save_messages(self.state.messages, session_id=self._conversation_id_for_context())

            return "continue"
    
    def cancel_current_request(self) -> bool:
        """精确逻辑取消当前主请求，不影响其他会话或随后提交的请求。"""
        with self._request_id_lock:
            request_id = self._current_request_id
        return self.ipc_manager.cancel_request(request_id)

    def handle_keyboard_interrupt(self) -> None:
        """处理键盘中断"""
        print("\nInterrupt LLM...")
        clear_last_todo_content()
        todo_write([], session_id=self._conversation_id_for_context())

        self.cancel_current_request()

        # 清理打断时产生的残留消息
        self._cleanup_interrupted_messages()
        
        # 重置状态变量
        self.state.last_answer = ""
        self.state.current_answer = ""
        
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
            
            # 检查是否包含 STOP_REASON，说明是完整回复
            if has_stop_reason_marker(content):
                pass  # 保留完整的最终响应
            
            # 检查是否包含未完成的 ACTION 块
            elif self._parse_action_block_from_message(content) is not None:
                # 有 ACTION 但没有对应的 RESULT，移除
                self.state.messages.pop()
            
            # 空内容或不完整的响应
            elif not content.strip():
                self.state.messages.pop()
