"""
多Agent进程管理模块

管理多个子Agent线程的并发执行。
每个子Agent有独立的监控终端。
"""
import threading
import uuid
import time
import multiprocessing as mp
import logging
import json
import contextvars
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path

from .agent_types import AgentTypeConfig, get_agent_type
from .agent_database import SubAgentDatabase, AgentTask, MultiAgentResult, AgentStatus
from .event_signal import EventSignalManager, get_event_signal_manager
from .tools import TOOL_DEFINITIONS, TOOL_HANDLERS
from .logger import log_error, log_info, log_tool_error
from .multi_agent_monitor import create_agent_terminal, close_all_terminals, AgentTerminal
from .text_protocol import ProtocolManager, ParsedAction, ParsedActionBlock
from .utils import check_tool_result_error
from .session_context import get_current_conversation_id, conversation_context


# 全局IPC管理器引用
_ipc_manager = None

# 全局Agent管理器引用（用于中断）
_current_agent_manager = None


def set_ipc_manager(ipc_manager):
    """设置全局IPC管理器"""
    global _ipc_manager
    _ipc_manager = ipc_manager


def get_ipc_manager():
    """获取全局IPC管理器"""
    return _ipc_manager


def set_current_agent_manager(manager):
    """设置当前活动的Agent管理器"""
    global _current_agent_manager
    _current_agent_manager = manager


def get_current_agent_manager():
    """获取当前活动的Agent管理器"""
    return _current_agent_manager


# 按会话注册的Agent管理器（用于会话级中断，避免误伤其他会话的子Agent）
_agent_managers_by_conversation: Dict[str, "AgentProcessManager"] = {}
_conversation_registry_lock = threading.Lock()


def register_conversation_agent_manager(conversation_id: str, manager) -> None:
    """将Agent管理器登记到其所属会话（同会话后启动的派发覆盖前一个）"""
    with _conversation_registry_lock:
        _agent_managers_by_conversation[conversation_id] = manager


def unregister_conversation_agent_manager(conversation_id: str, manager) -> None:
    """注销会话的Agent管理器（仅当登记的仍是该实例时）"""
    with _conversation_registry_lock:
        if _agent_managers_by_conversation.get(conversation_id) is manager:
            _agent_managers_by_conversation.pop(conversation_id, None)


def terminate_conversation_agents(conversation_id: str) -> bool:
    """
    终止指定会话的所有子Agent（会话级中断）。

    与 terminate_all 不同：不发送全局终止信号、不中断IPC请求，
    只对该会话名下的子Agent置位 termination_event，不影响其他会话。

    Returns:
        bool: 该会话是否存在登记的Agent管理器
    """
    with _conversation_registry_lock:
        manager = _agent_managers_by_conversation.pop(conversation_id, None)
    if manager is None:
        return False
    manager.terminate_own_agents()
    return True


class SubAgentThread(threading.Thread):
    """
    子Agent工作线程
    
    遵循Coder模式，独立执行主Agent分派的任务。
    使用事件驱动的方式等待LLM响应。
    """
    
    def __init__(
        self,
        agent_id: str,
        task: str,
        agent_type: AgentTypeConfig,
        ipc_manager: Any,  # IPCManager
        database: SubAgentDatabase,
        event_manager: EventSignalManager,
        monitor_queue: Optional[mp.Queue] = None,
        max_iterations: int = 100,
        working_dir: Optional[str] = None,
        skill: Optional[str] = None,
        parent_conversation_id: Optional[str] = None
    ):
        """
        初始化子Agent线程
        
        Args:
            agent_id: Agent唯一标识
            task: 任务内容
            agent_type: Agent类型配置
            ipc_manager: IPC管理器
            database: Agent数据库
            event_manager: 事件信号管理器
            monitor_queue: 监控输出队列
            max_iterations: 最大迭代次数
            working_dir: 工作目录（绝对路径）
            skill: 指定使用的skill名称
        """
        super().__init__(name=f"SubAgent-{agent_id}", daemon=True)
        
        self.agent_id = agent_id
        self.conversation_id = str(uuid.uuid4())
        self.task = task
        self.agent_type = agent_type
        self.ipc_manager = ipc_manager
        self.database = database
        self.event_manager = event_manager
        self.termination_event = threading.Event()  # 每个子Agent独立的中断事件
        self.monitor_queue = monitor_queue  # 保留兼容性，但不再使用
        self.max_iterations = max_iterations
        self.working_dir = working_dir  # 工作目录
        self.skill = skill  # 指定使用的skill
        self.parent_conversation_id = parent_conversation_id
        
        # 构建工具定义字典（用于文本协议）
        self.tool_definitions = {name: TOOL_DEFINITIONS[name] for name in agent_type.tools_list if name in TOOL_DEFINITIONS}
        
        # 初始化文本协议管理器
        self.protocol_manager = ProtocolManager()
        
        # 系统提示词（注入文本协议说明）
        base_prompt = agent_type.prompt
        if not base_prompt:
            log_info(f"警告: Agent {agent_type.name} 的 prompt 为空，将只使用协议说明")
        self.system_prompt = self.protocol_manager.inject_protocol(base_prompt, self.tool_definitions)
        
        # 追加工作目录信息
        if self.working_dir:
            self.system_prompt += f"\n\n## 工作目录\n你的工作目录是: {self.working_dir}\n所有文件操作和输出都应该在此目录下进行。"
        
        # 追加指定skill信息
        if self.skill:
            self.system_prompt += f"\n\n## 指定Skill\n你将使用skill: `{self.skill}`\n请先调用 `skill_query` 工具查询该skill的用法。"
        
        # 对话历史
        self.messages: List[Dict[str, Any]] = []
        
        # Token 统计
        self.total_tokens_used = 0
        
        # 执行结果
        self.result: Optional[Dict[str, Any]] = None
        
        # 独立监控终端
        self.terminal: Optional[AgentTerminal] = None
        
        # 创建子Agent专用的日志记录器
        self._setup_agent_logger()
    
    def _setup_agent_logger(self):
        """为子Agent创建独立的日志文件（优先写到所属对话的日志目录）"""
        import logging
        from logging.handlers import RotatingFileHandler
        from pathlib import Path
        import os

        agents_dir = None
        try:
            from .logger import get_logger
            from .session_context import conversation_context
            if getattr(self, 'parent_conversation_id', None):
                with conversation_context(self.parent_conversation_id):
                    agents_dir = get_logger().get_active_log_dir() / "agents"
            else:
                agents_dir = get_logger().get_active_log_dir() / "agents"
        except Exception:
            agents_dir = None

        if agents_dir is None:
            session_dir_env = (
                os.environ.get('SPORE_CONVERSATION_LOG_DIR')
                or os.environ.get('SPORE_SESSION_LOG_DIR')
            )
            if not session_dir_env:
                self.agent_logger = None
                return
            agents_dir = Path(session_dir_env) / "agents"

        agents_dir.mkdir(parents=True, exist_ok=True)

        # 创建子Agent专用的日志文件
        log_file = agents_dir / f"{self.agent_id}.log"
        
        # 创建logger
        logger_name = f"subagent_{self.agent_id}"
        self.agent_logger = logging.getLogger(logger_name)
        self.agent_logger.setLevel(logging.DEBUG)
        self.agent_logger.propagate = False
        
        # 避免重复添加handler
        if not self.agent_logger.handlers:
            handler = RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=3,
                encoding='utf-8'
            )
            handler.setLevel(logging.DEBUG)
            
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.agent_logger.addHandler(handler)
    
    def _log_to_agent_file(self, message: str, level: str = "INFO"):
        """记录到子Agent专用日志文件"""
        if self.agent_logger:
            log_level = getattr(logging, level.upper(), logging.INFO)
            self.agent_logger.log(log_level, message)
    
    def log_output(self, message: str, level: str = "INFO"):
        """
        输出日志到独立监控终端
        
        Args:
            message: 日志消息
            level: 日志级别
        """
        if self.terminal:
            with conversation_context(self.parent_conversation_id):
                self.terminal.log(message, level)
    
    def start_terminal(self) -> None:
        """启动独立监控终端"""
        self.terminal = create_agent_terminal(self.agent_id, self.agent_type.name)
    
    def close_terminal(self, delay: float = 0) -> None:
        """
        关闭监控终端
        
        Args:
            delay: 延迟关闭时间（秒），0表示立即关闭
        """
        if self.terminal:
            if delay > 0:
                self.terminal.signal_complete()  # 发送完成信号，终端会延迟关闭
            else:
                self.terminal.signal_interrupt()  # 立即关闭
    
    def send_request_and_wait(self, messages: List[Dict]) -> Optional[Dict]:
        """
        发送请求并等待事件信号唤醒
        
        Args:
            messages: 消息列表
        
        Returns:
            Dict: 响应数据，如果被终止返回None
        """
        # 检查终止信号
        if self.termination_event.is_set():
            return None
        
        # 注册到事件管理器
        self.event_manager.register_agent(self.conversation_id)
        
        try:
            # 更新状态为等待
            self.database.set_status(AgentStatus.WAITING)
            
            # 发送请求到Chat Process（使用文本协议，不使用function calling）
            from .config import get_config
            config = get_config()
            
            # 记录请求信息到子Agent日志
            self._log_to_agent_file(
                f"发送LLM请求 (消息数: {len(messages)}, system长度: {len(self.system_prompt)})",
                "DEBUG"
            )
            
            request_id = self.ipc_manager.send_chat_request(
                messages=messages,
                model=config.get_sub_agent_model(),
                system=self.system_prompt,
                tool_calls=False,  # 文本协议不使用 function calling
                tools=None,
                request_id=self.conversation_id,
                use_sub_agent_config=True  # 使用子 agent 独立配置
            )
            
            # 等待响应（使用短超时循环，以便能够检查终止信号）
            while True:
                # 检查终止信号
                if self.termination_event.is_set():
                    return None
                
                # 使用短超时等待响应
                response = self.ipc_manager.get_chat_response(
                    request_id=self.conversation_id,
                    timeout=1  # 允许快速响应终止信号
                )
                
                if response is not None:
                    break
            
            # 从响应中获取 token 统计（从 LLM API 返回的 usage）
            if response and response.get("status") == "success":
                reply_data = response.get("data", {})
                reply_content = reply_data.get("content", "")
                usage = reply_data.get("usage", {})
                input_tokens = usage.get("input_tokens", 0) or usage.get("prompt_tokens", 0)
                output_tokens = usage.get("output_tokens", 0) or usage.get("completion_tokens", 0)
                
                # 更新 token 统计（input_tokens 就是完整的上下文，不需要累加）
                # total = context + output
                self.total_tokens_used = input_tokens + output_tokens
                
                # 记录响应状态
                self._log_to_agent_file(
                    f"收到响应 (状态: success, 内容长度: {len(reply_content)}, context: {input_tokens}, output: {output_tokens})",
                    "DEBUG"
                )
            else:
                # 记录异常响应
                self._log_to_agent_file(
                    f"收到异常响应: {response}",
                    "WARNING"
                )
            
            # 更新状态为运行
            self.database.set_status(AgentStatus.RUNNING)
            
            return response
            
        finally:
            # 注销
            self.event_manager.unregister_agent(self.conversation_id)
    
    def run(self):
        """执行子Agent任务（使用文本协议）"""
        # 整线程绑定父会话：日志/侧信道与主会话一致
        if self.parent_conversation_id:
            with conversation_context(self.parent_conversation_id):
                self._run_impl()
        else:
            self._run_impl()

    def _run_impl(self):
        """子Agent实际执行体"""
        # 设置当前线程的 agent_id（用于文件修改标志）
        from base.utils.system_io import set_current_agent_id
        set_current_agent_id(self.agent_id)
        
        # 启动独立监控终端
        self.start_terminal()
        
        self.database.set_status(AgentStatus.RUNNING)
        self.log_output(f"开始执行任务: {self.task[:100]}...")
        
        # 记录到子Agent专用日志
        import json
        task_info = json.dumps({
            'agent_type': self.agent_type.name,
            'task': self.task,
            'working_dir': self.working_dir,
            'skill': self.skill,
            'system_prompt_length': len(self.system_prompt),
            'tools_count': len(self.tool_definitions)
        }, ensure_ascii=False, indent=2)
        self._log_to_agent_file(f"开始执行任务\n{task_info}", "INFO")
        
        # 初始化消息
        self.messages = [{"role": "user", "content": self.task}]
        
        # 用于循环检测
        self._last_answer = ""
        
        iteration = 0
        completed = False
        try:
            while iteration < self.max_iterations:
                iteration += 1
                
                # 记录迭代开始
                self._log_to_agent_file(f"迭代 {iteration}/{self.max_iterations}", "INFO")
                
                # 检查终止信号
                if self.termination_event.is_set():
                    self.log_output("收到终止信号，停止执行")
                    self.database.set_status(AgentStatus.INTERRUPTED)
                    self._log_to_agent_file(f"被终止 (迭代 {iteration})", "WARNING")
                    return
                
                # 发送请求并等待响应
                response = self.send_request_and_wait(self.messages)
                
                if response is None:
                    self.log_output("响应为空，可能被终止")
                    self.database.set_status(AgentStatus.INTERRUPTED)
                    return
                
                if response.get("status") == "cancelled":
                    self.log_output("请求被取消")
                    self.database.set_status(AgentStatus.INTERRUPTED)
                    return
                
                if response.get("status") != "success":
                    error_msg = response.get("data", "未知错误")
                    self.log_output(f"请求失败: {error_msg}", "ERROR")
                    self.database.set_error(error_msg)
                    return
                
                # 处理响应（使用文本协议）
                reply_data = response.get("data", {})
                reply_content = reply_data.get("content", "")
                
                # 检查回复是否为空或只包含空白字符
                if not reply_content or not reply_content.strip():
                    self.log_output("收到空响应或纯空白响应", "WARNING")
                    self._log_to_agent_file(f"收到空响应: {repr(reply_content)}", "WARNING")
                    continue
                
                # 记录LLM完整回复到子Agent日志
                self._log_to_agent_file(f"LLM回复 (长度: {len(reply_content)})\n{reply_content}", "DEBUG")
                
                # 使用 ProtocolManager 解析响应
                parsed = self.protocol_manager.parse_response(reply_content)
                
                if parsed.response_type == "action":
                    if parsed.action_block is None:
                        self.messages.append({
                            "role": "assistant",
                            "content": reply_content
                        })
                        self.messages.append({
                            "role": "user",
                            "content": self.protocol_manager.format_parse_error("ACTION 块解析失败")
                        })
                        continue
                    result = self._handle_action_block(parsed.action_block, parsed.prefix_text, reply_content)
                    if result == "break":
                        return
                    # 重置循环检测
                    self._last_answer = ""
                    continue

                elif parsed.response_type == "protocol_error":
                    self.log_output(f"协议错误: {parsed.protocol_error.code}", "WARNING")
                    self._log_to_agent_file(
                        f"协议错误 (迭代 {iteration}) {parsed.protocol_error.code}: {parsed.protocol_error.message}\n回复内容: {reply_content}",
                        "WARNING"
                    )
                    self.messages.append({
                        "role": "assistant",
                        "content": reply_content
                    })
                    self.messages.append({
                        "role": "user",
                        "content": self.protocol_manager.format_protocol_error(parsed.protocol_error)
                    })
                    continue
                
                elif parsed.response_type == "final":
                    # 检测到 STOP_REASON，任务完成
                    if parsed.reply_content:
                        self.log_output(f"回复: {parsed.reply_content}")
                    
                    # 添加 assistant 消息到对话历史
                    self.messages.append({
                        "role": "assistant",
                        "content": reply_content
                    })
                    
                    self.log_output("任务完成", "SUCCESS")
                    self.database.set_completed(reply_content)
                    self.result = {"status": "completed", "result": reply_content}
                    completed = True
                    
                    # 记录任务完成到子Agent日志
                    self._log_to_agent_file(
                        f"任务完成 (迭代: {iteration}, Tokens: {self.total_tokens_used})\n结果: {reply_content}",
                        "INFO"
                    )
                    return
                
                else:
                    # continue 类型：既没有 ACTION 也没有 FINAL
                    current_answer = parsed.reply_content or parsed.prefix_text or reply_content.strip()
                    
                    # 过滤掉只包含 < 或 <<< 等不完整标记的情况
                    display_answer = ""
                    if current_answer and current_answer.strip('<> \n'):
                        # 移除末尾可能的不完整标记
                        display_answer = current_answer.rstrip('<').strip()
                    
                    # 输出回复内容
                    if display_answer:
                        self.log_output(f"回复: {display_answer}")
                    
                    # 使用 supervisor 检测循环
                    from AutoAgent.supervisor import supervisor
                    if self._last_answer and supervisor(self._last_answer, current_answer):
                        self.log_output("检测到循环回复，结束任务", "WARNING")
                        self.messages.append({
                            "role": "assistant",
                            "content": reply_content
                        })
                        self.database.set_completed(reply_content)
                        self.result = {"status": "completed", "result": reply_content}
                        completed = True
                        
                        # 记录循环检测到子Agent日志
                        self._log_to_agent_file(
                            f"检测到循环回复 (迭代 {iteration})\n上次: {self._last_answer}\n本次: {current_answer}",
                            "WARNING"
                        )
                        return
                    
                    # 更新 last_answer
                    self._last_answer = current_answer
                    
                    # 添加到消息历史
                    self.messages.append({
                        "role": "assistant",
                        "content": reply_content
                    })
                    
                    # 添加user消息提示继续执行
                    self.messages.append({
                        "role": "user",
                        "content": "请继续执行任务。如果需要使用工具，请输出 ACTION_SINGLE、ACTION_SEQUENCE 或 ACTION_PARALLEL 块；如果任务已完成，请输出 @SPORE:STOP_REASON=<自然语言终止原因>（不要再输出 REPLY 块）。"
                    })
                    
                    self._log_to_agent_file(
                        f"LLM未输出ACTION或STOP_REASON，提示继续执行",
                        "WARNING"
                    )
                    continue
            
            # 达到最大迭代次数
            self.log_output(f"达到最大迭代次数 ({self.max_iterations})", "WARNING")
            self.database.set_error(f"达到最大迭代次数限制 ({self.max_iterations})")
            
            # 记录到子Agent日志
            self._log_to_agent_file(
                f"达到最大迭代次数 ({self.max_iterations}), Tokens: {self.total_tokens_used}",
                "WARNING"
            )
            
        except Exception as e:
            self.log_output(f"执行异常: {e}", "ERROR")
            self._log_to_agent_file(f"执行异常 (迭代 {iteration}): {e}", "ERROR")
            log_error("SUB_AGENT_ERROR", f"SubAgent {self.agent_id} error", e, context={
                "agent_id": self.agent_id,
                "iteration": iteration,
                "task": self.task
            })
            self.database.set_error(str(e))
        
        finally:
            # 保存 token 统计到数据库
            self.database.total_tokens = self.total_tokens_used
            
            # 清空文件修改标志（无论是完成还是中断）
            from base.utils.system_io import clear_all_file_flags
            clear_all_file_flags(self.agent_id)
            
            # 关闭终端：完成时延迟2秒，中断时立即关闭
            if completed:
                self.close_terminal(delay=2)
            else:
                self.close_terminal(delay=0)
    
    def _check_and_log_tool_result_error(self, tool_name: str, tool_result: str, args: dict) -> None:
        """
        检查工具返回结果是否包含错误，如果有则记录到日志系统
        
        Args:
            tool_name: 工具名称
            tool_result: 工具返回的结果字符串
            args: 工具参数
        """
        is_error, error_msg = check_tool_result_error(tool_result)
        if is_error and error_msg:
            log_tool_error(
                tool_name, 
                f"工具返回错误: {error_msg}", 
                args,
                context={
                    "result": tool_result,
                    "result_length": len(tool_result) if isinstance(tool_result, str) else None,
                }
            )
            self.log_output(f"工具返回错误: {error_msg}", "WARNING")
    
    def _execute_single_action(self, action: ParsedAction, prefix_text: str = "") -> Dict[str, Any]:
        """执行一个工具调用并返回结构化状态。"""
        if self.parent_conversation_id and get_current_conversation_id() != self.parent_conversation_id:
            with conversation_context(self.parent_conversation_id):
                return self._execute_single_action(action, prefix_text)

        tool_name = action.tool_name
        args = action.parameters

        self.log_output(f"调用工具: {tool_name}")
        self.database.record_tool_call(
            tool_name=tool_name,
            arguments=args,
            llm_content=prefix_text or ""
        )
        
        # 记录工具调用到子Agent日志
        import json
        args_str = json.dumps(args, ensure_ascii=False, indent=2)
        self._log_to_agent_file(
            f"调用工具: {tool_name}\n参数:\n{args_str}",
            "INFO"
        )

        handler = TOOL_HANDLERS.get(tool_name)
        if handler is None:
            log_tool_error(tool_name, "未找到工具处理器", args,
                          context={"available_tools": list(TOOL_HANDLERS.keys()), "requested_tool": tool_name})
            return {"status": "error", "tool_name": tool_name, "arguments": args, "error": f"Tool not found: {tool_name}"}

        try:
            from base.utils.system_io import set_current_agent_id
            set_current_agent_id(self.agent_id)

            with conversation_context(self.parent_conversation_id):
                tool_result = handler(args)
            if tool_result is None:
                self.log_output("工具执行被中断")
                self.database.set_status(AgentStatus.INTERRUPTED)
                return {"status": "interrupted", "tool_name": tool_name, "arguments": args, "error": f"Tool interrupted: {tool_name}"}

            self._check_and_log_tool_result_error(tool_name, tool_result, args)
            result_preview = tool_result[:500] if isinstance(tool_result, str) and len(tool_result) > 500 else tool_result
            self._log_to_agent_file(
                f"工具执行完成: {tool_name}\n结果预览: {result_preview}",
                "INFO"
            )
            return {"status": "success", "tool_name": tool_name, "arguments": args, "result": tool_result}

        except Exception as e:
            log_tool_error(tool_name, f"工具执行异常: {str(e)}", args, e)
            self.log_output(f"工具执行异常: {e}", "ERROR")
            return {"status": "error", "tool_name": tool_name, "arguments": args, "error": str(e)}

    def _format_single_execution_result(self, execution: Dict[str, Any]) -> str:
        status = execution.get("status")
        tool_name = execution.get("tool_name")
        if status == "success":
            return self.protocol_manager.format_result(execution.get("result"), tool_name)
        if status == "interrupted":
            return self.protocol_manager.format_interrupt(tool_name)
        if status == "error" and str(execution.get("error", "")).startswith("Tool not found:"):
            return self.protocol_manager.format_not_found(tool_name)
        return self.protocol_manager.format_error(execution.get("error", "Tool execution failed"), tool_name)

    def _handle_action_block(
        self,
        action_block: ParsedActionBlock,
        prefix_text: str,
        full_reply: str,
    ) -> str:
        """处理 ACTION_SINGLE、ACTION_SEQUENCE 或 ACTION_PARALLEL 块。"""
        if prefix_text:
            self.log_output(f"说明: {prefix_text}")

        self.messages.append({
            "role": "assistant",
            "content": full_reply
        })

        should_break = False
        if action_block.mode == "single":
            execution = self._execute_single_action(action_block.first_action, prefix_text)
            result_text = self._format_single_execution_result(execution)
            should_break = execution.get("status") == "interrupted"

        elif action_block.mode == "sequence":
            results = []
            stopped_at = None
            for action in action_block.actions:
                execution = self._execute_single_action(action, prefix_text)
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
                    futures.append((executor.submit(ctx.run, self._execute_single_action, action, prefix_text), action))
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
        
        self.messages.append({
            "role": "user",
            "content": result_text
        })

        return "break" if should_break else "continue"
    
    def terminate(self) -> None:
        """中断此Agent"""
        self.termination_event.set()




class AgentProcessManager:
    """
    多Agent进程管理器
    
    管理多个子Agent线程的创建、执行和终止。
    """
    
    def __init__(self, ipc_manager: Any, monitor_queue: Optional[mp.Queue] = None):
        """
        初始化Agent进程管理器
        
        Args:
            ipc_manager: IPC管理器
            monitor_queue: 监控输出队列
        """
        self.ipc_manager = ipc_manager
        self.monitor_queue = monitor_queue
        self.event_manager = get_event_signal_manager()
        
        # 子Agent字典: agent_id -> SubAgentThread
        self.sub_agents: Dict[str, SubAgentThread] = {}
        # 数据库字典: agent_id -> SubAgentDatabase
        self.agent_databases: Dict[str, SubAgentDatabase] = {}

        # 所有Agent完成事件
        self.all_complete_event = threading.Event()

        # 锁
        self._lock = threading.Lock()

        # 开始时间
        self._start_time: Optional[float] = None

        # 所属会话 ID（派发时从会话上下文捕获，用于会话级中断）
        self.conversation_id: Optional[str] = None
    
    def dispatch_tasks(self, tasks: List[AgentTask]) -> str:
        """
        派发多个任务给子Agent
        
        Args:
            tasks: 任务列表
        
        Returns:
            str: 派发ID
        """
        dispatch_id = str(uuid.uuid4())
        self._start_time = time.time()
        self.all_complete_event.clear()

        # 设置为当前活动的管理器
        set_current_agent_manager(self)

        # 登记到所属会话（会话级中断用；desktop 模式下派发在 conversation_context 内执行）
        self.conversation_id = get_current_conversation_id()
        if self.conversation_id:
            register_conversation_agent_manager(self.conversation_id, self)
        
        with self._lock:
            for task in tasks:
                # 获取Agent类型配置
                if task.agent_type_config:
                    agent_type = task.agent_type_config
                else:
                    agent_type = get_agent_type(task.agent_type_name)
                    if agent_type is None:
                        log_error("AGENT_TYPE_NOT_FOUND", f"Agent type not found: {task.agent_type_name}")
                        continue
                
                # 创建数据库
                database = SubAgentDatabase(
                    agent_id=task.task_id,
                    agent_type_name=task.agent_type_name,
                    initial_task=task.task_content
                )
                self.agent_databases[task.task_id] = database
                
                # 创建子Agent线程（不再传递全局termination_event）
                agent_thread = SubAgentThread(
                    agent_id=task.task_id,
                    task=task.task_content,
                    agent_type=agent_type,
                    ipc_manager=self.ipc_manager,
                    database=database,
                    event_manager=self.event_manager,
                    monitor_queue=self.monitor_queue,
                    working_dir=task.working_dir,
                    skill=task.skill,  # 传递指定skill
                    parent_conversation_id=get_current_conversation_id()
                )
                self.sub_agents[task.task_id] = agent_thread
        
        # 启动所有线程
        for agent_thread in self.sub_agents.values():
            agent_thread.start()
        
        log_info(f"Dispatched {len(tasks)} tasks", context={"dispatch_id": dispatch_id})
        return dispatch_id
    
    def wait_for_completion(self, timeout: Optional[float] = None) -> MultiAgentResult:
        """
        等待所有子Agent完成或超时
        
        主agent的Ctrl+C中断由InterruptHandler处理，会调用terminate_all()
        
        Args:
            timeout: 超时时间（秒），None表示无限等待
        
        Returns:
            MultiAgentResult: 执行结果
        """
        from .config import get_config
        config = get_config()
        
        start_time = time.time()
        
        # Windows上无超时的join()会阻塞信号处理，必须使用带超时的循环
        # 使用较短的间隔，让事件循环有机会处理 WebSocket 消息
        join_interval = min(config.multi_agent_join_interval, 0.1)  # 最多 100ms
        
        for agent_thread in self.sub_agents.values():
            while agent_thread.is_alive():
                # 检查超时
                if timeout is not None:
                    elapsed = time.time() - start_time
                    if elapsed >= timeout:
                        return self._build_result()
                    remaining = min(join_interval, timeout - elapsed)
                else:
                    remaining = join_interval
                
                # 带超时的join，允许信号处理
                agent_thread.join(timeout=remaining)
        
        return self._build_result()
    
    def terminate_agent(self, agent_id: str) -> bool:
        """
        中断单个子Agent（内部方法，暂不对外暴露）
        
        Args:
            agent_id: Agent ID
        
        Returns:
            bool: 是否成功中断
        """
        with self._lock:
            agent_thread = self.sub_agents.get(agent_id)
            if agent_thread and agent_thread.is_alive():
                # 设置该Agent的中断事件
                agent_thread.termination_event.set()
                
                # 关闭该Agent的监控终端
                agent_thread.close_terminal(delay=0)
                
                # 等待线程结束（最多等待2秒）
                agent_thread.join(timeout=2.0)
                
                # 更新数据库状态
                database = self.agent_databases.get(agent_id)
                if database and (database.status == AgentStatus.RUNNING or database.status == AgentStatus.WAITING):
                    database.set_status(AgentStatus.INTERRUPTED)
                
                log_info(f"Agent {agent_id} terminated")
                return True
            
            return False
    
    def terminate_all(self) -> Dict[str, SubAgentDatabase]:
        """
        异步中断所有子Agent
        
        给每个子Agent发送独立的中断信号，让它们各自处理中断。
        不等待所有Agent完成，而是立即返回。
        
        Returns:
            Dict: agent_id -> SubAgentDatabase
        """
        # 发送全局终止信号到事件管理器（用于唤醒等待LLM响应的agent）
        self.event_manager.signal_termination()
        
        # 中断IPC请求
        if self.ipc_manager:
            self.ipc_manager.interrupt_current_request()
        
        # 给每个子Agent发送独立的中断信号（异步）
        with self._lock:
            for agent_thread in self.sub_agents.values():
                # 设置中断事件
                agent_thread.termination_event.set()
                # 关闭监控终端
                agent_thread.close_terminal(delay=0)
        
        # 启动后台线程等待所有Agent结束并更新状态
        def wait_and_update():
            # 等待所有线程结束（最多等待5秒）
            for agent_thread in self.sub_agents.values():
                agent_thread.join(timeout=5.0)
            
            # 更新未完成的Agent状态
            for agent_id, database in self.agent_databases.items():
                if database.status == AgentStatus.RUNNING or database.status == AgentStatus.WAITING:
                    database.set_status(AgentStatus.INTERRUPTED)
            
            # 重置事件管理器
            self.event_manager.reset_termination()
            
            # 关闭所有终端（确保清理）
            close_all_terminals()
        
        # 在后台线程中等待和清理
        cleanup_thread = threading.Thread(target=wait_and_update, daemon=True)
        cleanup_thread.start()

        # 立即返回数据库（不等待清理完成）
        return self.agent_databases.copy()

    def terminate_own_agents(self) -> None:
        """
        仅终止本管理器名下的子Agent（会话级中断）。

        与 terminate_all 的区别：不发送全局终止信号（event_manager.signal_termination）、
        不中断IPC请求（会波及其他会话）。子Agent等待LLM响应时以1秒短超时轮询
        termination_event，置位后最迟约1秒即退出。
        """
        with self._lock:
            agents = list(self.sub_agents.values())

        for agent_thread in agents:
            agent_thread.termination_event.set()
            agent_thread.close_terminal(delay=0)

        def wait_and_update():
            for agent_thread in agents:
                agent_thread.join(timeout=10.0)
            for database in self.agent_databases.values():
                if database.status in (AgentStatus.RUNNING, AgentStatus.WAITING):
                    database.set_status(AgentStatus.INTERRUPTED)

        threading.Thread(target=wait_and_update, daemon=True).start()

    def get_all_databases(self) -> Dict[str, SubAgentDatabase]:
        """
        获取所有子Agent的数据库
        
        Returns:
            Dict: agent_id -> SubAgentDatabase
        """
        return self.agent_databases.copy()
    
    def _build_result(self) -> MultiAgentResult:
        """构建执行结果"""
        completed = []
        interrupted = []
        failed = []
        
        for agent_id, database in self.agent_databases.items():
            if database.status == AgentStatus.COMPLETED:
                completed.append(agent_id)
            elif database.status == AgentStatus.INTERRUPTED:
                interrupted.append(agent_id)
            elif database.status == AgentStatus.ERROR:
                failed.append(agent_id)
        
        total_time = time.time() - self._start_time if self._start_time else 0
        
        return MultiAgentResult(
            success=len(failed) == 0 and len(interrupted) == 0,
            completed_agents=completed,
            interrupted_agents=interrupted,
            failed_agents=failed,
            databases=self.agent_databases.copy(),
            total_time=total_time
        )
    
    def get_agent_count(self) -> int:
        """获取子Agent数量"""
        return len(self.sub_agents)
    
    def clear(self):
        """清理所有资源"""
        self.terminate_all()
        with self._lock:
            self.sub_agents.clear()
            self.agent_databases.clear()
        self._start_time = None

        # 清除全局引用
        if get_current_agent_manager() == self:
            set_current_agent_manager(None)

        # 清除会话登记
        if self.conversation_id:
            unregister_conversation_agent_manager(self.conversation_id, self)



def analyze_databases_for_redispatch(
    databases: Dict[str, SubAgentDatabase],
    user_correction: Optional[str] = None
) -> str:
    """
    分析数据库生成重派发摘要
    
    Args:
        databases: Agent数据库字典
        user_correction: 用户更正信息
    
    Returns:
        str: 供主Agent分析的摘要文本
    """
    lines = ["=== 多Agent执行状态分析 ===\n"]
    
    # 统计
    completed = 0
    interrupted = 0
    failed = 0
    
    for agent_id, db in databases.items():
        if db.status == AgentStatus.COMPLETED:
            completed += 1
        elif db.status == AgentStatus.INTERRUPTED:
            interrupted += 1
        elif db.status == AgentStatus.ERROR:
            failed += 1
    
    lines.append(f"总计: {len(databases)} 个Agent")
    lines.append(f"  - 完成: {completed}")
    lines.append(f"  - 中断: {interrupted}")
    lines.append(f"  - 失败: {failed}")
    
    if user_correction:
        lines.append(f"\n用户更正信息: {user_correction}")
    
    lines.append("\n--- 各Agent详情 ---\n")
    
    for agent_id, db in databases.items():
        lines.append(db.to_summary())
        lines.append("")
    
    return "\n".join(lines)


class MultiAgentCoordinator:
    """
    多Agent协调器
    
    协调多Agent的派发、中断和重派发。
    """
    
    def __init__(self, ipc_manager: Any):
        """
        初始化协调器
        
        Args:
            ipc_manager: IPC管理器
        """
        self.ipc_manager = ipc_manager
        self.manager: Optional[AgentProcessManager] = None
        self.last_result: Optional[MultiAgentResult] = None
        self.dispatch_history: List[Dict[str, Any]] = []
    
    def dispatch(self, tasks: List[AgentTask]) -> MultiAgentResult:
        """
        派发任务
        
        Args:
            tasks: 任务列表
        
        Returns:
            MultiAgentResult: 执行结果
        """
        from .config import get_config
        
        config = get_config()
        
        # 创建管理器（每个子Agent会创建独立终端，不再需要全局监控）
        self.manager = AgentProcessManager(
            ipc_manager=self.ipc_manager,
            monitor_queue=None  # 不再使用全局队列
        )
        
        # 记录派发历史
        self.dispatch_history.append({
            "tasks": [{"id": t.task_id, "content": t.task_content[:100]} for t in tasks],
            "timestamp": time.time()
        })
        
        # 派发任务
        self.manager.dispatch_tasks(tasks)
        
        # 等待完成
        self.last_result = self.manager.wait_for_completion(
            timeout=config.multi_agent_timeout
        )
        
        return self.last_result
    
    def interrupt_and_collect(self) -> tuple[Dict[str, SubAgentDatabase], str]:
        """
        中断所有Agent并收集状态
        
        Returns:
            tuple: (数据库字典, 分析摘要)
        """
        if self.manager is None:
            return {}, "没有正在运行的Agent"
        
        databases = self.manager.terminate_all()
        summary = analyze_databases_for_redispatch(databases)
        
        return databases, summary
    
    def redispatch_with_correction(
        self,
        new_tasks: List[AgentTask],
        user_correction: Optional[str] = None
    ) -> MultiAgentResult:
        """
        根据更正信息重新派发任务
        
        Args:
            new_tasks: 新任务列表
            user_correction: 用户更正信息
        
        Returns:
            MultiAgentResult: 执行结果
        """
        # 记录更正信息
        if user_correction:
            self.dispatch_history.append({
                "type": "correction",
                "correction": user_correction,
                "timestamp": time.time()
            })
        
        # 重新派发
        return self.dispatch(new_tasks)
    
    def get_status_summary(self) -> str:
        """获取当前状态摘要"""
        if self.last_result is None:
            return "尚未执行任何任务"
        
        return self.last_result.get_all_summaries()
    
    def clear(self):
        """清理资源"""
        if self.manager:
            self.manager.clear()
        self.manager = None
        self.last_result = None
