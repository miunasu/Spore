import os
import contextvars
from typing import Optional
from pathlib import Path
from dotenv import load_dotenv
import logging
logging.getLogger("dotenv").setLevel(logging.ERROR)

# 线程安全的当前 agent 名称（ContextVar，支持多会话并发）
_current_agent_name: contextvars.ContextVar[str] = contextvars.ContextVar(
    "spore_current_agent_name", default="Spore"
)

def get_current_agent_name() -> str:
    """线程安全地获取当前 agent 名称。"""
    return _current_agent_name.get()

def set_current_agent_name(name: str) -> contextvars.Token:
    """线程安全地设置当前 agent 名称，返回 Token 供 reset 使用。"""
    return _current_agent_name.set(name)

# 向后兼容：保留模块级属性供旧代码直接 import，值固定为初始默认值
# 实际读取请使用 get_current_agent_name()
current_agent_name = "Spore"

# 全局继承记忆标志（用于 SYSTEM_AS_USER 模式下，continue 后第一条消息拼接 prompt）
memory_continued = False

# AutoAgent 颗粒化基座：支持独立配置 LLM 基座的 Agent profile 列表
AGENT_PROFILES = ("supervisor", "mode_selector", "security", "frontend")


class Config:
    """统一配置管理类"""
    
    def __init__(self):
        """初始化配置，从环境变量加载"""
        # ========== LLM SDK 配置 ==========
        # 选择使用的 SDK：openai 或 anthropic
        self.llm_sdk: str = os.getenv("LLM_SDK", "openai").lower().strip() or "openai"
        
        # ========== OpenAI API 配置 ==========
        self.openai_api_key: str = os.getenv("OPENAI_API_KEY", "").strip()
        self.openai_api_url: Optional[str] = os.getenv("OPENAI_API_URL", "").strip() or None
        self.openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
        
        # 是否使用 OpenAI Responses API（替代 Chat Completions API）
        # 启用后使用 client.responses.create，支持 o 系列模型的原生接口
        self.use_responses_api: bool = os.getenv("USE_RESPONSES_API", "false").lower() == "true"

        # 主 Agent 流式输出。Chat 进程仍会聚合完整响应供协议解析与历史持久化，
        # 分片仅作为旁路事件供桌面前端实时展示。
        self.llm_stream_enabled: bool = os.getenv("LLM_STREAM_ENABLED", "true").lower() == "true"

        # OpenAI reasoning_effort 参数（用于推理模型如 o1/gpt-5.5 等）
        # 可选值：low, medium, high, xhigh；留空或 none/off 表示不传此参数
        _openai_reasoning_effort = os.getenv("OPENAI_REASONING_EFFORT", "").strip()
        if _openai_reasoning_effort.lower() in ("", "none", "off"):
            _openai_reasoning_effort = ""
        self.openai_reasoning_effort: Optional[str] = _openai_reasoning_effort or None

        # 是否清理 SDK 的 x-stainless headers（某些第三方API代理需要）
        # 对 OpenAI SDK 和 Anthropic SDK 都生效
        self.clean_sdk_headers: bool = os.getenv("CLEAN_SDK_HEADERS", "false").lower() == "true"
        
        # 是否清理 Authorization 头部（Anthropic SDK 会同时发送 x-api-key 和 Authorization）
        # 某些第三方代理只接受 x-api-key，需要移除 Authorization 头部
        # 仅对 Anthropic SDK 有意义，OpenAI SDK 不发送此头部
        self.clean_auth_header: bool = os.getenv("CLEAN_AUTH_HEADER", "false").lower() == "true"
        
        # ========== Embedding 配置 ==========
        # 仅使用专用配置。聊天服务常不支持 /v1/embeddings，自动复用
        # OPENAI_API_* 会在 DeepSeek/Claude/各类中转上产生无意义的启动探针。
        # EMBEDDING_API_KEY 留空表示明确禁用 Learning。
        self.embedding_api_key: str = os.getenv("EMBEDDING_API_KEY", "").strip()
        self.embedding_api_url: Optional[str] = (
            os.getenv("EMBEDDING_API_URL", "").strip() or None
        )
        self.embedding_model: str = (
            os.getenv("EMBEDDING_MODEL", "").strip()
            or "text-embedding-3-small"
        )

        # ========== Anthropic API 配置 ==========
        self.anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "").strip()
        self.anthropic_api_url: Optional[str] = os.getenv("ANTHROPIC_API_URL", "").strip() or None
        self.anthropic_model: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514").strip() or "claude-sonnet-4-20250514"

        # Anthropic effort / thinking 配置（对应 Claude API 的 output_config.effort 与 thinking）
        # effort 可选值：low, medium, high, xhigh, max；留空或 none/off 表示不传
        # 现代模型推荐：thinking=adaptive + output_config.effort
        # 旧模型/手动扩展思考：thinking=enabled + budget_tokens
        _anthropic_effort = os.getenv("ANTHROPIC_EFFORT", "").strip().lower()
        self.anthropic_effort: Optional[str] = _anthropic_effort or None
        if self.anthropic_effort and self.anthropic_effort not in {"low", "medium", "high", "xhigh", "max"}:
            self.anthropic_effort = None

        _thinking_mode = os.getenv("ANTHROPIC_THINKING_MODE", "").strip().lower()
        # adaptive | enabled | disabled；留空表示自动（有 effort 时默认 adaptive，有 budget 时默认 enabled）
        self.anthropic_thinking_mode: Optional[str] = _thinking_mode or None
        if self.anthropic_thinking_mode and self.anthropic_thinking_mode not in {"adaptive", "enabled", "disabled"}:
            self.anthropic_thinking_mode = None

        try:
            _budget = os.getenv("ANTHROPIC_THINKING_BUDGET_TOKENS", "").strip()
            self.anthropic_thinking_budget_tokens: Optional[int] = int(_budget) if _budget else None
        except ValueError:
            self.anthropic_thinking_budget_tokens = None
        
        # ========== 子 Agent LLM 配置 ==========
        # 子 Agent 使用的 SDK（留空则继承主 Agent 配置）
        self.sub_agent_llm_sdk: Optional[str] = os.getenv("SUB_AGENT_LLM_SDK", "").lower().strip() or None
        
        # 子 Agent OpenAI 配置（留空则继承主 Agent 配置）
        self.sub_agent_openai_api_key: Optional[str] = os.getenv("SUB_AGENT_OPENAI_API_KEY", "").strip() or None
        self.sub_agent_openai_api_url: Optional[str] = os.getenv("SUB_AGENT_OPENAI_API_URL", "").strip() or None
        self.sub_agent_openai_model: Optional[str] = os.getenv("SUB_AGENT_OPENAI_MODEL", "").strip() or None
        
        # 子 Agent Anthropic 配置（留空则继承主 Agent 配置）
        self.sub_agent_anthropic_api_key: Optional[str] = os.getenv("SUB_AGENT_ANTHROPIC_API_KEY", "").strip() or None
        self.sub_agent_anthropic_api_url: Optional[str] = os.getenv("SUB_AGENT_ANTHROPIC_API_URL", "").strip() or None
        self.sub_agent_anthropic_model: Optional[str] = os.getenv("SUB_AGENT_ANTHROPIC_MODEL", "").strip() or None

        # ========== AutoAgent 颗粒化基座配置 ==========
        # 每个基座目标（sub_agent 默认层 + 4 个 AutoAgent）可单独配置 LLM 基座
        # 与高级参数（effort/thinking/responses），字段级回退：
        #   AGENT_<PROFILE>_* → SUB_AGENT_* → 主 Agent 配置
        # 环境变量示例：AGENT_SECURITY_LLM_SDK / AGENT_SECURITY_ANTHROPIC_EFFORT / ...
        # effort 类参数（ANTHROPIC_EFFORT / OPENAI_REASONING_EFFORT）支持显式关闭：
        #   留空 = 继承下层；none/off = 该 Agent 明确不传此参数（不再向下回退）
        _layer_prefixes = {
            "sub_agent": "SUB_AGENT",
            "supervisor": "AGENT_SUPERVISOR",
            "mode_selector": "AGENT_MODE_SELECTOR",
            "security": "AGENT_SECURITY",
            "frontend": "AGENT_FRONTEND",
        }
        self._agent_llm_overrides: dict = {
            key: self._parse_llm_layer(prefix) for key, prefix in _layer_prefixes.items()
        }

        try:
            self.frontend_agent_timeout: int = int(os.getenv("FRONTEND_AGENT_TIMEOUT", "180"))
        except ValueError:
            self.frontend_agent_timeout = 180
        try:
            self.frontend_agent_max_iterations: int = int(os.getenv("FRONTEND_AGENT_MAX_ITERATIONS", "10"))
        except ValueError:
            self.frontend_agent_max_iterations = 10
        
        # 系统提示文件名（不含路径，位于 prompt 目录下）
        # 可选：prompt.md（默认）、prompt_claude.md（Claude 专用）
        self.system_prompt_file: str = os.getenv("SYSTEM_PROMPT_FILE", "prompt.md").strip() or "prompt.md"
        
        # 是否将 system prompt 作为第一条 user 消息发送（兼容不支持 system role 的模型，如某些 Claude API）
        # 启用后，system prompt 只会在对话开始时作为第一条 user 消息发送一次，后续不会重复
        self.system_as_user: bool = os.getenv("SYSTEM_AS_USER", "false").lower() == "true"
        
        # ========== LLM 参数配置 ==========
        # max_tokens配置（LLM 单次输出的最大 token 数）
        try:
            self.max_output_tokens: int = int(os.getenv("MAX_OUTPUT_TOKENS", "15000"))
        except ValueError:
            self.max_output_tokens = 15000
        
        # 请求超时配置（秒）
        try:
            self.api_timeout: int = int(os.getenv("API_TIMEOUT", "300"))
        except ValueError:
            self.api_timeout = 300
        
        # ========== 对话管理配置 ==========
        # 上下文token限制
        try:
            self.context_max_tokens: int = int(os.getenv("CONTEXT_MAX_TOKENS", "128000"))
        except ValueError:
            self.context_max_tokens = 128000
        
        # 上下文警告阈值（百分比）
        try:
            self.context_warning_threshold: float = float(os.getenv("CONTEXT_WARNING_THRESHOLD", "0.8"))
        except ValueError:
            self.context_warning_threshold = 0.8
        
        # 单条消息的最大token比例（相对于context_max_tokens）
        try:
            self.max_single_message_ratio: float = float(os.getenv("MAX_SINGLE_MESSAGE_RATIO", "0.3"))
        except ValueError:
            self.max_single_message_ratio = 0.3
        
        # ========== Characters 系统配置 ==========
        # 默认启用的 character 名称（为空则不自动加载）
        self.default_character: str = os.getenv("DEFAULT_CHARACTER", "").strip()
        
        # 规则提醒间隔（每 N 条用户消息提醒一次，0 表示禁用）
        try:
            self.rule_reminder_interval: int = int(os.getenv("RULE_REMINDER_INTERVAL", "10"))
        except ValueError:
            self.rule_reminder_interval = 10
        
        # 是否使用精简版规则提醒（节省 token）
        self.rule_reminder_short: bool = os.getenv("RULE_REMINDER_SHORT", "false").lower() == "true"
        
        # ========== 日志配置 ==========
        self.log_to_file: bool = os.getenv("LOG_TO_FILE", "true").lower() == "true"
        
        # 日志文件最大大小（字节）
        try:
            self.log_file_max_size: int = int(os.getenv("LOG_FILE_MAX_SIZE", str(10 * 1024 * 1024)))
        except ValueError:
            self.log_file_max_size = 10 * 1024 * 1024  # 10MB
        
        # 日志文件备份数量
        try:
            self.log_backup_count: int = int(os.getenv("LOG_BACKUP_COUNT", "5"))
        except ValueError:
            self.log_backup_count = 5
        
        # 日志监控显示行最大长度（字符数）
        try:
            self.log_monitor_max_line_length: int = int(os.getenv("LOG_MONITOR_MAX_LINE_LENGTH", "200"))
        except ValueError:
            self.log_monitor_max_line_length = 200
        
        # 日志文件名配置
        self.log_error_filename: str = os.getenv("LOG_ERROR_FILENAME", "error.log")
        self.log_llm_validation_filename: str = os.getenv("LOG_LLM_VALIDATION_FILENAME", "llm_validation.log")
        self.log_tool_execution_filename: str = os.getenv("LOG_TOOL_EXECUTION_FILENAME", "tool_execution.log")
        self.log_general_filename: str = os.getenv("LOG_GENERAL_FILENAME", "general.log")

        # Raw 日志：收到 LLM 回复时立即把原文完整落盘（不推送到 Desktop 左栏日志）
        self.log_raw_enabled: bool = os.getenv("LOG_RAW_ENABLED", "true").lower() == "true"
        self.log_raw_filename: str = os.getenv("LOG_RAW_FILENAME", "raw.log")

        # 日志监控配置
        self.log_monitor_lock_filename: str = os.getenv("LOG_MONITOR_LOCK_FILENAME", ".monitor.lock")
        try:
            self.log_monitor_check_interval: float = float(os.getenv("LOG_MONITOR_CHECK_INTERVAL", "0.5"))
        except ValueError:
            self.log_monitor_check_interval = 0.5
        
        # 日志监控显示的日志类型（逗号分隔）
        # 可选值：error, llm_validation, tool_execution, general
        # 默认显示除general外的所有类型
        monitor_types_str = os.getenv("LOG_MONITOR_TYPES", "error,llm_validation,tool_execution")
        self.log_monitor_types: set = set(t.strip() for t in monitor_types_str.split(',') if t.strip())
        
        # ========== 工具配置 ==========
        # Web浏览器工具配置
        try:
            self.web_browser_timeout: int = int(os.getenv("WEB_BROWSER_TIMEOUT", "15"))
        except ValueError:
            self.web_browser_timeout = 15
        
        try:
            self.web_proxy_port: int = int(os.getenv("WEB_PROXY_PORT", "7897"))
        except ValueError:
            self.web_proxy_port = 7897
        
        try:
            self.web_max_content_length: int = int(os.getenv("WEB_MAX_CONTENT_LENGTH", "15000"))
        except ValueError:
            self.web_max_content_length = 15000
        
        # 文件读取工具配置
        try:
            self.file_read_default_limit: int = int(os.getenv("FILE_READ_DEFAULT_LIMIT", "2000"))
        except ValueError:
            self.file_read_default_limit = 2000
        
        try:
            self.file_max_line_length: int = int(os.getenv("FILE_MAX_LINE_LENGTH", "2000"))
        except ValueError:
            self.file_max_line_length = 2000
        
        # IPC通信配置
        try:
            self.ipc_check_interval: float = float(os.getenv("IPC_CHECK_INTERVAL", "0.1"))
        except ValueError:
            self.ipc_check_interval = 0.1
        
        # ========== Chat进程并发配置 ==========
        # 最大并发LLM请求数（线程池大小）
        try:
            self.chat_max_workers: int = int(os.getenv("CHAT_MAX_WORKERS", "5"))
        except ValueError:
            self.chat_max_workers = 5
        
        # 响应缓存过期时间（秒），超时未被取走的响应会被清理
        try:
            self.chat_response_expire: float = float(os.getenv("CHAT_RESPONSE_EXPIRE", "300"))
        except ValueError:
            self.chat_response_expire = 300
        
        # 响应缓存清理间隔（秒）
        try:
            self.chat_response_cleanup_interval: float = float(os.getenv("CHAT_RESPONSE_CLEANUP_INTERVAL", "60"))
        except ValueError:
            self.chat_response_cleanup_interval = 60
        
        # ========== SubAgent 配置 ==========
        # Coder 子 Agent 最大迭代次数
        try:
            self.coder_max_iterations: int = int(os.getenv("CODER_MAX_ITERATIONS", "1000"))
        except ValueError:
            self.coder_max_iterations = 1000
        
        # ========== 多Agent配置 ==========
        # 最大并发子Agent数量
        try:
            self.multi_agent_max_count: int = int(os.getenv("MULTI_AGENT_MAX_COUNT", "5"))
        except ValueError:
            self.multi_agent_max_count = 5
        
        # 子Agent最大迭代次数
        try:
            self.sub_agent_max_iterations: int = int(os.getenv("SUB_AGENT_MAX_ITERATIONS", "100"))
        except ValueError:
            self.sub_agent_max_iterations = 100
        
        # 多Agent等待超时时间（秒），None表示无限等待
        multi_agent_timeout_str = os.getenv("MULTI_AGENT_TIMEOUT", "")
        if multi_agent_timeout_str:
            try:
                self.multi_agent_timeout: Optional[float] = float(multi_agent_timeout_str)
            except ValueError:
                self.multi_agent_timeout = None
        else:
            self.multi_agent_timeout = None
        
        # 是否启用多Agent监控终端
        self.multi_agent_monitor_enabled: bool = os.getenv("MULTI_AGENT_MONITOR_ENABLED", "true").lower() == "true"
        
        # 多Agent等待轮询间隔（秒），用于检查中断信号
        try:
            self.multi_agent_join_interval: float = float(os.getenv("MULTI_AGENT_JOIN_INTERVAL", "2.0"))
        except ValueError:
            self.multi_agent_join_interval = 2.0

        # 桌面端异步子Agent派发的整批最长运行时间（秒）；0 表示禁用 watchdog
        try:
            self.multi_agent_total_timeout: float = float(os.getenv("MULTI_AGENT_TOTAL_TIMEOUT", "3600"))
        except ValueError:
            self.multi_agent_total_timeout = 3600.0
        
        # ========== 工具执行配置 ==========
        # 工具执行超时时间（秒）
        try:
            self.tool_execution_timeout: int = int(os.getenv("TOOL_EXECUTION_TIMEOUT", "120"))
        except ValueError:
            self.tool_execution_timeout = 120
        
        # Shell 命令执行超时时间（秒）
        try:
            self.shell_command_timeout: int = int(os.getenv("SHELL_COMMAND_TIMEOUT", "60"))
        except ValueError:
            self.shell_command_timeout = 60

        # ========== Command intercept (master switch) ==========
        # COMMAND_INTERCEPT: master switch for shell/command safety intercept strategies.
        # true: enable intercept strategies; false: disable all of them.
        # Legacy alias: BLOCK_SHELL_DELETE (used only if COMMAND_INTERCEPT unset).
        _cmd_intercept_raw = os.getenv("COMMAND_INTERCEPT", "").strip()
        if not _cmd_intercept_raw:
            _cmd_intercept_raw = os.getenv("BLOCK_SHELL_DELETE", "true").strip() or "true"
        self.command_intercept: bool = _cmd_intercept_raw.lower() == "true"

        # Fine-grained strategies (only applied when command_intercept=true).
        # Unset => enabled; set INTERCEPT_SHELL_DELETE/WRITE=true|false to override.
        _del = os.getenv("INTERCEPT_SHELL_DELETE", "").strip().lower()
        self.intercept_shell_delete: bool = True if _del == "" else _del == "true"
        _write = os.getenv("INTERCEPT_SHELL_WRITE", "").strip().lower()
        self.intercept_shell_write: bool = True if _write == "" else _write == "true"
        
        # 是否限制写工具的返回值（不在messages中添加arguments字段）
        self.limit_write_tool_return: bool = os.getenv("LIMIT_WRITE_TOOL_RETURN", "true").lower() == "true"

        # ========== 备份恢复配置 ==========
        # 备份系统总开关：文件写操作自动备份 + 对话点快照
        self.backup_enabled: bool = os.getenv("BACKUP_ENABLED", "true").lower() == "true"

        # 备份存储目录（相对项目根目录或绝对路径）
        self.backup_dir: str = os.getenv("BACKUP_DIR", ".spore").strip() or ".spore"

        # 单文件备份大小上限（字节），超过则跳过备份
        try:
            self.backup_max_file_bytes: int = int(os.getenv("BACKUP_MAX_FILE_BYTES", str(50 * 1024 * 1024)))
        except ValueError:
            self.backup_max_file_bytes = 50 * 1024 * 1024

        # 删除目录时最多备份的文件数量
        try:
            self.backup_max_delete_files: int = int(os.getenv("BACKUP_MAX_DELETE_FILES", "200"))
        except ValueError:
            self.backup_max_delete_files = 200

        # ========== 安全 Agent 配置 ==========
        # 单一模式开关：
        #   off   : 完全关闭
        #   basic : 关键词研判 —— 命中 ps 高危关键词 -> AI 风险评估 -> 按容忍度确认
        #   full  : 全权交给安全 Agent —— 不做关键词预筛，每条命令都交安全 Agent
        #           异步研判语义意图 + 风险 + 恶意（不阻塞），确定为恶意即熔断会话
        _sa_mode = os.getenv("SECURITY_AGENT_MODE", "full").lower().strip()
        if _sa_mode not in ("off", "basic", "full"):
            _sa_mode = "full"
        self.security_agent_mode: str = _sa_mode
        # 兼容属性：旧代码判定"守卫是否启用"（basic/full 均启用关键词检测）
        self.security_guard_enabled: bool = _sa_mode != "off"

        # 风险容忍度: strict（命中策略一律确认）/ balanced（低风险自动放行）
        #             / permissive（低+中风险自动放行）
        _sg_mode = os.getenv("SECURITY_GUARD_MODE", "balanced").lower().strip()
        self.security_guard_mode: str = _sg_mode if _sg_mode in ("strict", "balanced", "permissive") else "balanced"

        # 高危命令 AI 风险评估超时（秒）
        try:
            self.security_llm_timeout: int = int(os.getenv("SECURITY_LLM_TIMEOUT", "30"))
        except ValueError:
            self.security_llm_timeout = 30

        # 意图 / 恶意研判超时（秒，full 模式）
        # 留足 provider 限流重试（5s/15s）的余量，避免多命令并发分析时后续请求被静默丢弃
        try:
            self.security_intent_timeout: int = int(os.getenv("SECURITY_INTENT_TIMEOUT", "45"))
        except ValueError:
            self.security_intent_timeout = 45

        # 会话上下文模式：将本次会话已分析过的命令作为历史上下文随当前命令一起发给 LLM，
        # 使安全 Agent 能结合 Agent 行为序列理解当前命令的真实意图。
        # 仅对 full 模式有效；session_id 为 None（CLI 无桌面 session）时自动降级为无上下文。
        self.security_agent_session_context: bool = (
            os.getenv("SECURITY_AGENT_SESSION_CONTEXT", "false").lower() == "true"
        )

        # 会话上下文保留的最大历史命令数（超出则丢弃最旧的）
        try:
            self.security_session_context_max_commands: int = int(
                os.getenv("SECURITY_SESSION_CONTEXT_MAX_COMMANDS", "20")
            )
        except ValueError:
            self.security_session_context_max_commands = 20

        # ========== 系统语言 ==========
        # 影响需要"面向用户自然语言输出"的辅助 Agent（如命令意图说明、熔断修复建议）。
        # zh: 简体中文；en: English。前端语言开关会通过 settings 接口同步此项。
        _sys_lang = os.getenv("SYSTEM_LANGUAGE", "zh").lower().strip()
        self.system_language: str = _sys_lang if _sys_lang in ("zh", "en") else "zh"
        
        # ========== 目录路径配置 ==========
        # Skills 目录路径
        self.skills_dir: str = os.getenv("SKILLS_DIR", "skills")
        
        # Characters 目录路径
        self.characters_dir: str = os.getenv("CHARACTERS_DIR", "characters")
        
        # Prompt 目录路径
        self.prompt_dir: str = os.getenv("PROMPT_DIR", "prompt")
        
        # 日志目录路径
        self.log_dir: str = os.getenv("LOG_DIR", "logs")
        
        # Output 目录路径
        self.output_dir: str = os.getenv("OUTPUT_DIR", "output")
        
        # Web 上传目录路径
        self.upload_dir: str = os.getenv("UPLOAD_DIR", "uploads")
        
        # ========== 桌面模式配置 ==========
        # 启动模式: cli 或 desktop
        self.launch_mode: str = os.getenv("LAUNCH_MODE", "cli").lower().strip() or "cli"
        
        # 桌面模式 API 服务器主机地址
        self.desktop_api_host: str = os.getenv("DESKTOP_API_HOST", "127.0.0.1")
        
        # 桌面模式 API 服务器端口
        try:
            self.desktop_api_port: int = int(os.getenv("DESKTOP_API_PORT", "8765"))
        except ValueError:
            self.desktop_api_port = 8765
        
        # 桌面模式 WebSocket 推送端口（API 端口 + 1）
        self.desktop_ws_port: int = self.desktop_api_port + 1
        
        # ========== 上下文处理模式配置 ==========
        # 上下文处理模式: strong_context, long_context, auto
        # strong_context: 强上下文关联模式（当前默认行为）
        # long_context: 长上下文处理模式（使用不同的工具集）
        # auto: 自动选择模式（由LLM判断使用哪种模式）
        self.context_mode: str = os.getenv("CONTEXT_MODE", "strong_context").lower().strip() or "strong_context"

        # Tool policy scope: session (per conversation) | global (tool_policy.json for all)
        # Runtime UI can still override via tool_policy.json "scope" field.
        _tps = os.getenv("TOOL_POLICY_SCOPE", "session").lower().strip() or "session"
        self.tool_policy_scope: str = _tps if _tps in ("session", "global") else "session"
        
    def validate(self) -> bool:
        """
        验证配置的有效性
        
        Returns:
            bool: 配置是否有效
        
        Raises:
            RuntimeError: 当必需的配置缺失时
        """
        if self.llm_sdk == "anthropic":
            if not self.anthropic_api_key:
                raise RuntimeError("ANTHROPIC_API_KEY 未设置。请在环境变量中配置 Anthropic API 密钥。")
        else:
            if not self.openai_api_key:
                raise RuntimeError("OPENAI_API_KEY 未设置。请在环境变量中配置 OpenAI API 密钥。")
        return True
    

    def is_intercept_enabled(self, strategy: Optional[str] = None) -> bool:
        """Return whether command intercept is active.

        Args:
            strategy: Optional strategy name, e.g. "shell_delete", "shell_write".
                      When provided, requires master switch AND that strategy flag.
        """
        if not getattr(self, "command_intercept", True):
            return False
        if not strategy:
            return True
        strategy_map = {
            "shell_delete": getattr(self, "intercept_shell_delete", True),
            "shell_write": getattr(self, "intercept_shell_write", True),
            # Add new strategies here later.
        }
        return bool(strategy_map.get(strategy, True))

    def get_model(self) -> str:
        """根据当前 SDK 获取模型名称"""
        if self.llm_sdk == "anthropic":
            return self.anthropic_model
        return self.openai_model
    
    def get_sub_agent_sdk(self) -> str:
        """获取子 Agent 使用的 SDK（若未配置则继承主 Agent）"""
        return self.sub_agent_llm_sdk or self.llm_sdk
    
    def get_sub_agent_openai_api_key(self) -> str:
        """获取子 Agent OpenAI API Key（若未配置则继承主 Agent）"""
        return self.sub_agent_openai_api_key or self.openai_api_key
    
    def get_sub_agent_openai_api_url(self) -> Optional[str]:
        """获取子 Agent OpenAI API URL（若未配置则继承主 Agent）"""
        if self.sub_agent_openai_api_url is not None:
            return self.sub_agent_openai_api_url
        return self.openai_api_url
    
    def get_sub_agent_openai_model(self) -> str:
        """获取子 Agent OpenAI 模型（若未配置则继承主 Agent）"""
        return self.sub_agent_openai_model or self.openai_model
    
    def get_sub_agent_anthropic_api_key(self) -> str:
        """获取子 Agent Anthropic API Key（若未配置则继承主 Agent）"""
        return self.sub_agent_anthropic_api_key or self.anthropic_api_key
    
    def get_sub_agent_anthropic_api_url(self) -> Optional[str]:
        """获取子 Agent Anthropic API URL（若未配置则继承主 Agent）"""
        if self.sub_agent_anthropic_api_url is not None:
            return self.sub_agent_anthropic_api_url
        return self.anthropic_api_url
    
    def get_sub_agent_anthropic_model(self) -> str:
        """获取子 Agent Anthropic 模型（若未配置则继承主 Agent）"""
        return self.sub_agent_anthropic_model or self.anthropic_model
    
    def get_sub_agent_model(self) -> str:
        """根据子 Agent SDK 获取对应的模型名称"""
        sdk = self.get_sub_agent_sdk()
        if sdk == "anthropic":
            return self.get_sub_agent_anthropic_model()
        return self.get_sub_agent_openai_model()

    def resolve_agent_llm(self, profile: str) -> dict:
        """
        解析指定基座目标的 LLM 基座 + 高级参数。

        profile ∈ {sub_agent, supervisor, mode_selector, security, frontend}。
        字段级回退：
          - sub_agent：SUB_AGENT_* → 主 Agent
          - 其余 AutoAgent：AGENT_<PROFILE>_* → SUB_AGENT_* → 主 Agent
        返回 {sdk, api_key, api_url, model, use_responses_api, reasoning_effort,
              effort, thinking_mode, thinking_budget_tokens}。
        """
        layers = []
        if profile in self._agent_llm_overrides:
            layers.append(self._agent_llm_overrides[profile])
        if profile != "sub_agent" and "sub_agent" in self._agent_llm_overrides:
            layers.append(self._agent_llm_overrides["sub_agent"])
        layers.append(self._main_llm_layer())

        def pick(key):
            for layer in layers:
                val = layer.get(key)
                if val is not None:
                    return val
            return None

        sdk = pick("sdk") or "openai"
        if sdk == "anthropic":
            return {
                "sdk": "anthropic",
                "api_key": pick("anthropic_api_key"),
                "api_url": pick("anthropic_api_url"),
                "model": pick("anthropic_model"),
                "use_responses_api": None,
                "reasoning_effort": None,
                "effort": pick("anthropic_effort"),
                "thinking_mode": pick("anthropic_thinking_mode"),
                "thinking_budget_tokens": pick("anthropic_thinking_budget_tokens"),
                "max_output_tokens": pick("max_output_tokens"),
            }
        return {
            "sdk": "openai",
            "api_key": pick("openai_api_key"),
            "api_url": pick("openai_api_url"),
            "model": pick("openai_model"),
            "use_responses_api": pick("use_responses_api"),
            "reasoning_effort": pick("openai_reasoning_effort"),
            "effort": None,
            "thinking_mode": None,
            "thinking_budget_tokens": None,
            "max_output_tokens": pick("max_output_tokens"),
        }

    def _main_llm_layer(self) -> dict:
        """主 Agent 基座层（供颗粒化回退链的兜底层，反映当前主配置）。"""
        return {
            "sdk": self.llm_sdk,
            "openai_api_key": self.openai_api_key or None,
            "openai_api_url": self.openai_api_url,
            "openai_model": self.openai_model,
            "anthropic_api_key": self.anthropic_api_key or None,
            "anthropic_api_url": self.anthropic_api_url,
            "anthropic_model": self.anthropic_model,
            "use_responses_api": self.use_responses_api,
            "openai_reasoning_effort": self.openai_reasoning_effort,
            "anthropic_effort": self.anthropic_effort,
            "anthropic_thinking_mode": self.anthropic_thinking_mode,
            "anthropic_thinking_budget_tokens": self.anthropic_thinking_budget_tokens,
        }

    @staticmethod
    def _parse_llm_layer(prefix: str) -> dict:
        """从 <PREFIX>_* 环境变量解析一层基座配置（基础 + 高级）。空值为 None。"""
        def g(suffix: str):
            return os.getenv(f"{prefix}_{suffix}", "").strip() or None

        def g_lower(suffix: str):
            v = g(suffix)
            return v.lower() if v else None

        budget_raw = g("ANTHROPIC_THINKING_BUDGET_TOKENS")
        try:
            budget = int(budget_raw) if budget_raw else None
        except ValueError:
            budget = None

        ura = g_lower("USE_RESPONSES_API")
        use_resp = True if ura == "true" else (False if ura == "false" else None)

        max_tokens_raw = g("MAX_OUTPUT_TOKENS")
        try:
            max_output_tokens = int(max_tokens_raw) if max_tokens_raw else None
        except ValueError:
            max_output_tokens = None

        return {
            "sdk": g_lower("LLM_SDK"),
            "openai_api_key": g("OPENAI_API_KEY"),
            "openai_api_url": g("OPENAI_API_URL"),
            "openai_model": g("OPENAI_MODEL"),
            "anthropic_api_key": g("ANTHROPIC_API_KEY"),
            "anthropic_api_url": g("ANTHROPIC_API_URL"),
            "anthropic_model": g("ANTHROPIC_MODEL"),
            "use_responses_api": use_resp,
            "openai_reasoning_effort": g_lower("OPENAI_REASONING_EFFORT"),
            "anthropic_effort": g_lower("ANTHROPIC_EFFORT"),
            "anthropic_thinking_mode": g_lower("ANTHROPIC_THINKING_MODE"),
            "anthropic_thinking_budget_tokens": budget,
            "max_output_tokens": max_output_tokens,
        }
    
    def get_max_tokens(self) -> int:
        """
        获取 LLM 单次输出的最大 token 数
        
        Returns:
            int: max_tokens值
        """
        return self.max_output_tokens
    
    def __repr__(self) -> str:
        """配置的字符串表示（隐藏敏感信息）"""
        api_url = self.anthropic_api_url if self.llm_sdk == "anthropic" else self.openai_api_url
        return (
            f"Config(\n"
            f"  llm_sdk={self.llm_sdk},\n"
            f"  model={self.get_model()},\n"
            f"  api_url={api_url},\n"
            f"  context_max_tokens={self.context_max_tokens},\n"
            f"  api_timeout={self.api_timeout}s\n"
            f")"
        )


# 全局配置实例（单例模式）
_config_instance: Optional[Config] = None


def get_config() -> Config:
    """
    获取全局配置实例（单例模式）
    
    Returns:
        Config: 全局配置对象
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance


def reload_config() -> Config:
    """Reload .env and rebuild the global Config instance."""
    global _config_instance
    load_dotenv(dotenv_path=_ENV_PATH, override=True)
    _config_instance = Config()
    return _config_instance


# 向后兼容接口已移除，请直接使用 get_config() 获取配置

# 获取项目根目录
import sys as _sys
if getattr(_sys, 'frozen', False):
    # 打包环境：使用 cwd（exe 所在目录）
    _PROJECT_ROOT = Path.cwd()
else:
    # 开发环境：config.py 在 base/ 目录下，向上一级
    _PROJECT_ROOT = Path(__file__).parent.parent
# 预加载项目根目录下的 .env 文件
_ENV_PATH = _PROJECT_ROOT / '.env'
load_dotenv(dotenv_path=_ENV_PATH, override=False)
