import os
from typing import Optional
from pathlib import Path
from dotenv import load_dotenv
import logging
logging.getLogger("dotenv").setLevel(logging.ERROR)

# 全局当前agent名称
current_agent_name = "Spore"

# 全局继承记忆标志（用于 SYSTEM_AS_USER 模式下，continue 后第一条消息拼接 prompt）
memory_continued = False


class Config:
    """统一配置管理类"""
    
    def __init__(self):
        """初始化配置，从环境变量加载"""
        # ========== LLM SDK 配置 ==========
        # 选择使用的 SDK：openai 或 anthropic
        self.llm_sdk: str = os.getenv("LLM_SDK", "openai").lower().strip()
        
        # ========== OpenAI API 配置 ==========
        self.openai_api_key: str = os.getenv("OPENAI_API_KEY", "").strip()
        self.openai_api_url: Optional[str] = os.getenv("OPENAI_API_URL", "").strip() or None
        self.openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        
        # 是否清理 SDK 的 x-stainless headers（某些第三方API代理如packyapi需要）
        # 对 OpenAI SDK 和 Anthropic SDK 都生效
        self.clean_sdk_headers: bool = os.getenv("CLEAN_SDK_HEADERS", "false").lower() == "true"
        
        # 是否清理 Authorization 头部（Anthropic SDK 会同时发送 x-api-key 和 Authorization）
        # packyapi 等第三方代理只接受 x-api-key，需要移除 Authorization 头部
        # 仅对 Anthropic SDK 有意义，OpenAI SDK 不发送此头部
        self.clean_auth_header: bool = os.getenv("CLEAN_AUTH_HEADER", "false").lower() == "true"
        
        # ========== Anthropic API 配置 ==========
        self.anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "").strip()
        self.anthropic_api_url: Optional[str] = os.getenv("ANTHROPIC_API_URL", "").strip() or None
        self.anthropic_model: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
        
        # 系统提示文件名（不含路径，位于 prompt 目录下）
        # 可选：prompt.md（默认）、prompt_claude.md（Claude 专用）
        self.system_prompt_file: str = os.getenv("SYSTEM_PROMPT_FILE", "prompt.md")
        
        # 是否将 system prompt 作为第一条 user 消息发送（兼容不支持 system role 的模型，如某些 Claude API）
        # 启用后，system prompt 只会在对话开始时作为第一条 user 消息发送一次，后续不会重复
        self.system_as_user: bool = os.getenv("SYSTEM_AS_USER", "false").lower() == "true"
        
        # ========== LLM 参数配置 ==========
        # 主对话 temperature
        try:
            self.temperature_main: float = float(os.getenv("TEMPERATURE_MAIN", "0.7"))
        except ValueError:
            self.temperature_main = 0.7
        
        try:
            self.temperature_coder: float = float(os.getenv("TEMPERATURE_CODER", "0.3"))
        except ValueError:
            self.temperature_coder = 0.3
        
        try:
            self.temperature_supervisor: float = float(os.getenv("TEMPERATURE_SUPERVISOR", "0.1"))
        except ValueError:
            self.temperature_supervisor = 0.1
        
        try:
            self.temperature_character_selector: float = float(os.getenv("TEMPERATURE_CHARACTER_SELECTOR", "0.1"))
        except ValueError:
            self.temperature_character_selector = 0.1
        
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
        
        # 用户消息计数触发角色推荐的频率
        try:
            self.character_recommend_interval: int = int(os.getenv("CHARACTER_RECOMMEND_INTERVAL", "5"))
        except ValueError:
            self.character_recommend_interval = 5
        
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
        
        # 是否限制写工具的返回值（不在messages中添加arguments字段）
        self.limit_write_tool_return: bool = os.getenv("LIMIT_WRITE_TOOL_RETURN", "true").lower() == "true"
        
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
        self.launch_mode: str = os.getenv("LAUNCH_MODE", "cli").lower().strip()
        
        # 桌面模式 API 服务器主机地址
        self.desktop_api_host: str = os.getenv("DESKTOP_API_HOST", "127.0.0.1")
        
        # 桌面模式 API 服务器端口
        try:
            self.desktop_api_port: int = int(os.getenv("DESKTOP_API_PORT", "8765"))
        except ValueError:
            self.desktop_api_port = 8765
        
        # ========== 上下文处理模式配置 ==========
        # 上下文处理模式: strong_context, long_context, auto
        # strong_context: 强上下文关联模式（当前默认行为）
        # long_context: 长上下文处理模式（使用不同的工具集）
        # auto: 自动选择模式（由LLM判断使用哪种模式）
        self.context_mode: str = os.getenv("CONTEXT_MODE", "strong_context").lower().strip()
        
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
    
    def get_model(self) -> str:
        """根据当前 SDK 获取模型名称"""
        if self.llm_sdk == "anthropic":
            return self.anthropic_model
        return self.openai_model
    
    def get_temperature(self, mode: str = "main") -> float:
        """
        根据模式获取对应的temperature
        
        Args:
            mode: 模式名称，可选值：main, coder, supervisor, character_selector
        
        Returns:
            float: 对应的temperature值
        """
        mode_map = {
            "main": self.temperature_main,
            "coder": self.temperature_coder,
            "supervisor": self.temperature_supervisor,
            "character_selector": self.temperature_character_selector,
        }
        return mode_map.get(mode, self.temperature_main)
    
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
            f"  temperature_main={self.temperature_main},\n"
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


# 向后兼容接口已移除，请直接使用 get_config() 获取配置

# 获取项目根目录（config.py 在 base/ 目录下，所以向上一级）
_PROJECT_ROOT = Path(__file__).parent.parent
# 预加载项目根目录下的 .env 文件
_ENV_PATH = _PROJECT_ROOT / '.env'
load_dotenv(dotenv_path=_ENV_PATH, override=False)
