"""
日志系统模块

提供统一的日志记录功能，记录错误和 LLM 输入验证问题
日志文件保存在项目根目录的 logs 文件夹中
"""
import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path
import traceback
import json
from typing import Optional, Dict, Any


class FlushingRotatingFileHandler(RotatingFileHandler):
    """自动刷新的文件处理器，确保日志实时写入"""
    
    def emit(self, record):
        """重写 emit 方法，每次写入后立即刷新"""
        try:
            super().emit(record)
            self.flush()  # 立即刷新到磁盘
            # 强制操作系统刷新文件缓冲区到磁盘
            if self.stream and hasattr(self.stream, 'fileno'):
                try:
                    import os
                    os.fsync(self.stream.fileno())
                except (OSError, AttributeError):
                    # 某些stream可能不支持fsync，忽略错误
                    pass
        except Exception:
            self.handleError(record)


class SporeLogger:
    """Spore 项目的日志管理器"""
    
    # 类变量：当前会话的日志目录（所有实例共享）
    _session_log_dir: Optional[Path] = None
    
    def __init__(self, log_dir: Optional[str] = None, start_monitor: bool = True):
        """
        初始化日志管理器
        
        Args:
            log_dir: 日志目录路径，None 使用配置默认值
            start_monitor: 是否启动日志监控终端窗口（默认 True）
        """
        # 获取项目根目录
        # PyInstaller 打包环境下，使用 cwd（由 main.rs 设置为安装根目录）
        # 开发环境下，从 __file__ 推断
        if getattr(sys, 'frozen', False):
            project_root = Path.cwd()
        else:
            project_root = Path(__file__).parent.parent
        
        # 从配置获取日志根目录
        if log_dir is None:
            from .config import get_config
            log_dir = get_config().log_dir
        
        self.log_root = project_root / log_dir
        self.project_root = project_root
        
        # 创建日志根目录
        self.log_root.mkdir(exist_ok=True)
        
        # 获取或创建会话日志目录
        self.log_dir = self._get_or_create_session_dir()
        
        # 创建不同类型的日志文件
        self.loggers = {}
        self._setup_loggers()
        
        # 初始化监控客户端（连接到监控服务端）
        self.monitor_client = None
        self._init_monitor_client()
    
    def _get_or_create_session_dir(self) -> Path:
        """
        获取或创建当前会话的日志目录
        
        会话目录以启动时间命名，格式：YYYY-MM-DD_HH-MM-SS
        同一进程的所有 Logger 实例共享同一个会话目录
        """
        # 如果已有会话目录，直接返回
        if SporeLogger._session_log_dir is not None:
            return SporeLogger._session_log_dir
        
        # 检查环境变量（子进程继承主进程的会话目录）
        session_dir_env = os.environ.get('SPORE_SESSION_LOG_DIR')
        if session_dir_env:
            session_dir = Path(session_dir_env)
            if session_dir.exists():
                SporeLogger._session_log_dir = session_dir
                return session_dir
        
        # 创建新的会话目录
        session_name = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        session_dir = self.log_root / session_name
        session_dir.mkdir(exist_ok=True)
        
        # 保存到类变量和环境变量
        SporeLogger._session_log_dir = session_dir
        os.environ['SPORE_SESSION_LOG_DIR'] = str(session_dir)
        
        return session_dir
    
    def _init_monitor_client(self):
        """初始化监控客户端，连接到监控服务，如果服务未运行则自动启动"""
        import multiprocessing as mp
        
        # 只在 Windows 主进程中启动监控
        if sys.platform != 'win32':
            self.monitor_client = None
            return
        
        # 桌面模式下不启动监控终端（前端有日志显示区域）
        if os.environ.get('SPORE_DESKTOP_MODE') == '1':
            self.monitor_client = None
            return
        
        is_main_process = mp.current_process().name == 'MainProcess'
        
        try:
            from .log_monitor import LogMonitorClient, is_monitor_running
            
            # 先检查监控服务是否在运行
            monitor_running = is_monitor_running()
            
            # 如果服务未运行且是主进程，先启动服务
            if not monitor_running and is_main_process:
                self._start_monitor_server()
                # 等待服务启动
                import time
                time.sleep(1.5)
            
            # 创建客户端并连接
            self.monitor_client = LogMonitorClient()
            
            # 尝试连接（最多重试几次）
            import time
            for _ in range(5):
                if self.monitor_client.connect():
                    return
                time.sleep(0.3)
            
            # 最终连接失败
            self.monitor_client = None
            
        except Exception:
            self.monitor_client = None
    
    def _start_monitor_server(self):
        """启动日志监控服务（新终端窗口）"""
        import subprocess
        
        try:
            monitor_script = self.project_root / "base" / "log_monitor.py"
            if not monitor_script.exists():
                return
            
            # 使用 PowerShell 启动新终端窗口
            cmd = [
                'powershell.exe',
                '-NoExit',
                '-ExecutionPolicy', 'Bypass',
                '-Command',
                f'cd "{self.project_root}"; '
                f'$host.UI.RawUI.WindowTitle = "Spore AI - Log Monitor"; '
                f'python "{monitor_script}"'
            ]
            
            subprocess.Popen(
                cmd,
                creationflags=subprocess.CREATE_NEW_CONSOLE,
                cwd=str(self.project_root)
            )
        except Exception:
            pass
    
    def _send_to_monitor(self, log_type: str, content: str):
        """
        发送日志到监控服务端
        
        Args:
            log_type: 日志类型
            content: 日志内容
        """
        if self.monitor_client:
            try:
                self.monitor_client.send(log_type, content)
            except Exception:
                pass  # 发送失败不影响日志记录
    
    def _setup_loggers(self):
        """设置不同类型的日志记录器"""
        from .config import get_config
        _config = get_config()
        
        # 所有日志使用DEBUG级别，记录所有信息
        # 错误日志
        self.loggers['error'] = self._create_logger(
            'error',
            self.log_dir / _config.log_error_filename
        )
        
        # LLM 输入验证日志
        self.loggers['llm_validation'] = self._create_logger(
            'llm_validation',
            self.log_dir / _config.log_llm_validation_filename
        )
        
        # 工具执行日志
        self.loggers['tool_execution'] = self._create_logger(
            'tool_execution',
            self.log_dir / _config.log_tool_execution_filename
        )
        
        # 通用日志
        self.loggers['general'] = self._create_logger(
            'general',
            self.log_dir / _config.log_general_filename
        )
    
    def _create_logger(self, name: str, log_file: Path) -> logging.Logger:
        """
        创建单个日志记录器
        
        Args:
            name: 日志器名称
            log_file: 日志文件路径
        
        Returns:
            配置好的日志记录器
        """
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)  # 固定使用DEBUG级别，记录所有信息
        
        # 避免重复添加处理器
        if logger.handlers:
            return logger
        
        # 禁用向父logger传播，避免重复日志和缓冲问题
        logger.propagate = False
        
        # 创建文件处理器（带轮转，每个文件最大 10MB，保留 5 个备份）
        # 使用自定义的 FlushingRotatingFileHandler 确保实时写入
        from .config import get_config
        _logger_config = get_config()
        file_handler = FlushingRotatingFileHandler(
            log_file,
            maxBytes=_logger_config.log_file_max_size,
            backupCount=_logger_config.log_backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)  # 固定使用DEBUG级别
        
        # 设置日志格式
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        # 添加处理器（仅文件，不输出到控制台）
        logger.addHandler(file_handler)
        
        return logger
    
    def log_error(self, error_type: str, message: str, exception: Optional[Exception] = None, 
                  context: Optional[Dict[str, Any]] = None):
        """
        记录错误日志
        
        Args:
            error_type: 错误类型（如 "API_ERROR", "TOOL_ERROR" 等）
            message: 错误消息
            exception: 异常对象（可选）
            context: 上下文信息（可选）
        """
        log_entry = {
            'error_type': error_type,
            'message': message,
        }
        
        if exception:
            log_entry['exception'] = {
                'type': type(exception).__name__,
                'message': str(exception),
                'traceback': traceback.format_exc()
            }
        
        if context:
            log_entry['context'] = context
        
        # 格式化为 JSON 字符串
        log_message = json.dumps(log_entry, ensure_ascii=False, indent=2)
        
        # 记录到错误日志
        self.loggers['error'].debug(log_message)
        
        # 推送到监控服务端
        self._send_to_monitor('error', log_message)
    
    def log_llm_validation_error(self, error_type: str, message: str, 
                                  llm_response: Optional[str] = None,
                                  expected_format: Optional[str] = None):
        """
        记录 LLM 输入验证错误
        
        Args:
            error_type: 验证错误类型（如 "INVALID_JSON", "MISSING_FIELD" 等）
            message: 错误描述
            llm_response: LLM 的原始响应（可选）
            expected_format: 期望的格式说明（可选）
        """
        log_entry = {
            'validation_error_type': error_type,
            'message': message,
        }
        
        if llm_response:
            # 保存完整响应到日志文件
            log_entry['llm_response'] = llm_response
            log_entry['llm_response_length'] = len(llm_response)
        
        if expected_format:
            log_entry['expected_format'] = expected_format
        
        log_message = json.dumps(log_entry, ensure_ascii=False, indent=2)
        self.loggers['llm_validation'].debug(log_message)
        
        # 推送到监控服务端
        self._send_to_monitor('llm_validation', log_message)
    
    def log_tool_error(self, tool_name: str, error_message: str, 
                       args: Optional[Dict] = None, exception: Optional[Exception] = None,
                       context: Optional[Dict[str, Any]] = None):
        """
        记录工具执行错误
        
        Args:
            tool_name: 工具名称
            error_message: 错误消息
            args: 工具参数（可选）
            exception: 异常对象（可选）
            context: 额外上下文信息（可选）
        """
        log_entry = {
            'tool_name': tool_name,
            'error_message': error_message,
        }
        
        if args:
            # 过滤敏感信息
            safe_args = self._sanitize_args(args)
            log_entry['args'] = safe_args
        
        if exception:
            log_entry['exception'] = {
                'type': type(exception).__name__,
                'message': str(exception),
                'traceback': traceback.format_exc()
            }
        
        if context:
            log_entry['context'] = context
        
        log_message = json.dumps(log_entry, ensure_ascii=False, indent=2)
        self.loggers['tool_execution'].debug(log_message)
        
        # 推送到监控服务端
        self._send_to_monitor('tool_execution', log_message)
    
    def log_info(self, message: str, context: Optional[Dict[str, Any]] = None, 
                 args: Optional[Dict[str, Any]] = None):
        """
        记录一般信息
        
        Args:
            message: 信息内容
            context: 上下文信息（可选）
            args: 工具参数（可选，最多记录200字符）
        """
        log_entry = {}
        
        # 添加简洁的描述（不再使用message字段，直接作为日志级别的消息）
        if context:
            log_entry['context'] = context
        
        # 添加参数信息（完整记录）
        if args:
            log_entry['args'] = json.dumps(args, ensure_ascii=False)
        
        # 如果log_entry为空，只记录消息
        if log_entry:
            log_message = f"{message}\n{json.dumps(log_entry, ensure_ascii=False, indent=2)}"
        else:
            log_message = message
        
        self.loggers['general'].debug(log_message)
        
        # 推送到监控服务端
        self._send_to_monitor('general', log_message)
    
    def _sanitize_args(self, args: Dict) -> Dict:
        """
        清理参数中的敏感信息
        
        Args:
            args: 原始参数字典
        
        Returns:
            清理后的参数字典
        """
        sanitized = {}
        sensitive_keys = ['password', 'api_key', 'token', 'secret', 'credential']
        
        for key, value in args.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            else:
                # 保存完整内容到日志文件
                sanitized[key] = value
                # 记录长度信息（如果是长字符串）
                if isinstance(value, str) and len(value) > 500:
                    sanitized[f"{key}_length"] = len(value)
        
        return sanitized


# 创建全局日志实例
_logger_instance: Optional[SporeLogger] = None


def get_logger() -> SporeLogger:
    """获取全局日志实例"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = SporeLogger()
    return _logger_instance


# 便捷函数
def log_error(error_type: str, message: str, exception: Optional[Exception] = None, 
              context: Optional[Dict[str, Any]] = None):
    """记录错误日志的便捷函数"""
    get_logger().log_error(error_type, message, exception, context)


def log_llm_validation_error(error_type: str, message: str, 
                              llm_response: Optional[str] = None,
                              expected_format: Optional[str] = None):
    """记录 LLM 验证错误的便捷函数"""
    get_logger().log_llm_validation_error(error_type, message, llm_response, expected_format)


def log_tool_error(tool_name: str, error_message: str, 
                   args: Optional[Dict] = None, exception: Optional[Exception] = None,
                   context: Optional[Dict[str, Any]] = None):
    """记录工具错误的便捷函数"""
    get_logger().log_tool_error(tool_name, error_message, args, exception, context)


def log_info(message: str, context: Optional[Dict[str, Any]] = None, 
             args: Optional[Dict[str, Any]] = None):
    """记录信息的便捷函数"""
    get_logger().log_info(message, context, args)
