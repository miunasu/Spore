"""
日志系统模块

提供统一的日志记录功能，记录错误和 LLM 输入验证问题
日志文件保存在项目根目录的 logs 文件夹中

目录结构：
  logs/<进程启动时间>/                 # 进程级会话目录（兼容旧逻辑）
    general.log / error.log / ...
    conversations/<session_id>/        # 一样本/一对话独立日志
      general.log / error.log / ...
      agents/
"""
import os
import sys
import re
import logging
import threading
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path
import traceback
import json
from typing import Optional, Dict, Any, Tuple


class FlushingRotatingFileHandler(RotatingFileHandler):
    """自动刷新的文件处理器，确保日志实时写入"""

    def emit(self, record):
        """重写 emit 方法，每次写入后立即刷新"""
        try:
            super().emit(record)
            self.flush()
            if self.stream and hasattr(self.stream, "fileno"):
                try:
                    os.fsync(self.stream.fileno())
                except (OSError, AttributeError):
                    pass
        except Exception:
            self.handleError(record)


def _resolve_conversation_id() -> Optional[str]:
    """解析当前执行上下文绑定的对话/会话 ID。"""
    try:
        from .session_context import get_current_conversation_id
        cid = get_current_conversation_id()
        if cid:
            return cid
    except Exception:
        pass
    env_cid = os.environ.get("SPORE_CONVERSATION_ID")
    if env_cid and env_cid.strip():
        return env_cid.strip()
    return None


def _sanitize_conversation_id(conversation_id: str) -> str:
    safe = re.sub(r"[^\w\-]+", "_", conversation_id, flags=re.UNICODE)
    safe = safe.strip("._") or "unknown"
    return safe[:120]


class SporeLogger:
    """Spore 项目的日志管理器"""

    # 类变量：当前进程的日志根会话目录（所有实例共享）
    _session_log_dir: Optional[Path] = None
    _handler_lock = threading.RLock()

    def __init__(self, log_dir: Optional[str] = None, start_monitor: bool = True):
        if getattr(sys, "frozen", False):
            project_root = Path.cwd()
        else:
            project_root = Path(__file__).parent.parent

        if log_dir is None:
            from .config import get_config
            log_dir = get_config().log_dir

        self.log_root = project_root / log_dir
        self.project_root = project_root
        self.log_root.mkdir(exist_ok=True)
        self.log_dir = self._get_or_create_session_dir()
        self.loggers: Dict[str, logging.Logger] = {}
        self._dynamic_loggers: Dict[str, Dict[str, logging.Logger]] = {}
        self._setup_loggers_into(self.loggers, self.log_dir, logger_suffix="process")
        self.monitor_client = None
        self._init_monitor_client()
    def _get_or_create_session_dir(self) -> Path:
        """获取或创建当前进程的日志会话目录。"""
        if SporeLogger._session_log_dir is not None:
            return SporeLogger._session_log_dir

        session_dir_env = os.environ.get("SPORE_SESSION_LOG_DIR")
        if session_dir_env:
            session_dir = Path(session_dir_env)
            if session_dir.exists():
                SporeLogger._session_log_dir = session_dir
                return session_dir

        session_name = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        session_dir = self.log_root / session_name
        session_dir.mkdir(exist_ok=True)
        SporeLogger._session_log_dir = session_dir
        os.environ["SPORE_SESSION_LOG_DIR"] = str(session_dir)
        return session_dir

    def get_process_log_dir(self) -> Path:
        if SporeLogger._session_log_dir is not None:
            return SporeLogger._session_log_dir
        return self.log_dir

    def get_active_log_dir(self) -> Path:
        """返回当前上下文应写入的日志目录（按对话隔离）。"""
        env_conv_dir = os.environ.get("SPORE_CONVERSATION_LOG_DIR")
        if env_conv_dir:
            path = Path(env_conv_dir)
            path.mkdir(parents=True, exist_ok=True)
            return path

        process_dir = self.get_process_log_dir()
        cid = _resolve_conversation_id()
        if cid:
            conv_dir = process_dir / "conversations" / _sanitize_conversation_id(cid)
            conv_dir.mkdir(parents=True, exist_ok=True)
            meta = conv_dir / "session_id.txt"
            try:
                if not meta.exists():
                    meta.write_text(cid, encoding="utf-8")
            except OSError:
                pass
            return conv_dir
        return process_dir

    def _init_monitor_client(self):
        import multiprocessing as mp
        if sys.platform != "win32":
            self.monitor_client = None
            return
        if os.environ.get("SPORE_DESKTOP_MODE") == "1":
            self.monitor_client = None
            return
        is_main_process = mp.current_process().name == "MainProcess"
        try:
            from .log_monitor import LogMonitorClient, is_monitor_running
            monitor_running = is_monitor_running()
            if not monitor_running and is_main_process:
                self._start_monitor_server()
                import time
                time.sleep(1.5)
            self.monitor_client = LogMonitorClient()
            import time
            for _ in range(5):
                if self.monitor_client.connect():
                    return
                time.sleep(0.3)
            self.monitor_client = None
        except Exception:
            self.monitor_client = None

    def _start_monitor_server(self):
        import subprocess
        try:
            monitor_script = self.project_root / "base" / "log_monitor.py"
            if not monitor_script.exists():
                return
            cmd = [
                "powershell.exe",
                "-NoExit",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                'cd "{0}"; $host.UI.RawUI.WindowTitle = "Spore AI - Log Monitor"; python "{1}"'.format(
                    self.project_root, monitor_script
                ),
            ]
            subprocess.Popen(
                cmd,
                creationflags=subprocess.CREATE_NEW_CONSOLE,
                cwd=str(self.project_root),
            )
        except Exception:
            pass

    def _send_to_monitor(self, log_type: str, content: str):
        if self.monitor_client:
            try:
                self.monitor_client.send(log_type, content)
            except Exception:
                pass
    def _setup_loggers_into(self, target: Dict[str, logging.Logger], log_dir: Path, logger_suffix: str) -> None:
        from .config import get_config
        _config = get_config()
        specs = [
            ("error", _config.log_error_filename),
            ("llm_validation", _config.log_llm_validation_filename),
            ("tool_execution", _config.log_tool_execution_filename),
            ("general", _config.log_general_filename),
        ]
        for name, filename in specs:
            target[name] = self._create_logger(f"{name}.{logger_suffix}", log_dir / filename)

    def _setup_loggers(self):
        self._setup_loggers_into(self.loggers, self.log_dir, logger_suffix="process")

    def _get_loggers_for_active_context(self) -> Tuple[Dict[str, logging.Logger], Optional[str]]:
        cid = _resolve_conversation_id()
        key = _sanitize_conversation_id(cid) if cid else "__process__"
        with SporeLogger._handler_lock:
            cached = self._dynamic_loggers.get(key)
            if cached is not None:
                return cached, cid
            log_dir = self.get_active_log_dir()
            loggers: Dict[str, logging.Logger] = {}
            self._setup_loggers_into(loggers, log_dir, logger_suffix=key)
            self._dynamic_loggers[key] = loggers
            return loggers, cid

    def _create_logger(self, name: str, log_file: Path) -> logging.Logger:
        logger = logging.getLogger(f"spore.{name}")
        logger.setLevel(logging.DEBUG)
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        if logger.handlers:
            for h in list(logger.handlers):
                try:
                    h.close()
                except Exception:
                    pass
                logger.removeHandler(h)
        logger.propagate = False
        from .config import get_config
        _logger_config = get_config()
        file_handler = FlushingRotatingFileHandler(
            log_file,
            maxBytes=_logger_config.log_file_max_size,
            backupCount=_logger_config.log_backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        return logger

    def log_error(self, error_type: str, message: str, exception: Optional[Exception] = None, context: Optional[Dict[str, Any]] = None):
        # session_id 仅用于按对话目录落盘，不写入日志正文（前端/监控已通过 conversation_id 路由）
        loggers, _session_id = self._get_loggers_for_active_context()
        log_entry: Dict[str, Any] = {"error_type": error_type, "message": message}
        if exception:
            log_entry["exception"] = {
                "type": type(exception).__name__,
                "message": str(exception),
                "traceback": traceback.format_exc(),
            }
        if context:
            log_entry["context"] = context
        log_message = json.dumps(log_entry, ensure_ascii=False, indent=2)
        loggers["error"].debug(log_message)
        self._send_to_monitor("error", log_message)

    def log_llm_validation_error(self, error_type: str, message: str, llm_response: Optional[str] = None, expected_format: Optional[str] = None):
        loggers, _session_id = self._get_loggers_for_active_context()
        log_entry: Dict[str, Any] = {"validation_error_type": error_type, "message": message}
        if llm_response:
            log_entry["llm_response"] = llm_response
            log_entry["llm_response_length"] = len(llm_response)
        if expected_format:
            log_entry["expected_format"] = expected_format
        log_message = json.dumps(log_entry, ensure_ascii=False, indent=2)
        loggers["llm_validation"].debug(log_message)
        self._send_to_monitor("llm_validation", log_message)

    def log_tool_error(self, tool_name: str, error_message: str, args: Optional[Dict] = None, exception: Optional[Exception] = None, context: Optional[Dict[str, Any]] = None):
        loggers, _session_id = self._get_loggers_for_active_context()
        log_entry: Dict[str, Any] = {"tool_name": tool_name, "error_message": error_message}
        if args:
            log_entry["args"] = self._sanitize_args(args)
        if exception:
            log_entry["exception"] = {
                "type": type(exception).__name__,
                "message": str(exception),
                "traceback": traceback.format_exc(),
            }
        if context:
            log_entry["context"] = context
        log_message = json.dumps(log_entry, ensure_ascii=False, indent=2)
        loggers["tool_execution"].debug(log_message)
        self._send_to_monitor("tool_execution", log_message)

    def log_info(self, message: str, context: Optional[Dict[str, Any]] = None, args: Optional[Dict[str, Any]] = None):
        loggers, _session_id = self._get_loggers_for_active_context()
        log_entry: Dict[str, Any] = {}
        if context:
            log_entry["context"] = context
        if args:
            log_entry["args"] = json.dumps(args, ensure_ascii=False)
        if log_entry:
            log_message = "{0}\n{1}".format(message, json.dumps(log_entry, ensure_ascii=False, indent=2))
        else:
            log_message = message
        loggers["general"].debug(log_message)
        self._send_to_monitor("general", log_message)

    def _sanitize_args(self, args: Dict) -> Dict:
        sanitized = {}
        sensitive_keys = ["password", "api_key", "token", "secret", "credential"]
        for key, value in args.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = value
                if isinstance(value, str) and len(value) > 500:
                    sanitized["{0}_length".format(key)] = len(value)
        return sanitized


_logger_instance: Optional[SporeLogger] = None


def get_logger() -> SporeLogger:
    """获取全局日志实例"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = SporeLogger()
    return _logger_instance


def log_error(error_type: str, message: str, exception: Optional[Exception] = None, context: Optional[Dict[str, Any]] = None):
    get_logger().log_error(error_type, message, exception, context)


def log_llm_validation_error(error_type: str, message: str, llm_response: Optional[str] = None, expected_format: Optional[str] = None):
    get_logger().log_llm_validation_error(error_type, message, llm_response, expected_format)


def log_tool_error(tool_name: str, error_message: str, args: Optional[Dict] = None, exception: Optional[Exception] = None, context: Optional[Dict[str, Any]] = None):
    get_logger().log_tool_error(tool_name, error_message, args, exception, context)


def log_info(message: str, context: Optional[Dict[str, Any]] = None, args: Optional[Dict[str, Any]] = None):
    get_logger().log_info(message, context, args)