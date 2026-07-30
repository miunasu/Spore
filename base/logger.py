"""
日志系统模块

提供统一的日志记录功能，记录错误和 LLM 输入验证问题
日志文件保存在项目根目录的 logs 文件夹中

目录结构：
  logs/<进程启动时间>/                 # 进程级会话目录（兼容旧逻辑）
    general.log / error.log / ...
    conversations/<session_id>/        # 一样本/一对话独立日志
      general.log / error.log / ...
      raw.log                          # LLM 回复原始记录（仅落盘，不推送到 Desktop 日志栏）
                                       #   RECEIVED       = 收到即记的完整 wire 原文，不加工不截断
                                       #   EXTRACTED TEXT = 提取后的正文 + 健康诊断元信息
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

    def get_conversation_log_dir(self, conversation_id: str) -> Path:
        """按显式对话 ID 定位日志目录（用于 contextvar 不可用的子进程）。"""
        conv_dir = self.get_process_log_dir() / "conversations" / _sanitize_conversation_id(conversation_id)
        conv_dir.mkdir(parents=True, exist_ok=True)
        meta = conv_dir / "session_id.txt"
        try:
            if not meta.exists():
                meta.write_text(conversation_id, encoding="utf-8")
        except OSError:
            pass
        return conv_dir

    def get_active_log_dir(self) -> Path:
        """返回当前上下文应写入的日志目录（按对话隔离）。"""
        env_conv_dir = os.environ.get("SPORE_CONVERSATION_LOG_DIR")
        if env_conv_dir:
            path = Path(env_conv_dir)
            path.mkdir(parents=True, exist_ok=True)
            return path

        cid = _resolve_conversation_id()
        if cid:
            return self.get_conversation_log_dir(cid)
        return self.get_process_log_dir()

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
        # raw 日志按开关创建，关闭时不生成空文件
        if getattr(_config, "log_raw_enabled", False):
            # raw 日志刻意不轮转：单条 RECEIVED 记录可能远超 maxBytes，一旦开启轮转，
            # 每写一条就触发一次 rollover，backupCount 很快把先前轮次的原文删掉——
            # 那和"完整记录"的目的直接冲突。宁可让文件长，也不丢已收到的原文。
            target["raw"] = self._create_logger(
                f"raw.{logger_suffix}",
                log_dir / getattr(_config, "log_raw_filename", "raw.log"),
                rotating=False,
            )

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

    def _get_loggers_for_conversation(self, conversation_id: Optional[str]) -> Dict[str, logging.Logger]:
        """按显式对话 ID 取日志器；未提供时回退到当前上下文。"""
        if not conversation_id:
            return self._get_loggers_for_active_context()[0]
        key = _sanitize_conversation_id(conversation_id)
        with SporeLogger._handler_lock:
            cached = self._dynamic_loggers.get(key)
            if cached is not None:
                return cached
            log_dir = self.get_conversation_log_dir(conversation_id)
            loggers: Dict[str, logging.Logger] = {}
            self._setup_loggers_into(loggers, log_dir, logger_suffix=key)
            self._dynamic_loggers[key] = loggers
            return loggers

    def _create_logger(self, name: str, log_file: Path, rotating: bool = True) -> logging.Logger:
        """创建单文件日志器。

        Args:
            rotating: 是否按大小轮转。raw 日志传 False（maxBytes=0 即禁用轮转），
                避免超大单条记录把历史原文挤出 backupCount 窗口。
        """
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
            maxBytes=_logger_config.log_file_max_size if rotating else 0,
            backupCount=_logger_config.log_backup_count if rotating else 0,
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

    def log_raw_received(
        self,
        payload: Any,
        conversation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """收到 LLM 数据的那一刻立即把原文完整落盘。

        这是 raw 日志的第一现场：不提取、不裁剪、不做任何解析，只把收到的东西原样
        写下来。之所以必须在"收到即记"这个时点写，是因为后面的提取 / 协议解析 /
        健康判定任何一步抛异常，原文就永远消失了，空回复与截断故障也就彻底失去可
        归因的证据。

        payload 是字符串（wire body 原文）时原样写出，绝不 json.dumps 再包一层：
        那会把响应体变成一个带满转义的单行 JSON 字符串，保真度和可读性双输。
        只有 dict 等结构化对象才需要序列化。

        仅落盘到对应会话目录下的 raw 日志，刻意不调用 _send_to_monitor——原文体量
        可能极大，推到 Desktop 日志栏只会把界面刷爆。

        Args:
            payload: 收到的原始数据。优先传字符串（HTTP 响应体原文）；
                拿不到 wire body 时可退回 model_dump() 之类的 dict
            conversation_id: 显式对话 ID；子进程中 contextvar 不可用时必须传
            metadata: 附带的定位信息（request_id / model / payload_kind / 轮次序号等）
        """
        from .config import get_config
        if not get_config().log_raw_enabled:
            return
        try:
            loggers = self._get_loggers_for_conversation(conversation_id)
            raw_logger = loggers.get("raw")
            if raw_logger is None:
                return
            # 字符串直接原样落盘；其余类型才序列化，且序列化同样不设长度上限
            if isinstance(payload, str):
                body = payload
            else:
                body = self._stringify_raw_payload(payload)
            header = dict(metadata or {})
            header.setdefault("payload_type", type(payload).__name__)
            header["received_length"] = len(body)
            raw_logger.debug("\n".join([
                json.dumps(header, ensure_ascii=False),
                "----- RECEIVED -----",
                body,
                "----- END RECEIVED -----",
            ]))
            # 注意：raw 日志刻意不调用 _send_to_monitor，只落地到文件
        except Exception:
            # raw 日志属于旁路记录，任何异常都不应影响主流程
            pass

    def log_raw_response(
        self,
        content: str,
        conversation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """记录提取后的 LLM 回复正文与健康诊断元信息。

        仅落盘到对应会话目录下的 raw 日志，不推送到日志监控 / Desktop 左栏日志。

        与 log_raw_received 配对：后者存"收到的原文"，本方法存"我们从原文里提取出
        了什么、怎么判定的"。两条对照才能区分"模型没生成文本块"与"生成了但被提取
        逻辑丢掉"——单看任何一条，这两种空回复在日志里长得一模一样。

        Args:
            content: 提取后的 LLM 回复正文（不截断、不做任何解析）
            conversation_id: 显式对话 ID；子进程中 contextvar 不可用时必须传
            metadata: 附带的请求元信息（model / request_id / usage /
                api_stop_reason / finish_state / truncated / content_blocks 等）
        """
        from .config import get_config
        if not get_config().log_raw_enabled:
            return
        try:
            loggers = self._get_loggers_for_conversation(conversation_id)
            raw_logger = loggers.get("raw")
            if raw_logger is None:
                return
            header = dict(metadata or {})
            header["extracted_text_length"] = len(content or "")
            raw_logger.debug("\n".join([
                json.dumps(header, ensure_ascii=False),
                "----- EXTRACTED TEXT -----",
                content or "",
                "----- END EXTRACTED TEXT -----",
            ]))
            # 注意：raw 日志刻意不调用 _send_to_monitor，只落地到文件
        except Exception:
            # raw 日志属于旁路记录，任何异常都不应影响主流程
            pass

    def _stringify_raw_payload(self, payload: Any) -> str:
        """把非字符串的原始数据结构转成可落盘的字符串。

        刻意不设长度上限：raw 日志存在的意义就是完整，而截断恰好会抹掉排查截断
        故障最需要的尾部。任何序列化失败都退化为 repr，绝不让日志旁路把主流程带崩。
        """
        try:
            return json.dumps(payload, ensure_ascii=False, default=str)
        except Exception:
            try:
                return repr(payload)
            except Exception:
                return "<unserializable payload>"

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

    def _close_conversation_loggers(self, conversation_id: str) -> None:
        """关闭并从缓存中移除指定会话的所有日志器，释放文件句柄。

        Windows 下日志文件被 handler 持有时 shutil.rmtree 会抛 PermissionError；
        必须先 close() 再删目录。
        """
        key = _sanitize_conversation_id(conversation_id)
        with SporeLogger._handler_lock:
            loggers = self._dynamic_loggers.pop(key, None)
        if not loggers:
            return
        for logger in loggers.values():
            for handler in list(logger.handlers):
                try:
                    handler.flush()
                    handler.close()
                except Exception:
                    pass
                try:
                    logger.removeHandler(handler)
                except Exception:
                    pass

    def delete_conversation_log_dir(self, conversation_id: str) -> None:
        """删除指定会话的日志目录（会话删除时联动调用）。

        先关闭文件句柄（Windows 要求），再 rmtree。只删 conversations/ 子目录，
        绝不触碰进程级根目录。路径安全检查：resolved 父级必须是 conversations/。
        静默失败 —— 日志清理不能阻断会话删除的主流程。
        """
        import shutil
        try:
            key = _sanitize_conversation_id(conversation_id)
            proc_dir = self.get_process_log_dir()
            conv_dir = proc_dir / "conversations" / key
            # 路径安全：只允许删 conversations/ 的直接子目录
            expected_parent = (proc_dir / "conversations").resolve()
            if conv_dir.resolve().parent != expected_parent:
                return
            self._close_conversation_loggers(conversation_id)
            if conv_dir.exists():
                shutil.rmtree(conv_dir, ignore_errors=True)
        except Exception:
            pass


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


def log_raw_received(
    payload: Any,
    conversation_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """收到即记：把收到的原始数据完整落盘（仅落盘，不上报日志监控 / Desktop 日志栏）"""
    get_logger().log_raw_received(payload, conversation_id, metadata)


def log_raw_response(
    content: str,
    conversation_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """记录提取后的回复正文与健康诊断（仅落盘，不上报日志监控 / Desktop 日志栏）"""
    get_logger().log_raw_response(content, conversation_id, metadata)


def delete_conversation_log_dir(conversation_id: str) -> None:
    """会话删除时联动清除该会话的日志目录（先关句柄，再 rmtree）。

    仅清理当前进程会话目录下的 conversations/<id>/ 子目录，不触碰其他路径。
    静默失败，日志清理不阻断调用方的主流程。
    """
    get_logger().delete_conversation_log_dir(conversation_id)
