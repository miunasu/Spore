import os
import re
import subprocess
import time

from typing import Optional, Dict, Any, List, Union
from .encoding import smart_decode


MULTILINE_COMMAND_HINT = (
    "For multiline PowerShell or Python commands, pass real newlines with "
    "@SPORE:CONTENT_START ... @SPORE:CONTENT_END. PowerShell here-strings "
    "require a real newline immediately after @' or @\"."
)


def _is_unescaped_backslash(text: str, index: int) -> bool:
    backslashes = 0
    pos = index - 1
    while pos >= 0 and text[pos] == "\\":
        backslashes += 1
        pos -= 1
    return backslashes % 2 == 0


def _escaped_newline_length(text: str, index: int) -> int:
    if not _is_unescaped_backslash(text, index):
        return 0
    if text.startswith("\\r\\n", index):
        return 4
    if text.startswith("\\n", index):
        return 2
    return 0


def _looks_like_here_string_start(command: str, index: int) -> bool:
    if index > 0:
        prev = command[index - 1]
        if not (prev.isspace() or prev in ";|=([{,"):
            return False
    return command.startswith("@'", index) or command.startswith('@"', index)


def _replace_escaped_newlines_outside_quotes(text: str) -> str:
    result: List[str] = []
    in_single = False
    in_double = False
    escaped = False
    i = 0

    while i < len(text):
        escaped_newline_len = _escaped_newline_length(text, i)
        if escaped_newline_len and not in_single and not in_double:
            result.append("\n")
            i += escaped_newline_len
            escaped = False
            continue

        char = text[i]
        result.append(char)

        if char == "\\":
            escaped = not escaped
        else:
            if char == "'" and not in_double and not escaped:
                in_single = not in_single
            elif char == '"' and not in_single and not escaped:
                in_double = not in_double
            escaped = False

        i += 1

    return "".join(result)


def _find_escaped_here_string_close(command: str, start: int, quote: str) -> tuple[int, int]:
    i = start
    while i < len(command):
        newline_len = _escaped_newline_length(command, i)
        if newline_len and command.startswith(f"{quote}@", i + newline_len):
            return i, newline_len
        i += 1
    return -1, 0


def _normalize_escaped_powershell_here_strings(command: str) -> tuple[str, bool]:
    """Recover common quoted-tool-call output like @'\\n...\\n'@."""
    result: List[str] = []
    changed = False
    i = 0

    while i < len(command):
        if _looks_like_here_string_start(command, i):
            quote = command[i + 1]
            body_start = i + 2
            opener_newline_len = _escaped_newline_length(command, body_start)
            if opener_newline_len:
                content_start = body_start + opener_newline_len
                close_start, close_newline_len = _find_escaped_here_string_close(
                    command, content_start, quote
                )
                if close_start >= 0:
                    body = command[content_start:close_start]
                    result.append(command[i:i + 2])
                    result.append("\n")
                    result.append(_replace_escaped_newlines_outside_quotes(body))
                    result.append("\n")
                    result.append(f"{quote}@")
                    i = close_start + close_newline_len + 2
                    changed = True
                    continue

        result.append(command[i])
        i += 1

    return "".join(result), changed


def _validate_powershell_here_strings(command: str) -> Optional[str]:
    i = 0
    while i < len(command):
        if _looks_like_here_string_start(command, i):
            after = i + 2
            if after >= len(command) or command[after] not in "\r\n":
                return (
                    "Invalid PowerShell here-string header: @' or @\" must be "
                    "followed by a real newline, not inline text or an escaped "
                    "\\n sequence."
                )
        i += 1
    return None


def _attach_hints(result: Dict[str, Any], hints: List[str]) -> Dict[str, Any]:
    if hints:
        result["hints"] = hints
    return result


def _is_powershell_progress_noise(stderr: str) -> bool:
    stripped = stderr.strip()
    return (
        stripped.startswith("#< CLIXML")
        and '<Obj S="progress"' in stripped
        and '<S S="Error">' not in stripped
    )


def execute_command(command: Union[str, List[str]], timeout: Optional[int] = None, encoding: str = None, working_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    使用原生 PowerShell 执行系统命令。

    参数:
        command: 字符串（经 PowerShell 解析）或 参数列表（直接执行）。
        timeout: 超时时间（秒），None 使用配置默认值。
        encoding: 输出编码，None 时智能检测（Windows优先GBK，Linux/Mac优先UTF-8）。
        working_dir: 工作目录（可选），指定命令执行的目录。

    返回:
        {
          ok: bool,               # 综合判断：returncode!=0 或 检测到错误标识时为False
          returncode: int,        # 原始进程退出码（未修改）
          error_detected: bool,   # 仅当returncode=0但检测到错误输出特征时为True
          stdout: str,            # 标准输出（智能解码）
          stderr: str,            # 错误输出（智能解码）
          duration_sec: float,    # 执行耗时（秒）
          shell_used: bool        # 是否使用shell执行
        }
        
    注意:
        - ok=False 表示检测到错误（returncode!=0 或 输出中有错误标识）
        - returncode 保持原始值，LLM可据此判断命令实际是否失败
        - error_detected 仅在 returncode=0 但输出中检测到错误时为True
        - LLM应综合 returncode、error_detected、stderr、stdout 判断执行结果
    """
    # 命令安全检查：拦截危险的删除命令
    hints: List[str] = []
    if isinstance(command, str):
        command, normalized_here_string = _normalize_escaped_powershell_here_strings(command)
        if normalized_here_string:
            hints.append("Normalized escaped PowerShell here-string newlines in command input.")

        here_string_error = _validate_powershell_here_strings(command)
        if here_string_error:
            return _attach_hints({
                "ok": False,
                "returncode": -1,
                "error_detected": False,
                "stdout": "",
                "stderr": here_string_error,
                "duration_sec": 0,
                "shell_used": True,
            }, [MULTILINE_COMMAND_HINT])

    cmd_str = command if isinstance(command, str) else ' '.join(command)
    cmd_lower = cmd_str.strip().lower()
    
    # Command intercept strategies (master: COMMAND_INTERCEPT / config.command_intercept)
    from ..config import get_config
    _cfg = get_config()

    # strategy: shell_write — block Set-Content/Out-File (BOM risk)
    if _cfg.is_intercept_enabled("shell_write"):
        write_file_pattern = r'\b(set-content|out-file)\b'
        write_match = re.search(write_file_pattern, cmd_lower)
        if write_match:
            detected_cmd = write_match.group(1)
            return {
                "ok": False,
                "returncode": -1,
                "stdout": "",
                "stderr": (
                    f"错误: 不允许使用 '{detected_cmd}' 写文件（会产生BOM编码问题）。\n"
                    f"请使用 file type=write 工具来写入文件。\n"
                    f"（可在桌面菜单关闭“拦截开关”以放行）"
                ),
                "duration_sec": 0,
                "shell_used": isinstance(command, str),
            }

    # strategy: shell_delete — block del/rm/rmdir/rd/Remove-Item
    if _cfg.is_intercept_enabled("shell_delete"):
        dangerous_pattern = r'\b(del|rm|rmdir|rd|remove-item)\b'
        match = re.search(dangerous_pattern, cmd_lower)
        if match:
            detected_cmd = match.group(1)
            start_pos = max(0, match.start() - 20)
            end_pos = min(len(cmd_lower), match.end() + 20)
            context = cmd_lower[start_pos:end_pos].strip()
            return {
                "ok": False,
                "returncode": -1,
                "stdout": "",
                "stderr": (
                    f"错误: 不允许在命令中使用 '{detected_cmd}' 删除文件。\n"
                    f"检测到的命令片段: ...{context}...\n"
                    f"请使用 file type=delete 工具来安全地删除文件或目录。\n"
                    f"（可在桌面菜单关闭“拦截开关”以允许 shell 删除）"
                ),
                "duration_sec": 0,
                "shell_used": isinstance(command, str),
            }

    # 检测交互式命令：这些命令会等待用户输入，导致 agent 卡住
    # interactive_patterns = [
    #     # 文本编辑器
    #     r'\b(vim|vi|nano|emacs|notepad|code|subl)\b',
    #     # 交互式 shell（单独调用，不带 -c 或脚本文件）
    #     # 使用 \s*$ 确保是命令末尾，避免误拦截 "bash script.sh"
    #     r'\b(bash|zsh|fish)\s*$',
    #     r'\bsh\s*$',  # sh 单独匹配，避免误拦截 bash
    #     r'\b(cmd|powershell|pwsh)\s*$',
    #     # 交互式工具
    #     r'\b(top|htop|less|more|tail\s+-f)\b',
    #     # 需要输入的 PowerShell 命令
    #     r'\b(read-host|get-credential)\b',
    #     # SSH/远程连接
    #     r'\b(ssh|telnet|ftp|sftp)\b',
    #     # 调试器
    #     r'\b(gdb|lldb|pdb|windbg)\b',
    #     # 数据库客户端（单独调用）
    #     r'\b(mysql|psql|mongo|redis-cli|sqlite3)\s*$',
    #     # 交互式安装/配置（没有 -y/--yes 参数）
    #     r'\b(npm\s+init|yarn\s+init|cargo\s+init)\b(?!.*(-y|--yes))',
    #     # 文本查看器（不带文件参数）
    #     r'\b(cat|type)\s*$',
    # ]
    
    # for pattern in interactive_patterns:
    #     match = re.search(pattern, cmd_lower)
    #     if match:
    #         detected_cmd = match.group(1) if match.lastindex else match.group(0)
    #         return {
    #             "ok": False,
    #             "returncode": -1,
    #             "stdout": "",
    #             "stderr": f"错误: 不允许执行交互式命令 '{detected_cmd}'。\nAgent 无法处理需要持续交互的命令。\n如需执行脚本，请使用非交互模式（如: python script.py, node script.js）。",
    #             "duration_sec": 0,
    #             "shell_used": isinstance(command, str),
    #         }
    
    # 从配置获取默认timeout
    if timeout is None:
        from ..config import get_config
        timeout = get_config().shell_command_timeout
    
    # 确定首选编码
    prefer_encoding = encoding if encoding else ('gbk' if os.name == 'nt' else 'utf-8')
    
    start = time.time()
    shell_used = isinstance(command, str)
    cwd: Optional[str] = None
    
    # 处理 working_dir 参数
    if working_dir:
        # 规范化路径
        if not os.path.isabs(working_dir):
            working_dir = os.path.abspath(working_dir)
        else:
            working_dir = os.path.normpath(working_dir)
        
        # 验证目录存在性
        if os.path.isdir(working_dir):
            cwd = working_dir
        else:
            return {
                "ok": False,
                "returncode": -1,
                "stdout": "",
                "stderr": f"错误: 工作目录不存在: {working_dir}",
                "duration_sec": 0,
                "shell_used": isinstance(command, str),
            }
    
    # 设置环境变量
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = prefer_encoding
    
    # Windows 创建标志：防止终端闪屏
    creation_flags = 0
    if os.name == "nt":
        # CREATE_NO_WINDOW (0x08000000) 完全隐藏控制台窗口
        # CREATE_NEW_PROCESS_GROUP (0x00000200) 创建新进程组
        creation_flags = 0x08000000 | subprocess.CREATE_NEW_PROCESS_GROUP
    
    # Windows 系统：构建 PowerShell 命令
    # 使用 -EncodedCommand 避免引号/转义被 PowerShell 解析
    ps_args = None
    if os.name == "nt" and shell_used:
        # 查找 PowerShell 路径
        import shutil
        import base64
        ps_exe = shutil.which('pwsh')  # 优先 PowerShell 7+
        if not ps_exe:
            ps_exe = shutil.which('powershell')  # 回退到 PowerShell 5.x
        
        if ps_exe:
            if encoding is None:
                prefer_encoding = 'utf-8'
                env['PYTHONIOENCODING'] = 'utf-8'
            # 自动设置编码：$OutputEncoding 确保管道传中文，PYTHONIOENCODING 确保 Python stdout 输出 UTF-8
            full_command = '$env:PYTHONIOENCODING="utf-8"; $OutputEncoding = New-Object System.Text.UTF8Encoding $false; ' + command
            encoded = base64.b64encode(full_command.encode('utf-16-le')).decode('ascii')
            ps_args = [ps_exe, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded]
            shell_used = False  # 改为 False，因为我们直接调用可执行文件

    try:
        proc = subprocess.Popen(
            ps_args if ps_args else command,  # type: ignore[arg-type]
            shell=shell_used,  # PowerShell 模式下为 False
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,  # 使用字节模式，后续智能解码
            env=env,
            cwd=cwd,
            creationflags=creation_flags,
        )
    except Exception as exc:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"异常: {exc}",
            "duration_sec": 0,
            "shell_used": isinstance(command, str),
        }

    stdout_chunks: List[bytes] = []
    stderr_chunks: List[bytes] = []
    
    # 整体超时控制
    deadline = start + timeout if timeout else None

    try:
        while True:
            # 检查是否超过整体超时时间
            if deadline and time.time() >= deadline:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                
                dur = time.time() - start
                stdout_output = smart_decode(b"".join(stdout_chunks), prefer_encoding)
                return {
                    "ok": False,
                    "returncode": -1,
                    "stdout": stdout_output,
                    "stderr": f"命令执行超时 (>{timeout}秒)",
                    "duration_sec": round(dur, 4),
                    "shell_used": isinstance(command, str),
                }
            
            try:
                # 使用短超时轮询，以便能检查整体超时
                out, err = proc.communicate(timeout=0.2)
                if out:
                    stdout_chunks.append(out)
                if err:
                    stderr_chunks.append(err)
                break
            except subprocess.TimeoutExpired as exc:
                # 继续收集输出并继续轮询
                if exc.stdout:
                    stdout_chunks.append(exc.stdout)
                if exc.stderr:
                    stderr_chunks.append(exc.stderr)
                continue
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        return None

    dur = time.time() - start
    
    # 智能解码：合并字节块并尝试多种编码
    stdout_bytes = b"".join(stdout_chunks)
    stderr_bytes = b"".join(stderr_chunks)
    stdout_output = smart_decode(stdout_bytes, prefer_encoding)
    stderr_output = smart_decode(stderr_bytes, prefer_encoding)
    if _is_powershell_progress_noise(stderr_output):
        stderr_output = ""
    
    # 错误检测策略
    original_returncode = proc.returncode
    has_error = False
    
    # 条件1: returncode 非零必定失败
    if original_returncode != 0:
        has_error = True
    
    # 条件2和3: 检查输出中的错误标识（仅当returncode=0时）
    if not has_error:
        # stderr 错误标识列表（宽松检测）
        stderr_error_indicators = [
            # 英文错误标识
            'error:', 'exception:', 'failed:', 'fatal:', 'failure:',
            'error -', 'error!', 'errors:',
            'cannot', 'could not', 'unable to', 'can\'t',
            'not found', 'no such', 'does not exist', 'doesn\'t exist',
            'access denied', 'permission denied', 'forbidden',
            'invalid', 'illegal', 'traceback', 'stack trace',
            'is not recognized', 'not recognized as',
            'syntax error', 'runtime error', 'system error',
            'connection refused', 'connection failed',
            # 中文错误标识
            '错误', '异常', '失败', '无法', '不能', '不存在',
            '找不到', '拒绝访问', '权限不足', '非法', '无效',
            '不是内部或外部命令', '不是可运行的程序', '批处理文件',
            '无效开关', '此时不应有',
        ]
        
        # stdout 错误标识列表（严格检测）
        stdout_error_indicators = [
            'error:', 'exception:', 'fatal:', 'failure:',
            'error!', 'traceback (most recent call last)',
            '不是内部或外部命令', '不是可运行的程序',
            'is not recognized as an internal or external command',
        ]
        
        # 检查 stderr 中的错误标识
        if stderr_output:
            stderr_lower = stderr_output.lower()
            for indicator in stderr_error_indicators:
                if indicator in stderr_lower:
                    has_error = True
                    break
            
            # 额外检查：独立错误词
            if not has_error:
                standalone_errors = ['error', 'fail', 'failed', 'failure', 'exception']
                for word in standalone_errors:
                    pattern = r'\b' + re.escape(word) + r'\b'
                    if re.search(pattern, stderr_output, re.IGNORECASE):
                        has_error = True
                        break
        
        # 检查 stdout 中的错误标识（严格）
        if not has_error and stdout_output:
            stdout_lower = stdout_output.lower()
            for indicator in stdout_error_indicators:
                if indicator.lower() in stdout_lower:
                    has_error = True
                    break
    
    # 设置返回值
    error_detected = has_error and original_returncode == 0
    ok = not has_error
    
    return _attach_hints({
        "ok": ok,
        "returncode": original_returncode,
        "error_detected": error_detected,
        "stdout": stdout_output,
        "stderr": stderr_output,
        "duration_sec": round(dur, 4),
        "shell_used": isinstance(command, str),
    }, hints)
