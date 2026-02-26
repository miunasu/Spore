import os
import re
import subprocess
import time
from typing import Optional, Dict, Any, List, Union
from .encoding import smart_decode


def _parse_cd_command(command: str) -> tuple[Optional[str], str]:
    """
    解析命令字符串，提取 cd 命令的目标目录和剩余命令。
    
    参数:
        command: 命令字符串，可能包含 cd 命令（如 "cd path && command"）
    
    返回:
        (target_dir, remaining_command): 目标目录（如果存在）和剩余的命令
        如果未找到 cd 命令，返回 (None, command)
    """
    import re
    import shlex
    
    # 去除首尾空白
    command = command.strip()
    
    # 匹配 cd 命令的模式：
    # - cd "path" && command
    # - cd path && command
    # - cd /d "path" && command (Windows CMD)
    # - cd /d path && command
    # 支持引号包围的路径，也支持未引号的路径
    
    # 尝试匹配 "cd" 开头的命令
    # 支持: cd path && cmd, cd /d path && cmd, cd "path" && cmd
    cd_pattern = r'^\s*cd\s+(?:/d\s+)?(.+?)\s+&&\s+(.+)$'
    match = re.match(cd_pattern, command, re.IGNORECASE)
    
    if match:
        target_dir = match.group(1).strip()
        remaining_command = match.group(2).strip()
        
        # 移除路径周围的引号
        if (target_dir.startswith('"') and target_dir.endswith('"')) or \
           (target_dir.startswith("'") and target_dir.endswith("'")):
            target_dir = target_dir[1:-1]
        
        # 展开环境变量（如 %USERPROFILE%）
        target_dir = os.path.expandvars(target_dir)
        
        # 转换为绝对路径
        if not os.path.isabs(target_dir):
            # 如果是相对路径，需要相对于当前工作目录
            target_dir = os.path.abspath(target_dir)
        else:
            target_dir = os.path.normpath(target_dir)
        
        return target_dir, remaining_command
    
    return None, command


def execute_command(command: Union[str, List[str]], timeout: Optional[int] = None, encoding: str = None) -> Dict[str, Any]:
    """
    执行系统命令。

    参数:
        command: 字符串（经系统 shell 解析）或 参数列表（直接执行）。
        timeout: 超时时间（秒），None 使用配置默认值。
        encoding: 输出编码，None 时智能检测（Windows优先GBK，Linux/Mac优先UTF-8）。

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
    # 命令安全检查：拦截不应该使用的命令（O(n)复杂度）
    cmd_str = command if isinstance(command, str) else ' '.join(command)
    cmd_lower = cmd_str.strip().lower()
    
    # 使用正则表达式一次性检测所有危险命令
    # 模式：(命令开头或分隔符后) + 危险命令 + (空格或命令结尾)
    # \b 单词边界确保精确匹配
    dangerous_pattern = r'\b(del|rm|rmdir|rd)\b'
    
    match = re.search(dangerous_pattern, cmd_lower)
    if match:
        detected_cmd = match.group(1)
        # 获取匹配位置的上下文
        start_pos = max(0, match.start() - 20)
        end_pos = min(len(cmd_lower), match.end() + 20)
        context = cmd_lower[start_pos:end_pos].strip()
        
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"错误: 不允许在命令中使用 '{detected_cmd}' 删除文件。\n检测到的命令片段: ...{context}...\n请使用 delete_path 工具函数来安全地删除文件或目录。",
            "duration_sec": 0,
            "shell_used": isinstance(command, str),
        }
    
    # 从配置获取默认timeout
    if timeout is None:
        from ..config import get_config
        timeout = get_config().shell_command_timeout
    
    # 确定首选编码（但实际使用字节模式，后续智能解码）
    prefer_encoding = encoding if encoding else ('gbk' if os.name == 'nt' else 'utf-8')
    
    start = time.time()
    shell_used = isinstance(command, str)
    working_dir: Optional[str] = None
    
    # 如果命令是字符串且包含 cd 命令，解析它
    if shell_used:
        target_dir, remaining_cmd = _parse_cd_command(command)
        if target_dir:
            # 验证目录是否存在
            if os.path.isdir(target_dir):
                working_dir = target_dir
                command = remaining_cmd
            else:
                # 目录不存在，返回错误
                return {
                    "ok": False,
                    "returncode": -1,
                    "stdout": "",
                    "stderr": f"错误: 目录不存在: {target_dir}",
                    "duration_sec": 0,
                    "shell_used": shell_used,
                }
    
    # 设置环境变量
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = prefer_encoding
    
    creation_flags = 0
    if os.name == "nt" and shell_used:
        creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    try:
        proc = subprocess.Popen(
            command,  # type: ignore[arg-type]
            shell=shell_used,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,  # 使用字节模式，后续智能解码
            env=env,
            cwd=working_dir,
            creationflags=creation_flags,
        )
    except Exception as exc:
        # 返回错误结果，由 execute_tools 统一记录日志
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"异常: {exc}",
            "duration_sec": 0,
            "shell_used": shell_used,
        }

    stdout_chunks: List[str] = []
    stderr_chunks: List[str] = []
    
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
                    "shell_used": shell_used,
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
    
    # 错误检测策略：
    # 1. returncode != 0 → 错误
    # 2. stderr 包含错误标识 → 错误
    # 3. stdout 包含错误标识 → 错误
    # 
    # 一旦检测到错误，统一设置错误状态：ok=False, returncode非0
    
    original_returncode = proc.returncode
    has_error = False
    
    # 条件1: returncode 非零必定失败
    if original_returncode != 0:
        has_error = True
    
    # 条件2和3: 检查输出中的错误标识（仅当returncode=0时）
    # 用于捕获 a || b 链式命令中 a 失败但 b 成功导致 returncode=0 的情况
    if not has_error:
        # stderr 错误标识列表（宽松检测）
        stderr_error_indicators = [
            # 英文错误标识 - 带标点（强标识）
            'error:', 'exception:', 'failed:', 'fatal:', 'failure:',
            'error -', 'error!', 'errors:',
            # 英文错误短语（中等强度）
            'cannot', 'could not', 'unable to', 'can\'t',
            'not found', 'no such', 'does not exist', 'doesn\'t exist',
            'access denied', 'permission denied', 'forbidden',
            'invalid', 'illegal', 'traceback', 'stack trace',
            'is not recognized', 'not recognized as',  # Windows: command not found
            'syntax error', 'runtime error', 'system error',
            'connection refused', 'connection failed',
            # 中文错误标识
            '错误', '异常', '失败', '无法', '不能', '不存在',
            '找不到', '拒绝访问', '权限不足', '非法', '无效',
            '不是内部或外部命令', '不是可运行的程序', '批处理文件',  # Windows: 命令不存在
            '无效开关', '此时不应有',  # Windows: 参数/语法错误
        ]
        
        # stdout 错误标识列表（严格检测 - 只检测几乎不可能出现在正常输出中的强错误标识）
        # 避免误判 npm init 等命令的正常 JSON 输出
        stdout_error_indicators = [
            # 只保留带标点的强错误标识
            'error:', 'exception:', 'fatal:', 'failure:',
            'error!', 'traceback (most recent call last)',
            # Windows 系统级错误
            '不是内部或外部命令', '不是可运行的程序',
            'is not recognized as an internal or external command',
        ]
        
        # 检查 stderr 中的错误标识（宽松）
        if stderr_output:
            stderr_lower = stderr_output.lower()
            for indicator in stderr_error_indicators:
                if indicator in stderr_lower:
                    has_error = True
                    break
            
            # 额外检查：独立错误词（使用单词边界）
            if not has_error:
                standalone_errors = ['error', 'fail', 'failed', 'failure', 'exception']
                for word in standalone_errors:
                    pattern = r'\b' + re.escape(word) + r'\b'
                    if re.search(pattern, stderr_output, re.IGNORECASE):
                        has_error = True
                        break
        
        # 检查 stdout 中的错误标识（严格 - 用于捕获 a || b 链式命令的错误）
        if not has_error and stdout_output:
            stdout_lower = stdout_output.lower()
            for indicator in stdout_error_indicators:
                if indicator.lower() in stdout_lower:
                    has_error = True
                    break
    
    # 设置ok字段和error_detected标记
    # ok: 综合判断（returncode非0 或 检测到错误标识）
    # error_detected: 是否在输出中检测到错误特征（独立于returncode）
    error_detected = has_error and original_returncode == 0  # 仅当returncode=0但检测到错误时标记
    ok = not has_error
    
    return {
        "ok": ok,
        "returncode": original_returncode,  # 保留原始退出码
        "error_detected": error_detected,   # 是否检测到错误特征（在returncode=0时）
        "stdout": stdout_output,
        "stderr": stderr_output,
        "duration_sec": round(dur, 4),
        "shell_used": shell_used,
    }
