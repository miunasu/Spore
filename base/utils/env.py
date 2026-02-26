import os
import getpass
import platform
from datetime import datetime
from typing import Dict, Any


def get_environment_snapshot() -> Dict[str, Any]:
    """
    一次性获取当前系统环境信息：工作目录、时间、系统基础信息、Python 信息等。
    """
    now = datetime.now().astimezone()
    info: Dict[str, Any] = {
        "cwd": os.getcwd(),
        "now_iso": now.isoformat(),
        "timezone": str(now.tzinfo) if now.tzinfo else None,
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "user": getpass.getuser(),
        # 当前进程可见的环境变量集合（包含系统与用户环境变量）
        "env": {k: v for k, v in os.environ.items()},
    }
    return info
