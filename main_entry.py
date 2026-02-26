#!/usr/bin/env python3
"""
Spore AI Agent 统一入口
根据 .env 中的 LAUNCH_MODE 配置自动选择启动模式：
- cli: 命令行模式（默认）
- desktop: 桌面 GUI 模式（Tauri + React）
"""
import sys
import logging
import multiprocessing
from enum import Enum
from typing import Optional
from pathlib import Path

# Windows PyInstaller 打包环境下，multiprocessing 需要 freeze_support
# 必须在 __main__ 模块的最开始调用，且在任何其他代码之前
if __name__ == "__main__":
    multiprocessing.freeze_support()

# 如果是打包环境，先初始化资源
if getattr(sys, 'frozen', False):
    from desktop_app.resource_manager import initialize_app
    working_dir = initialize_app()
    # 打包环境下，.env 在工作目录（exe 所在目录）
    _env_path = working_dir / '.env'
else:
    # 开发环境下，.env 在脚本所在目录
    _env_path = Path(__file__).parent / '.env'

# 确保在导入其他模块前加载 .env
from dotenv import load_dotenv
load_dotenv(dotenv_path=_env_path, override=False)

from base.config import get_config


class LaunchMode(Enum):
    """启动模式枚举"""
    CLI = "cli"
    DESKTOP = "desktop"


def get_launch_mode() -> LaunchMode:
    """
    从配置读取启动模式
    
    Returns:
        LaunchMode: 启动模式枚举值
    """
    config = get_config()
    mode = getattr(config, 'launch_mode', 'cli').lower().strip()
    
    if mode == 'desktop':
        return LaunchMode.DESKTOP
    
    # 无效值或未设置时默认使用 CLI 模式
    if mode not in ('cli', 'desktop'):
        logging.warning(f"无效的 LAUNCH_MODE 值: '{mode}'，使用默认 CLI 模式")
    
    return LaunchMode.CLI


def start_cli_mode() -> None:
    """启动 CLI 模式 - 直接调用原有 main.py"""
    from main import main
    main()


def start_desktop_mode() -> None:
    """启动桌面模式 - FastAPI + Tauri"""
    try:
        from desktop_app.backend.server import run_desktop_app
        run_desktop_app()
    except ImportError as e:
        logging.error(f"桌面模式依赖未安装: {e}")
        logging.error("请先安装桌面模式依赖: pip install fastapi uvicorn websockets")
        logging.error("回退到 CLI 模式...")
        start_cli_mode()


def main() -> None:
    """统一入口"""
    mode = get_launch_mode()
    
    if mode == LaunchMode.DESKTOP:
        # 桌面模式下避免 print 编码问题
        import os
        if os.environ.get('SPORE_DESKTOP_MODE'):
            pass  # 静默启动
        else:
            print("Starting desktop mode...")
        start_desktop_mode()
    else:
        print("Starting CLI mode...")
        start_cli_mode()


if __name__ == "__main__":
    main()
