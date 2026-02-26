"""
PyInstaller 打包环境资源管理器

在 PyInstaller onefile 模式下，所有 Python 模块被解压到临时目录 (sys._MEIPASS)，
导致 __file__ 指向临时目录而非实际安装目录。

本模块在 main_entry.py 最早期被调用，负责：
1. 检测打包环境
2. 确定实际工作目录（spore_backend.exe 所在目录）
3. 设置 os.chdir() 到正确的工作目录
4. 返回工作目录路径供后续使用

注意：Tauri 的 main.rs 在启动后端时已经设置了：
- current_dir = Spore 安装根目录
- SPORE_RESOURCE_DIR = resources/ 子目录
- SPORE_DESKTOP_MODE = 1
所以本模块主要是确保 cwd 正确，并做一些额外的环境初始化。
"""

import sys
import os
from pathlib import Path


def get_exe_dir() -> Path:
    """
    获取可执行文件所在目录
    
    PyInstaller onefile 模式下：
    - sys.executable = 实际 exe 路径 (如 C:/Users/Tom/Desktop/Spore/spore_backend.exe)
    - sys._MEIPASS = 临时解压目录 (如 C:/Users/Tom/AppData/Local/Temp/_MEIxxxxxx)
    - __file__ = 临时解压目录下的路径（不可靠）
    
    Returns:
        Path: exe 所在目录的绝对路径
    """
    return Path(sys.executable).parent.resolve()


def initialize_app() -> Path:
    """
    初始化打包环境
    
    在 main_entry.py 中最早被调用（在所有其他 import 之前），
    确保工作目录和环境变量正确设置。
    
    Returns:
        Path: 工作目录路径
    """
    exe_dir = get_exe_dir()
    
    # 如果 main.rs 已经设置了 cwd（正常情况），os.getcwd() 应该已经正确
    # 但作为保险，如果 cwd 不是 exe 所在目录，则手动设置
    current_cwd = Path.cwd().resolve()
    if current_cwd != exe_dir:
        # cwd 不在 exe 目录，可能是从其他位置启动的
        # 检查 cwd 下是否有 .env 文件（说明 main.rs 已正确设置 cwd）
        if not (current_cwd / '.env').exists() and not (current_cwd / 'resources').exists():
            # cwd 看起来不对，切换到 exe 所在目录
            os.chdir(exe_dir)
    
    working_dir = Path.cwd().resolve()
    
    # 确保关键目录存在
    for dir_name in ['output', 'history', 'logs']:
        (working_dir / dir_name).mkdir(exist_ok=True)
    
    # 设置环境变量（如果 main.rs 没有设置的话）
    if not os.environ.get('SPORE_DESKTOP_MODE'):
        os.environ['SPORE_DESKTOP_MODE'] = '1'
    
    # 如果 SPORE_RESOURCE_DIR 未设置，检查 resources 子目录
    if not os.environ.get('SPORE_RESOURCE_DIR'):
        resource_dir = working_dir / 'resources'
        if resource_dir.exists():
            os.environ['SPORE_RESOURCE_DIR'] = str(resource_dir)
    
    return working_dir