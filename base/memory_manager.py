import time 
import json
import os
from typing import List, Dict
from datetime import datetime
from pathlib import Path


# 历史记录保存目录
HISTORY_DIR = "history"


def _ensure_history_dir():
    """确保 history 目录存在"""
    if not os.path.exists(HISTORY_DIR):
        os.makedirs(HISTORY_DIR)


def save_messages(messages: List[Dict[str, str]]):
    """保存对话历史到 history 目录"""
    _ensure_history_dir()
    filename = f"{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.mem"
    filepath = os.path.join(HISTORY_DIR, filename)
    
    with open(filepath, "w", encoding='utf-8') as f:
        json.dump(messages, f, ensure_ascii=False, indent=2)
    print(f"[对话已保存] 文件: {filepath}")
    return filepath


def load_messages(filename: str) -> List[Dict[str, str]]:
    """从 history 目录加载对话历史"""
    # 始终从 history 目录读取
    filepath = os.path.join(HISTORY_DIR, filename)
    
    with open(filepath, "r", encoding='utf-8') as f:
        return json.load(f)


def get_latest_history_file() -> str:
    """获取最近的历史记录文件路径"""
    _ensure_history_dir()
    
    # 获取所有 .mem 文件
    mem_files = [f for f in os.listdir(HISTORY_DIR) if f.endswith('.mem')]
    
    if not mem_files:
        raise FileNotFoundError("没有找到历史记录文件")
    
    # 按修改时间排序，获取最新的
    mem_files.sort(key=lambda f: os.path.getmtime(os.path.join(HISTORY_DIR, f)), reverse=True)
    latest_file = mem_files[0]
    
    return os.path.join(HISTORY_DIR, latest_file)


    