"""
路径验证和修复工具 (Path Validator)

用于检测和修复 Windows 路径中的转义问题，防止 LLM 输出未正确转义的路径。

主要功能:
- 检测路径中的未转义反斜杠（如 test\test）
- 自动修复为正确的转义格式（test\\test）
- 支持绝对路径和相对路径

使用示例:
    from base.utils.path_validator import validate_and_fix_path, normalize_path_for_pathlib
    
    # 修复单个路径
    fixed_path = validate_and_fix_path(r"test\\test\\file.txt")
    # 返回: "test\\\\test\\\\file.txt"
    
    # 规范化路径用于 pathlib
    normalized = normalize_path_for_pathlib(r"test\\script.py")
"""

import re
import os
from typing import Optional, Tuple


# Windows 转义字符列表（需要特别处理的）
ESCAPE_CHARS = {
    '\\t': 'tab',
    '\\n': 'newline', 
    '\\r': 'carriage return',
    '\\b': 'backspace',
    '\\f': 'form feed',
    '\\v': 'vertical tab',
    '\\a': 'bell',
    '\\0': 'null'
}


def detect_unescaped_path(path: str) -> Tuple[bool, Optional[str]]:
    """
    检测路径中是否存在未转义的反斜杠
    
    参数:
        path: 待检测的路径字符串
        
    返回:
        (is_problematic, reason): 
            - is_problematic: 是否存在问题
            - reason: 问题描述（如果存在）
    """
    if not path or not isinstance(path, str):
        return False, None
    
    # 跳过已经是正确格式的路径（双反斜杠或正斜杠）
    if '\\\\' in path or '/' in path:
        # 但仍需检查是否混合了单反斜杠
        if re.search(r'(?<!\\)\\(?!\\)', path):
            return True, "路径中混合了单反斜杠和双反斜杠"
        return False, None
    
    # 检测单个反斜杠（未转义）
    if '\\' in path:
        # 检查是否包含常见的转义序列
        for escape_seq, name in ESCAPE_CHARS.items():
            if escape_seq in path:
                return True, f"路径包含未转义的 {escape_seq} ({name})"
        
        # 检查是否是路径分隔符（如 test\test）
        # 匹配模式：字母/数字 + 单反斜杠 + 字母/数字
        if re.search(r'[a-zA-Z0-9_\-.]\\[a-zA-Z0-9_\-.]', path):
            return True, "路径包含未转义的反斜杠分隔符"
    
    return False, None


def validate_and_fix_path(path: str, auto_fix: bool = True) -> str:
    """
    验证并修复路径中的转义问题
    
    参数:
        path: 原始路径
        auto_fix: 是否自动修复（默认True）
        
    返回:
        修复后的路径（如果 auto_fix=False 且有问题，返回原路径）
    """
    if not path or not isinstance(path, str):
        return path
    
    # 检测问题
    is_problematic, reason = detect_unescaped_path(path)
    
    if not is_problematic:
        return path
    
    if not auto_fix:
        return path
    
    # 修复策略：将单个反斜杠替换为双反斜杠
    # 但要避免将已经是双反斜杠的再次替换
    
    # 先将所有双反斜杠临时替换为占位符
    placeholder = "<<<DOUBLE_BACKSLASH>>>"
    fixed_path = path.replace('\\\\', placeholder)
    
    # 将单反斜杠替换为双反斜杠
    fixed_path = fixed_path.replace('\\', '\\\\')
    
    # 恢复占位符为双反斜杠
    fixed_path = fixed_path.replace(placeholder, '\\\\')
    
    return fixed_path


def normalize_path_separators(path: str, target: str = 'windows') -> str:
    """
    标准化路径分隔符
    
    参数:
        path: 原始路径
        target: 目标系统 ('windows' 或 'unix')
        
    返回:
        标准化后的路径
    """
    if not path:
        return path
    
    if target == 'windows':
        # 转换为 Windows 格式（反斜杠）
        return path.replace('/', '\\')
    else:
        # 转换为 Unix 格式（正斜杠）
        return path.replace('\\', '/')


def is_absolute_path(path: str) -> bool:
    """
    判断是否为绝对路径
    
    支持 Windows 和 Unix 格式
    """
    if not path:
        return False
    
    # Windows: C:\ 或 \\server\share
    if re.match(r'^[a-zA-Z]:[/\\]', path) or path.startswith('\\\\'):
        return True
    
    # Unix: /path
    if path.startswith('/'):
        return True
    
    return False


def safe_path_join(*parts) -> str:
    """
    安全的路径拼接，自动处理转义
    
    参数:
        *parts: 路径组件
        
    返回:
        拼接后的路径（已修复转义）
    """
    # 使用 os.path.join 拼接
    joined = os.path.join(*parts)
    
    # 确保转义正确
    return validate_and_fix_path(joined)


def normalize_path_for_pathlib(path: str) -> str:
    """
    规范化路径用于 pathlib.Path，避免转义字符问题
    
    该函数处理 LLM 可能输出的各种路径格式：
    - 单反斜杠: test\\test -> test/test
    - 双反斜杠: test\\\\test -> test/test
    - 三反斜杠: test\\\\\\test -> test/test
    - 混合格式: test\\\\path\\file -> test/path/file
    - 已经是正斜杠: test/test -> test/test (不变)
    
    正斜杠在 Windows 和 Unix 系统中都能被 pathlib.Path 正确识别，
    且不会有转义字符问题（如 \\t, \\n 等）。
    
    参数:
        path: 原始路径字符串
        
    返回:
        规范化后的路径（使用正斜杠）
        
    示例:
        >>> normalize_path_for_pathlib(r"C:\\test\\file.txt")
        'C:/test/file.txt'
        
        >>> normalize_path_for_pathlib("C:\\\\\\\\test\\\\\\\\file.txt")
        'C:/test/file.txt'
        
        >>> normalize_path_for_pathlib(r"test\\\\\\path\\file.txt")
        'test/path/file.txt'
    """
    if not path or not isinstance(path, str):
        return path
    
    # 检测 UNC 路径（以 \\ 或 \\\\ 开头）
    is_unc = path.startswith('\\\\') or path.startswith('//')
    
    # 步骤1: 将所有反斜杠（无论多少个）统一转换为正斜杠
    normalized = re.sub(r'\\+', r'/', path)
    
    # 步骤2: 清理多余的正斜杠
    if is_unc:
        # UNC 路径：保留开头的 //，清理后面的多余斜杠
        # 先移除开头的所有斜杠
        normalized = normalized.lstrip('/')
        # 添加回 // 前缀
        normalized = '//' + re.sub(r'/+', '/', normalized)
    else:
        # 普通路径：清理所有多余斜杠
        normalized = re.sub(r'/+', '/', normalized)
    
    return normalized

