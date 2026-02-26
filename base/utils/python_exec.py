"""
Python代码执行工具

本模块提供在隔离环境中执行Python代码的功能，支持单行和多行代码执行。
"""

import sys
import io
import traceback
from contextlib import redirect_stdout, redirect_stderr
from typing import Dict, Any
import json


def execute_python(code: str, globals_dict: Dict[str, Any] = None, locals_dict: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    在当前Python环境中执行Python代码（单行或多行）
    
    参数:
        code: 要执行的Python代码字符串（支持单行或多行）
        globals_dict: 全局变量字典（可选）
        locals_dict: 局部变量字典（可选）
    
    返回:
        Dict: {
            "success": bool,          # 执行是否成功
            "stdout": str,            # 标准输出内容
            "stderr": str,            # 标准错误输出
            "result": Any,            # 表达式的返回值（如果是表达式）
            "error": str,             # 错误信息（如果失败）
            "code": str,              # 执行的代码
        }
    
    示例:
        >>> # 执行单行代码
        >>> result = execute_python("print('Hello, World!')")
        >>> result["stdout"]
        'Hello, World!\n'
        
        >>> # 执行多行代码
        >>> code = '''
        ... x = 10
        ... y = 20
        ... print(f"Sum: {x + y}")
        ... '''
        >>> result = execute_python(code)
        
        >>> # 执行表达式并获取返回值
        >>> result = execute_python("2 + 2")
        >>> result["result"]
        4
    """
    if not code or not isinstance(code, str):
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "result": None,
            "error": "代码参数缺失或格式错误",
            "code": str(code) if code else "",
        }
    
    # 去除首尾空白
    code = code.strip()
    
    if not code:
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "result": None,
            "error": "代码为空",
            "code": "",
        }
    
    # 初始化全局和局部变量字典
    if globals_dict is None:
        globals_dict = {}
    if locals_dict is None:
        locals_dict = {}
    
    # 添加一些常用的内置模块到全局命名空间
    globals_dict.setdefault('__builtins__', __builtins__)
    
    # 捕获标准输出和标准错误
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    
    result_value = None
    error_msg = None
    
    try:
        with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
            # 尝试判断是否是单行表达式
            try:
                # 先尝试编译为表达式
                compile(code, '<string>', 'eval')
                is_expression = True
            except SyntaxError:
                # 不是表达式，是语句
                is_expression = False
            
            if is_expression:
                # 执行表达式并获取返回值
                result_value = eval(code, globals_dict, locals_dict)
            else:
                # 执行语句块
                # 注意：为了让 import 在列表推导式等嵌套作用域中可见，
                # 需要使用同一个字典作为 globals 和 locals
                exec(code, globals_dict, globals_dict)
                result_value = None
    
    except Exception as e:
        # 捕获异常
        error_msg = f"{type(e).__name__}: {str(e)}"
        # 获取详细的traceback
        tb_lines = traceback.format_exception(type(e), e, e.__traceback__)
        # 过滤掉内部框架的traceback
        filtered_tb = []
        for line in tb_lines:
            if '<string>' in line or 'Traceback' in line or type(e).__name__ in line:
                filtered_tb.append(line)
        stderr_capture.write(''.join(filtered_tb))
    
    # 获取输出内容
    stdout_content = stdout_capture.getvalue()
    stderr_content = stderr_capture.getvalue()
    
    # 构造返回结果
    return {
        "success": error_msg is None,
        "stdout": stdout_content,
        "stderr": stderr_content,
        "result": result_value,
        "error": error_msg,
        "code": code,
    }
