import sys
import os
from typing import Optional
from base.todo_manager import get_current_todos_for_prompt

extra_line = 0
last_todo_content = ""
def clear_printed_lines(num_lines: int) -> None:
    """
    清除终端中已打印的指定行数。
    
    参数:
        num_lines: 要清除的行数
    
    注意:
        - 使用 ANSI 转义序列向上移动光标并清除行
        - 需要终端支持 ANSI 转义序列（Windows 10+ 默认支持）
    """
    if num_lines <= 0:
        return
    
    # 向上移动光标并清除每一行
    for _ in range(num_lines):
        # \033[A: 光标上移一行
        # \033[2K: 清除整行
        # \r: 回到行首
        sys.stdout.write("\033[A\033[2K\r")
    sys.stdout.flush()


def clear_todo_block(todo_content: Optional[str]) -> None:
    """
    清除 TODO 块（包括 "TODO:" 标题行和 TODO 内容）。
    从下往上清除行，直到清除完整个 TODO 块。
    
    参数:
        todo_content: TODO 内容（不包括 "TODO:" 标题）
    
    工作原理:
        1. 计算 TODO 内容占用的行数
        2. 加上 "TODO:" 标题行（1行）
        3. 从下往上清除所有这些行
    
    示例:
        >>> todo = "1. 步骤一  -\n2. 步骤二  -\n"
        >>> print("TODO:")
        >>> print(todo)
        >>> clear_todo_block(todo)  # 清除整个 TODO 块
    """
    global extra_line
    if todo_content is None:
        return
    
    # 获取终端宽度
    try:
        terminal_width = os.get_terminal_size().columns
    except Exception:
        terminal_width = 80
    
    # 计算 TODO 内容占用的行数
    text = str(todo_content)
    lines = text.split('\n')
    content_lines = 0
    
    for line in lines:
        if not line:
            content_lines += 1
        else:
            line_length = len(line)
            content_lines += (line_length + terminal_width - 1) // terminal_width
    
    # 总行数 = TODO 内容行数 + "TODO:" 标题行
    total_lines = content_lines + extra_line
    extra_line = 0
    # 从下往上清除所有行
    clear_printed_lines(total_lines)
    total_lines = 0


def todo_print():
    global last_todo_content
    global extra_line
    todo_content = get_current_todos_for_prompt()
    if todo_content and todo_content != "当前没有任务规划":
        todo_str = "TODO:\n" + todo_content
        extra_line += 1
        print(todo_str)
        last_todo_content = todo_content


def get_last_todo_content() -> str:
    """获取上次打印的TODO内容"""
    global last_todo_content
    return last_todo_content

def clear_last_todo_content():
    global last_todo_content
    last_todo_content = ""
