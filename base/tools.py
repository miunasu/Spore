"""
工具系统 (Tool System)

本模块提供了模块化的工具定义系统，支持为不同的 Agent 定制所需的工具集。
使用文本协议（ACTION/RESULT/FINAL_RESPONSE）进行工具调用，不使用 OpenAI function calling。

使用示例:
    # 1. 获取工具定义
    from base.tools import TOOL_DEFINITIONS
    
    # 2. 为特定 Agent 构建工具定义字典
    tool_names = ["file", "edit", "Grep", "execute_command"]
    tool_definitions = {name: TOOL_DEFINITIONS[name] for name in tool_names if name in TOOL_DEFINITIONS}
    
    # 3. 使用 ProtocolManager 注入协议到 system prompt
    from base.text_protocol import ProtocolManager
    protocol_manager = ProtocolManager()
    system_prompt = protocol_manager.inject_protocol(base_prompt, tool_definitions)

可用工具列表:
    - skill_query: 查询技能文档
    - execute_command: 执行系统命令
    - file: 文件操作（读取/写入/删除）
    - edit: 编辑文件（单次/批量替换）
    - web_browser: 访问网页或搜索
    - Grep: 文件内容搜索
    - multi_agent_dispatch: 多Agent任务派发
"""

from typing import Any, Dict, List, Optional
import json

from .utils import (
    find_skill_md_content,
    execute_command,
    write_text_file,
    delete_path,
    read_text_file,
    edit_text_exact,
    multi_edit_text,
    web_browser,
    grep,
)
from .character_manager import (
    select_character,
    remove_character,
    get_selected_characters,
)
from .utils.characters import get_all_characters_summary
# 多Agent系统已迁移到 base/agent_process.py
from . import config as _config
from .logger import log_tool_error

# 全局 IPC 管理器引用（用于超时时中断 chat process）
_ipc_manager = None

# 标记哪些工具会使用 chat process（需要在超时时中断）
# 注意：subagent 已经不限时，所以不在此列表中
TOOLS_USING_CHAT_PROCESS = set([
    # "subagent",  # 已经不限时，不需要
    # 未来如果有其他工具使用 chat process，在这里添加
])

def set_ipc_manager(ipc_manager):
    """设置工具系统的 IPC 管理器引用"""
    global _ipc_manager
    _ipc_manager = ipc_manager

# =============================================================================
# 工具定义字典 - 每个工具的独立 Spec
# =============================================================================
TOOL_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "skill_query": {
        "type": "function",
        "function": {
            "name": "skill_query",
            "description": "查询指定 skill 的说明文档并返回其内容（Markdown 文本）",
            "parameters": {
                "type": "object",
                "properties": {
                    "skill_name": {"type": "string", "description": "要查询的技能名"}
                },
                "required": ["skill_name"],
            },
        },
    },
    "execute_command": {
        "type": "function",
        "function": {
            "name": "execute_command",
            "description": """在系统中执行PowerShell命令并返回其输出。命令通过-EncodedCommand传递给PowerShell（自动Base64编码），支持所有PowerShell语法。多行Python代码推荐用 here-string 管道方式：@'\\n代码\\n'@ | python -

## 多行代码执行方式

### 使用 @SPORE:CONTENT 格式
对于多行代码或包含单引号的命令，必须使用 @SPORE:CONTENT...@SPORE:CONTENT_END 格式包裹命令参数。

示例1 - 执行多行Python代码（推荐方式）：
```
@SPORE:ACTION
execute_command command=@SPORE:CONTENT
@'
for i in range(5):
    print(f"Number: {i}")
    if i == 3:
        print("Found three!")
'@ | python -
@SPORE:CONTENT_END timeout=30
```

示例2 - 简单Python命令：
```
@SPORE:ACTION
execute_command command=python -c "print('hello')"
```

### Here-String 语法说明
- 单引号版本 @'...'@: 内容按字面值处理，不展开变量
- 多行Python用 @'...'@ | python - 从stdin执行
- 开始标记 @' 必须在行尾
- 结束标记 '@ 必须在行首

### 重要提示
✅ 命令通过-EncodedCommand传递，引号安全
✅ 包含单引号的命令需用 @SPORE:CONTENT 格式传参
✅ 多行Python用 @'...'@ | python - 从stdin执行""",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "PowerShell命令字符串（通过-EncodedCommand传递，引号安全）。包含单引号的命令需用@SPORE:CONTENT格式传参；多行Python用 @'...'@ | python - 从stdin执行。注意：@SPORE:CONTENT块只包裹command一个参数的值，其他参数（如timeout）写在块外面"},
                    "timeout": {"type": "integer", "description": "超时时间（秒），默认60秒。直接写数字即可（如timeout=120），不要用@SPORE:CONTENT格式"},
                    "working_dir": {"type": "string", "description": "工作目录（可选），指定命令执行的目录路径"}
                },
                "required": ["command"],
            },
        },
    },
    
    "file": {
        "type": "function",
        "function": {
            "name": "file",
            "description": "文件操作工具，支持读取、写入、删除",
            "parameters": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["read", "write", "delete"], "description": "操作类型"},
                    "file_path": {"type": "string", "description": "文件路径（read/write时使用）"},
                    "path": {"type": "string", "description": "文件路径（write时也可用此参数）"},
                    "content": {"type": "string", "description": "写入内容（write时必需）"},
                    "append": {"type": "boolean", "description": "是否追加模式（write时可选）"},
                    "encoding": {"type": "string", "description": "文件编码（write时可选）"},
                    "offset": {"type": "number", "description": "起始行号（read时可选）"},
                    "limit": {"type": "number", "description": "读取行数（read时可选）"},
                    "paths": {"type": "array", "items": {"type": "string"}, "description": "待删除路径列表（delete时必需）"}
                },
                "required": ["type"],
            },
        },
    },
    "edit": {
        "type": "function",
        "function": {
            "name": "edit",
            "description": "编辑文件，支持单次替换和批量替换。编辑前必须先用 file type=read 读取文件内容。不可用于覆盖整个文件内容，覆盖请用file type=write",
            "parameters": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["single", "multi"], "description": "编辑类型，默认single"},
                    "file_path": {"type": "string", "description": "文件路径"},
                    "old_string": {"type": "string", "description": "要替换的文本（single时必需）"},
                    "new_string": {"type": "string", "description": "替换后的文本（single时必需）"},
                    "replace_all": {"type": "boolean", "default": False, "description": "是否全部替换（single时可选）"},
                    "edits": {"type": "array", "items": {"type": "object", "properties": {"old_string": {"type": "string"}, "new_string": {"type": "string"}, "replace_all": {"type": "boolean", "default": False}}, "required": ["old_string", "new_string"]}, "description": "编辑操作列表（multi时必需）"}
                },
                "required": ["file_path"],
            },
        },
    },
    "web_browser": {
        "type": "function",
        "function": {
            "name": "web_browser",
            "description": """访问网页或搜索信息。action=visit 时访问 URL 并返回网页内容，action=search 时使用 DuckDuckGo 搜索。

## 高级搜索语法（在target参数中使用）
DuckDuckGo 支持以下搜索运算符，直接写在target搜索词中：
- "精确短语": 用引号搜索精确匹配的短语
- site:example.com: 限定在特定网站搜索
- -排除词: 排除包含该词的结果
- filetype:pdf: 搜索特定文件类型
- language:zh/en/ja: 限定搜索语言

## target参数示例
- "python async await" site:stackoverflow.com
- machine learning filetype:pdf language:en
- 深度学习教程 language:zh
- react hooks -class -component""",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["visit", "search"],
                        "description": "操作类型: visit 访问网页, search 搜索关键词",
                    },
                    "target": {
                        "type": "string",
                        "description": "访问的 URL 或搜索关键词",
                    },
                    "num_results": {
                        "type": "integer",
                        "default": 10,
                        "description": "search 模式返回的最大结果数量",
                    },
                    "raw": {
                        "type": "boolean",
                        "default": False,
                        "description": "visit 模式是否返回原始 HTML（默认返回提取后的文本）",
                    },
                    "debug": {
                        "type": "boolean",
                        "default": False,
                        "description": "是否返回调试信息",
                    },
                    "proxy_port": {
                        "type": "integer",
                        "default": 7897,
                        "description": "访问国外网站时使用的本地代理端口",
                    },
                    "timeout": {
                        "type": "integer",
                        "default": 15,
                        "description": "请求超时时间（秒）",
                    },
                },
                "required": ["action", "target"],
            },
        },
    },
    "Grep": {
        "type": "function",
        "function": {
            "name": "Grep",
            "description": "A powerful search tool built on ripgrep\n\n  Usage:\n  - ALWAYS use Grep for search tasks. NEVER invoke `grep` or `rg` as a Bash command. The Grep tool has been optimized for correct permissions and access.\n  - Supports full regex syntax (e.g., \"log.*Error\", \"function\\s+\\w+\")\n  - Filter files with glob parameter (e.g., \"*.js\", \"**/*.tsx\") or type parameter (e.g., \"js\", \"py\", \"rust\")\n  - Output modes: \"content\" shows matching lines, \"files_with_matches\" shows only file paths (default), \"count\" shows match counts\n  - Use Task tool for open-ended searches requiring multiple rounds\n  - Pattern syntax: Uses ripgrep (not grep) - literal braces need escaping (use `interface\\{\\}` to find `interface{}` in Go code)\n  - Multiline matching: By default patterns match within single lines only. For cross-line patterns like `struct \\{[\\s\\S]*?field`, use `multiline: true`\n",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "The regular expression pattern to search for in file contents",
                    },
                    "path": {
                        "type": "string",
                        "description": "File or directory to search in (rg PATH). Defaults to current working directory.",
                    },
                    "glob": {
                        "type": "string",
                        "description": "Glob pattern to filter files (e.g. \"*.js\", \"*.{ts,tsx}\") - maps to rg --glob",
                    },
                    "output_mode": {
                        "type": "string",
                        "enum": ["content", "files_with_matches", "count"],
                        "description": "Output mode: \"content\" shows matching lines (supports -A/-B/-C context, -n line numbers, head_limit), \"files_with_matches\" shows file paths (supports head_limit), \"count\" shows match counts (supports head_limit). Defaults to \"files_with_matches\".",
                    },
                    "-B": {
                        "type": "number",
                        "description": "Number of lines to show before each match (rg -B). Requires output_mode: \"content\", ignored otherwise.",
                    },
                    "-A": {
                        "type": "number",
                        "description": "Number of lines to show after each match (rg -A). Requires output_mode: \"content\", ignored otherwise.",
                    },
                    "-C": {
                        "type": "number",
                        "description": "Number of lines to show before and after each match (rg -C). Requires output_mode: \"content\", ignored otherwise.",
                    },
                    "-n": {
                        "type": "boolean",
                        "description": "Show line numbers in output (rg -n). Requires output_mode: \"content\", ignored otherwise.",
                    },
                    "-i": {
                        "type": "boolean",
                        "description": "Case insensitive search (rg -i)",
                    },
                    "type": {
                        "type": "string",
                        "description": "File type to search (rg --type). Common types: js, py, rust, go, java, etc. More efficient than include for standard file types.",
                    },
                    "head_limit": {
                        "type": "number",
                        "description": "Limit output to first N lines/entries, equivalent to \"| head -N\". Works across all output modes: content (limits output lines), files_with_matches (limits file paths), count (limits count entries). When unspecified, shows all results from ripgrep.",
                    },
                    "multiline": {
                        "type": "boolean",
                        "description": "Enable multiline mode where . matches newlines and patterns can span lines (rg -U --multiline-dotall). Default: false.",
                    },
                },
                "required": ["pattern"],
                "additionalProperties": False,
                "$schema": "http://json-schema.org/draft-07/schema#",
            },
        },
    },

    "multi_agent_dispatch": {
        "type": "function",
        "function": {
            "name": "multi_agent_dispatch",
            "description": "并发派发多个任务给子Agent执行。每个任务由独立的子Agent线程处理，支持Coder等多种Agent类型。主Agent会等待所有子Agent完成或被用户中断。",
            "parameters": {
                "type": "object",
                "properties": {
                    "tasks": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "task_id": {
                                    "type": "string",
                                    "description": "任务唯一标识"
                                },
                                "task_content": {
                                    "type": "string",
                                    "description": "任务内容描述，包含子Agent需要完成的具体工作。并且一定要求子agent输出报告到指定位置。"
                                },
                                "agent_type": {
                                    "type": "string",
                                    "enum": ["Coder", "WebInfoCollector", "FileContentAnalyzer", "TextEditor"],
                                    "description": """子Agent类型名称，根据任务性质选择：
- Coder: 代码编写、修改、重构、修复bug。
- WebInfoCollector: 网络信息搜索，搜索并汇总网页内容。
- FileContentAnalyzer: 本地文件搜索、信息收集，使用关键词定位文件或者分析多文件功能。
- TextEditor: 文本文件编辑修改，修改已存在的文本/文档内容。适合docx/txt等文本编辑任务"""
                                },
                                "working_dir": {
                                    "type": "string",
                                    "description": "子Agent的工作目录（绝对路径），用于指定子Agent的工作范围和输出位置。"
                                },
                                "skill": {
                                    "type": "string",
                                    "description": "指定子Agent必须使用的skill名称（可选）。子Agent会先查询该skill的用法，然后按照skill文档执行任务。"
                                }
                            },
                            "required": ["task_id", "task_content", "agent_type", "working_dir"]
                        },
                        "description": "要派发的任务列表"
                    }
                },
                "required": ["tasks"]
            }
        }
    },
}


# =============================================================================
# 工具执行包装函数 - 统一错误处理
# =============================================================================
def safe_tool_execution(
    tool_name: str,
    handler_func: Any,
    args: Dict[str, Any],
    return_json: bool = True
) -> str:
    """
    安全执行工具处理函数，统一错误处理和日志记录
    
    所有错误统一返回 JSON Status 格式: {"Status": "Error", "error": "..."}
    
    参数:
        tool_name: 工具名称
        handler_func: 实际的工具处理函数（可以是函数或lambda）
        args: 工具参数
        return_json: 是否将结果JSON序列化
    
    返回:
        工具执行结果（字符串），错误时返回 {"Status": "Error", "error": "..."}
    """
    try:
        result = handler_func(args)
        
        # 自动JSON序列化
        if return_json and not isinstance(result, str):
            return json.dumps(result, ensure_ascii=False)
        return result
        
    except TypeError as e:
        log_tool_error(tool_name, f"参数错误: {e}", args, e)
        return _format_tool_error(tool_name, "参数错误", str(e))
        
    except Exception as e:
        log_tool_error(tool_name, str(e), args, e)
        return _format_tool_error(tool_name, "执行异常", str(e))


def _format_tool_error(tool_name: str, error_type: str, error_msg: str) -> str:
    """格式化工具错误返回值 - 统一使用 JSON Status 格式"""
    return json.dumps({
        "Status": "Error",
        "error": f"{tool_name} {error_type}: {error_msg}"
    }, ensure_ascii=False)


# =============================================================================
# 工具处理函数 - 使用统一包装
# =============================================================================
def handle_skill_query(args: Dict[str, Any]) -> str:
    """查询技能文档 - 返回标准化的 JSON 格式"""
    def _impl(a):
        name = (a.get("skill_name") or "").strip()
        if not name:
            raise ValueError("skill_name 参数缺失")
        content = find_skill_md_content(name)
        
        # 包装成标准格式
        if content:
            return {
                "success": True,
                "skill_name": name,
                "content": content
            }
        else:
            return {
                "success": False,
                "skill_name": name,
                "error": f"未找到技能: {name}"
            }
    
    return safe_tool_execution("skill_query", _impl, args, return_json=True)




def handle_execute_command(args: Dict[str, Any]) -> str:
    """执行系统命令 - execute_command 返回 Dict，需要序列化"""
    def _impl(a):
        cmd = a.get("command")
        if not cmd or not isinstance(cmd, str):
            raise ValueError("command 参数缺失或类型错误")
        
        # 注意：命令字符串应由调用者确保格式正确
        # 如果命令中包含路径，建议在构造命令前先规范化路径
        
        timeout = a.get("timeout")  # 获取超时参数
        # 将 timeout 转换为整数（如果提供）
        if timeout is not None:
            try:
                timeout = int(timeout)
            except (ValueError, TypeError):
                raise ValueError(f"timeout 参数必须是整数，收到: {timeout}")
        
        working_dir = a.get("working_dir")  # 获取工作目录参数
        
        return execute_command(cmd, timeout=timeout, working_dir=working_dir)  # 返回 Dict
    
    return safe_tool_execution("execute_command", _impl, args, return_json=True)


def handle_file(args: Dict[str, Any]) -> str:
    """???????? - read/write/delete"""
    def _impl(a):
        op_type = a.get("type", "read")
        
        if op_type == "read":
            file_path = a.get("file_path") or a.get("path")
            if not file_path:
                raise ValueError("file_path ????")
            read_args = {"file_path": file_path}
            if a.get("offset") is not None:
                read_args["offset"] = a["offset"]
            if a.get("limit") is not None:
                read_args["limit"] = a["limit"]
            return read_text_file(**read_args)
        
        elif op_type == "write":
            file_path = a.get("file_path") or a.get("path")
            if not file_path:
                raise ValueError("path ????")
            content = a.get("content", "")
            write_args = {"path": file_path, "content": content}
            if a.get("append") is not None:
                write_args["append"] = a["append"]
            if a.get("encoding") is not None:
                write_args["encoding"] = a["encoding"]
            return write_text_file(**write_args)
        
        elif op_type == "delete":
            paths = a.get("paths", [])
            if isinstance(paths, str):
                try:
                    parsed = json.loads(paths)
                    if isinstance(parsed, list):
                        paths = parsed
                    else:
                        paths = [paths]
                except json.JSONDecodeError:
                    paths = [paths]
            return delete_path(paths=paths)
        
        else:
            raise ValueError(f"???????: {op_type}")
    
    return safe_tool_execution("file", _impl, args, return_json=True)


def handle_edit(args: Dict[str, Any]) -> str:
    """?????? - single/multi"""
    def _impl(a):
        edit_type = a.get("type", "single")
        
        if edit_type == "single":
            edit_args = {
                "file_path": a.get("file_path"),
                "old_string": a.get("old_string"),
                "new_string": a.get("new_string"),
            }
            if a.get("replace_all") is not None:
                edit_args["replace_all"] = a["replace_all"]
            if a.get("validate_syntax") is not None:
                edit_args["validate_syntax"] = a["validate_syntax"]
            if a.get("normalize_indent") is not None:
                edit_args["normalize_indent"] = a["normalize_indent"]
            return edit_text_exact(**edit_args)
        
        elif edit_type == "multi":
            edits = a.get("edits", [])
            if isinstance(edits, str):
                try:
                    edits = json.loads(edits)
                except json.JSONDecodeError:
                    edits = []
            if not isinstance(edits, list):
                edits = []
            multi_args = {
                "file_path": a.get("file_path"),
                "edits": edits,
            }
            if a.get("validate_syntax") is not None:
                multi_args["validate_syntax"] = a["validate_syntax"]
            if a.get("normalize_indent") is not None:
                multi_args["normalize_indent"] = a["normalize_indent"]
            return multi_edit_text(**multi_args)
        
        else:
            raise ValueError(f"???????: {edit_type}")
    
    return safe_tool_execution("edit", _impl, args, return_json=True)



def handle_grep(args: Dict[str, Any]) -> str:
    # grep 函数接受路径参数，但不需要预处理（grep 内部会处理）
    return safe_tool_execution("Grep", grep, args)


def handle_web_browser(args: Dict[str, Any]) -> str:
    return safe_tool_execution("web_browser", lambda a: web_browser(**a), args)


def handle_multi_agent_dispatch(args: Dict[str, Any]) -> str:
    """多Agent派发工具处理函数"""
    def _impl(a):
        from .agent_process import AgentProcessManager, get_ipc_manager
        from .agent_database import AgentTask
        from .agent_types import get_agent_type
        from .interrupt_handler import get_interrupt_handler
        
        tasks_data = a.get("tasks", [])
        # 处理字符串类型的tasks（LLM可能输出 tasks="[...]" 格式）
        if isinstance(tasks_data, str):
            try:
                tasks_data = json.loads(tasks_data)
            except json.JSONDecodeError:
                tasks_data = []
        # 确保tasks是列表
        if not isinstance(tasks_data, list):
            tasks_data = []
        if not tasks_data:
            raise ValueError("tasks 参数缺失或为空")
        
        # 获取IPC管理器
        ipc_manager = get_ipc_manager()
        if ipc_manager is None:
            ipc_manager = _ipc_manager
        if ipc_manager is None:
            raise RuntimeError("IPC管理器未初始化")
        
        # 创建Agent管理器（每个子Agent会创建独立终端）
        manager = AgentProcessManager(
            ipc_manager=ipc_manager,
            monitor_queue=None  # 不再使用全局队列
        )
        
        # 获取中断处理器并安装
        interrupt_handler = get_interrupt_handler()
        interrupt_handler.set_agent_manager(manager)
        interrupt_handler.set_ipc_manager(ipc_manager)
        interrupt_handler.install()  # 安装信号处理器
        
        # 构建任务列表
        tasks = []
        for task_data in tasks_data:
            # 修复 working_dir 路径
            working_dir = task_data.get("working_dir")
            if working_dir:
                # 规范化工作目录路径
                from .utils.path_validator import normalize_path_for_pathlib
                working_dir = normalize_path_for_pathlib(working_dir)
            
            task = AgentTask(
                task_id=task_data.get("task_id", ""),
                task_content=task_data.get("task_content", ""),
                agent_type_name=task_data.get("agent_type", "Coder"),
                agent_type_config=get_agent_type(task_data.get("agent_type", "Coder")),
                working_dir=working_dir,
                skill=task_data.get("skill")  # 指定使用的skill（可选）
            )
            tasks.append(task)
        
        try:
            # 派发任务
            manager.dispatch_tasks(tasks)
            
            # 等待完成
            result = manager.wait_for_completion()
            
            # Token 统计已由后端自动处理，无需手动累加
            
            # 检查是否被中断
            if interrupt_handler.is_interrupted():
                # 收集中断状态
                _, databases = interrupt_handler.handle_interrupt()
                
                # 收集每个Agent的输出
                agent_outputs = {}
                for agent_id, db in databases.items():
                    agent_outputs[agent_id] = {
                        "status": db.status.value,
                        "output": db.final_result or db.error_message or "",
                        "tokens": db.total_tokens
                    }
                
                return {
                    "success": False,
                    "interrupted": True,
                    "completed": result.completed_agents,
                    "interrupted_agents": result.interrupted_agents,
                    "failed": result.failed_agents,
                    "total_time": result.total_time,
                    "summary": result.get_summary(),
                    "agent_outputs": agent_outputs,
                    "message": "子Agent执行被用户中断"
                }
            
            # 收集每个Agent的输出
            agent_outputs = {}
            for agent_id, db in result.databases.items():
                agent_outputs[agent_id] = {
                    "status": db.status.value,
                    "output": db.final_result or db.error_message or "",
                    "tokens": db.total_tokens
                }
            
            return {
                "success": result.success,
                "completed": result.completed_agents,
                "interrupted": result.interrupted_agents,
                "failed": result.failed_agents,
                "total_time": result.total_time,
                "summary": result.get_summary(),
                "agent_outputs": agent_outputs
            }
        finally:
            # 清理：卸载信号处理器，取消注册
            interrupt_handler.uninstall()
            interrupt_handler.set_agent_manager(None)
            interrupt_handler.reset()
    
    return safe_tool_execution("multi_agent_dispatch", _impl, args, return_json=True)


TOOL_HANDLERS: Dict[str, Any] = {
    "skill_query": handle_skill_query,
    "execute_command": handle_execute_command,
    "file": handle_file,
    "edit": handle_edit,
    "Grep": handle_grep,
    "web_browser": handle_web_browser,
    "multi_agent_dispatch": handle_multi_agent_dispatch,
}
