"""
工具系统 (Tool System)

本模块提供了模块化的工具定义系统，支持为不同的 Agent 定制所需的工具集。
使用文本协议（ACTION_SINGLE/ACTION_SEQUENCE/ACTION_PARALLEL/RESULT/FINAL）进行工具调用，不使用 OpenAI function calling。

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
    - edit: 编辑文件（单次/批量替换/按行号编辑）
    - web_browser: 访问网页或搜索
    - Grep: 文件内容搜索
    - multi_agent_dispatch: 多Agent任务派发
"""

from contextvars import ContextVar
from typing import Any, Callable, Dict, List, Optional
import json
import re


# Desktop 后端通过依赖注入启用异步派发；CLI 不注册，保持原阻塞语义。
_async_dispatch_hook: Optional[Callable[..., Any]] = None
_subagent_status_hook: Optional[Callable[[str], Dict[str, Any]]] = None
CURRENT_ACTION_BLOCK_MODE: ContextVar[Optional[str]] = ContextVar(
    "spore_action_block_mode",
    default=None,
)


def set_async_dispatch_hook(hook: Optional[Callable[..., Any]]) -> None:
    global _async_dispatch_hook
    _async_dispatch_hook = hook


def set_subagent_status_hook(hook: Optional[Callable[[str], Dict[str, Any]]]) -> None:
    global _subagent_status_hook
    _subagent_status_hook = hook


def _coerce_path_list(raw: str) -> List[str]:
    """
    把字符串形式的 paths 参数还原为列表。

    兼容 LLM 把 JSON 数组整体写成带引号字符串的情况，以及 Windows
    单反斜杠路径产生非法 JSON 转义（如 \\S）导致 json.loads 失败的情况。
    """
    text = raw.strip()
    if not text.startswith("["):
        return [raw]
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else [raw]
    except json.JSONDecodeError:
        pass
    # 单反斜杠转义后重试：只转义未被转义的单反斜杠，避免已转义路径被二次翻倍
    try:
        import re as _re
        escaped = _re.sub(r'\\(?!\\)', r'\\\\', text)
        parsed = json.loads(escaped)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass
    # 仍失败：直接提取引号内的片段
    items = re.findall(r'"([^"]*)"', text) or re.findall(r"'([^']*)'", text)
    return items if items else [raw]

from .utils import (
    find_skill_md_content,
    execute_command,
    write_text_file,
    delete_path,
    read_text_file,
    edit_text_exact,
    multi_edit_text,
    edit_text_lines,
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
            "description": "在系统中执行PowerShell命令并返回其输出。命令通过-EncodedCommand传递给PowerShell（自动Base64编码），支持所有PowerShell语法。\n\n【多行PowerShell】使用@SPORE:CONTENT格式传参，直接写多行PS代码。示例：\ncommand=@SPORE:CONTENT_START\nNew-Item -Path C:/temp -ItemType Directory\nGet-ChildItem C:/temp\n@SPORE:CONTENT_END\n\n【多行Python】使用@SPORE:CONTENT格式传参，内容为PowerShell here-string管道给python。示例：\ncommand=@SPORE:CONTENT_START\n@'\nimport os\nprint(os.getcwd())\n'@ | python -\n@SPORE:CONTENT_END",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "PowerShell命令字符串（通过-EncodedCommand传递，引号安全）。单行直接写command=xxx；多行使用@SPORE:CONTENT格式传参。多行Python固定格式：@'(换行)python代码(换行)'@ | python -"},
                    "timeout": {"type": "integer", "description": "超时时间（秒），默认60秒；传入0表示无限制等待，直到命令自行结束。对于耗时较长的命令（如IDA分析），建议设置更长超时"},
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
                    "append": {"type": "boolean", "description": "是否追加模式（write时可选），**警告**：write时未选择append将采取覆写写入！原始文件将被清空！"},
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
            "description": "编辑文件，支持精确字符串替换（single/multi）和按行号编辑（line）。字符串匹配会自动容错tab/空格缩进差异。不可用于覆盖整个文件内容，覆盖请用file type=write",
            "parameters": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["single", "multi", "line"], "description": "编辑类型，默认single。字符串匹配反复失败时可改用line按行号编辑"},
                    "file_path": {"type": "string", "description": "文件路径"},
                    "old_string": {"type": "string", "description": "要替换的文本（single时必需）。tab/空格缩进差异和行尾空白差异会自动容错"},
                    "new_string": {"type": "string", "description": "替换后的文本（single时必需）；line模式下作为新内容（delete时可省略）"},
                    "replace_all": {"type": "boolean", "default": False, "description": "是否全部替换（single时可选）"},
                    "edits": {"type": "array", "items": {"type": "object", "properties": {"old_string": {"type": "string"}, "new_string": {"type": "string"}, "replace_all": {"type": "boolean", "default": False}}, "required": ["old_string", "new_string"]}, "description": "编辑操作列表（multi时必需）"},
                    "mode": {"type": "string", "enum": ["replace", "insert_before", "insert_after", "delete"], "description": "line模式的操作类型，默认replace。replace/delete作用于start_line~end_line，insert_before/insert_after相对start_line插入"},
                    "start_line": {"type": "integer", "description": "起始行号，1-based，与read输出的行号一致（line时必需）。注意编辑后行号会变化，连续行号编辑前需重新read"},
                    "end_line": {"type": "integer", "description": "结束行号（含），默认等于start_line（line时可选）"}
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
            "description": "并发派发多个任务给子Agent执行。必须单独放在 ACTION_SINGLE 块中。桌面模式为异步派发：工具立即返回 dispatch_mode=async，本轮任务自动结束，子Agent完成时会通过[系统通知]告知结果与进度；CLI模式仍同步等待全部完成。",
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

    "check_subagent_status": {
        "type": "function",
        "function": {
            "name": "check_subagent_status",
            "description": "查询当前会话所有后台异步子Agent派发的实时进度。仅用于用户主动询问进度或需要在行动前确认状态；不要循环轮询。",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False
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
                paths = _coerce_path_list(paths)
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

        elif edit_type == "line":
            line_args = {
                "file_path": a.get("file_path"),
                "start_line": a.get("start_line"),
                "end_line": a.get("end_line"),
                "mode": a.get("mode", "replace"),
                # 行内容优先取 content，兼容 new_string 传入
                "content": a.get("content") if a.get("content") is not None else a.get("new_string"),
            }
            if a.get("validate_syntax") is not None:
                line_args["validate_syntax"] = a["validate_syntax"]
            return edit_text_lines(**line_args)

        else:
            raise ValueError(f"???????: {edit_type}")
    
    return safe_tool_execution("edit", _impl, args, return_json=True)



def handle_grep(args: Dict[str, Any]) -> str:
    # grep 函数接受路径参数，但不需要预处理（grep 内部会处理）
    return safe_tool_execution("Grep", grep, args)


def handle_web_browser(args: Dict[str, Any]) -> str:
    return safe_tool_execution("web_browser", lambda a: web_browser(**a), args)


def handle_check_subagent_status(args: Dict[str, Any]) -> str:
    """查询当前会话异步子Agent进度。"""
    def _impl(_):
        from .session_context import get_current_conversation_id
        session_id = get_current_conversation_id()
        if not session_id:
            raise RuntimeError("当前没有绑定会话")
        if _subagent_status_hook is None:
            return {
                "success": False,
                "message": "当前运行模式未启用异步子Agent进度查询",
            }
        return _subagent_status_hook(session_id)

    return safe_tool_execution("check_subagent_status", _impl, args, return_json=True)


def handle_multi_agent_dispatch(args: Dict[str, Any]) -> str:
    """多Agent派发工具处理函数；Desktop 异步、CLI 同步。"""
    def _impl(a):
        from .agent_process import AgentProcessManager, get_ipc_manager
        from .agent_database import AgentTask
        from .agent_types import get_agent_type
        from .session_context import (
            get_current_conversation_id,
            get_current_task_epoch,
            get_current_task_source,
        )

        if get_current_task_source() == "agent_notification":
            raise RuntimeError("子Agent完成通知轮次不能再次派发子Agent")

        tasks_data = a.get("tasks", [])
        if isinstance(tasks_data, str):
            try:
                tasks_data = json.loads(tasks_data)
            except json.JSONDecodeError:
                tasks_data = []
        if not isinstance(tasks_data, list):
            tasks_data = []
        if not tasks_data:
            raise ValueError("tasks 参数缺失或为空")

        ipc_manager = get_ipc_manager() or _ipc_manager
        if ipc_manager is None:
            raise RuntimeError("IPC管理器未初始化")

        manager = AgentProcessManager(ipc_manager=ipc_manager, monitor_queue=None)
        tasks = []
        seen_task_ids = set()
        for task_data in tasks_data:
            working_dir = task_data.get("working_dir")
            if working_dir:
                from .utils.path_validator import normalize_path_for_pathlib
                working_dir = normalize_path_for_pathlib(working_dir)
            task_id = str(task_data.get("task_id", "")).strip()
            if not task_id:
                raise ValueError("每个子Agent任务都必须提供非空 task_id")
            if task_id in seen_task_ids:
                raise ValueError(f"子Agent task_id 重复: {task_id}")
            seen_task_ids.add(task_id)
            agent_type_name = task_data.get("agent_type", "Coder")
            agent_type_config = get_agent_type(agent_type_name)
            if agent_type_config is None:
                raise ValueError(f"未知子Agent类型: {agent_type_name}")
            tasks.append(AgentTask(
                task_id=task_id,
                task_content=task_data.get("task_content", ""),
                agent_type_name=agent_type_name,
                agent_type_config=agent_type_config,
                working_dir=working_dir,
                skill=task_data.get("skill"),
            ))

        session_id = get_current_conversation_id()
        block_mode = CURRENT_ACTION_BLOCK_MODE.get()
        async_mode = bool(_async_dispatch_hook and session_id and block_mode)
        if async_mode:
            if block_mode != "single":
                raise ValueError(
                    "桌面端异步 multi_agent_dispatch 必须单独放在 ACTION_SINGLE 块中，"
                    "不能用于 ACTION_SEQUENCE 或 ACTION_PARALLEL"
                )

            registration = _async_dispatch_hook(
                session_id,
                manager,
                tasks,
                expected_epoch=get_current_task_epoch(),
            )
            dispatch_id, callback, start_dispatch, cancel_registration = registration
            manager.completion_callback = callback
            try:
                start_dispatch()
            except Exception:
                cancel_registration()
                raise

            return {
                "success": True,
                "dispatch_mode": "async",
                "dispatch_id": dispatch_id,
                "total": len(tasks),
                "dispatched": [
                    {"task_id": task.task_id, "agent_type": task.agent_type_name}
                    for task in tasks
                ],
                "message": (
                    f"已异步派发 {len(tasks)} 个子Agent，它们将在后台运行。"
                    "本轮对话将立即结束；每个子Agent完成时会收到包含结果摘要、"
                    "已完成数量和仍在运行列表的[系统通知]。"
                ),
            }

        # CLI / 非 Desktop 调用保持原同步阻塞语义及 Ctrl+C 处理。
        from .interrupt_handler import get_interrupt_handler
        interrupt_handler = get_interrupt_handler()
        interrupt_handler.set_agent_manager(manager)
        interrupt_handler.set_ipc_manager(ipc_manager)
        interrupt_handler.install()
        try:
            manager.dispatch_tasks(tasks)
            result = manager.wait_for_completion()

            if interrupt_handler.is_interrupted():
                _, databases = interrupt_handler.handle_interrupt()
                agent_outputs = {
                    agent_id: {
                        "status": db.status.value,
                        "output": db.final_result or db.error_message or "",
                        "tokens": db.total_tokens,
                    }
                    for agent_id, db in databases.items()
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
                    "message": "子Agent执行被用户中断",
                }

            agent_outputs = {
                agent_id: {
                    "status": db.status.value,
                    "output": db.final_result or db.error_message or "",
                    "tokens": db.total_tokens,
                }
                for agent_id, db in result.databases.items()
            }
            return {
                "success": result.success,
                "completed": result.completed_agents,
                "interrupted": result.interrupted_agents,
                "failed": result.failed_agents,
                "total_time": result.total_time,
                "summary": result.get_summary(),
                "agent_outputs": agent_outputs,
            }
        finally:
            interrupt_handler.uninstall()
            interrupt_handler.set_agent_manager(None)
            interrupt_handler.reset()
            if manager.conversation_id:
                from .agent_process import unregister_conversation_agent_manager
                unregister_conversation_agent_manager(manager.conversation_id, manager)

    return safe_tool_execution("multi_agent_dispatch", _impl, args, return_json=True)


TOOL_HANDLERS: Dict[str, Any] = {
    "skill_query": handle_skill_query,
    "execute_command": handle_execute_command,
    "file": handle_file,
    "edit": handle_edit,
    "Grep": handle_grep,
    "web_browser": handle_web_browser,
    "multi_agent_dispatch": handle_multi_agent_dispatch,
    "check_subagent_status": handle_check_subagent_status,
}
