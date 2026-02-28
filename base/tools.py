"""
工具系统 (Tool System)

本模块提供了模块化的工具定义系统，支持为不同的 Agent 定制所需的工具集。
使用文本协议（ACTION/RESULT/FINAL_RESPONSE）进行工具调用，不使用 OpenAI function calling。

使用示例:
    # 1. 获取工具定义
    from base.tools import TOOL_DEFINITIONS
    
    # 2. 为特定 Agent 构建工具定义字典
    tool_names = ["Read", "Edit", "Grep", "execute_command"]
    tool_definitions = {name: TOOL_DEFINITIONS[name] for name in tool_names if name in TOOL_DEFINITIONS}
    
    # 3. 使用 ProtocolManager 注入协议到 system prompt
    from base.text_protocol import ProtocolManager
    protocol_manager = ProtocolManager()
    system_prompt = protocol_manager.inject_protocol(base_prompt, tool_definitions)

可用工具列表:
    - skill_query: 查询技能文档
    - execute_command: 执行系统命令
    - write_text_file: 写入文本文件
    - report_output: 输出报告文本
    - delete_path: 删除文件或文件夹
    - Read: 读取文件内容
    - Edit: 精确字符串替换编辑文件
    - MultiEdit: 批量编辑单个文件
    - web_browser: 访问网页或搜索
    - Grep: 文件内容搜索
    - character_manage: 角色管理
    - python_exec: 执行Python代码
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
    write_text,
    execute_python,
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
            "description": "在系统中执行cmd命令并返回其输出",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "要执行的命令字符串"},
                    "timeout": {"type": "integer", "description": "超时时间（秒），默认60秒。对于耗时较长的命令（如IDA分析），建议设置更长超时"}
                },
                "required": ["command"],
            },
        },
    },
    "write_text_file": {
        "type": "function",
        "function": {
            "name": "write_text_file",
            "description": """写入或覆盖创建文本文件，支持追加模式用于分段写入大文件。

支持任意大小的文件写入。对于超大文件，可以使用分段追加写入以提高性能：
- 第一次写入：append=false（覆盖模式）
- 后续写入：append=true（追加模式）""",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "目标文件路径"},
                    "content": {"type": "string", "description": "要写入的文本内容。【必须】使用 @SPORE:CONTENT内容@SPORE:CONTENT_END 格式。"},
                    "append": {"type": "boolean", "description": "是否追加模式（true=追加到文件末尾，false=覆盖文件，默认false）。大文件必须使用追加模式分段写入。"},
                    "encoding": {"type": "string", "description": "文件编码（默认utf-8）"},
                    "verify_result": {"type": "boolean", "description": "是否验证写入结果（默认true）"}
                },
                "required": ["path", "content"],
            },
        },
    },
    "report_output": {
        "type": "function",
        "function": {
            "name": "report_output",
            "description": """用于输出报告或其他人类自然语言文本，写入纯自然语言文本文件。

【文件格式限制】仅支持以下后缀：.txt、.md、.log、.json、.xml、.yaml、.yml、.csv
- 如需编写代码文件（.py、.js、.java 等），请使用子 Agent
- 如需编写配置文件（.conf、.ini 等），请使用子 Agent

支持任意大小的文件写入。对于超大报告，可以使用分段追加写入以提高性能：
- 第一次写入：append=false（覆盖模式）
- 后续写入：append=true（追加模式）""",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "目标文件的完整路径，支持相对路径和绝对路径"
                    },
                    "content": {
                        "type": "string",
                        "description": "写入报告的内容。【必须】使用 @SPORE:CONTENT内容@SPORE:CONTENT_END 格式。"
                    },
                    "encoding": {
                        "type": "string",
                        "description": "文件编码格式（默认utf-8）",
                        "enum": ["utf-8", "gbk", "gb2312", "ascii", "utf-16", "latin-1"]
                    },
                    "append": {
                        "type": "boolean",
                        "description": "是否追加模式，true为追加到文件末尾，false为覆盖写入（默认为false）。大文件必须使用追加模式分段写入。"
                    }
                },
                "required": ["path", "content"],
            },
        },
    },
    "delete_path": {
        "type": "function",
        "function": {
            "name": "delete_path",
            "description": "批量删除文件或文件夹（递归）。支持一次删除多个路径，会弹出确认对话框让用户确认所有待删除项。",
            "parameters": {
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "待删除的路径列表，支持文件和文件夹"
                    },
                    "verify_result": {"type": "boolean", "description": "是否验证删除结果，默认true"}
                },
                "required": ["paths"],
            },
        },
    },
    "Read": {
        "type": "function",
        "function": {
            "name": "Read",
            "description": "Reads a file from the local filesystem. You can access any file directly by using this tool.\nAssume this tool is able to read all files on the machine. If the User provides a path to a file assume that path is valid. It is okay to read a file that does not exist; an error will be returned.\n\nUsage:\n- The file_path parameter must be an absolute path, not a relative path\n- By default, it reads up to 2000 lines starting from the beginning of the file\n- You can optionally specify a line offset and limit (especially handy for long files), but it's recommended to read the whole file by not providing these parameters\n- Any lines longer than 2000 characters will be truncated\n- Results are returned using cat -n like format, with line numbers starting at 1\nIf you read a file that exists but has empty contents you will receive a system reminder warning in place of file contents.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "The absolute path to the file to read",
                    },
                    "offset": {
                        "type": "number",
                        "description": "The line number to start reading from. Only provide if the file is too large to read at once",
                    },
                    "limit": {
                        "type": "number",
                        "description": "The number of lines to read. Only provide if the file is too large to read at once.",
                    },
                },
                "required": ["file_path"],
                "additionalProperties": False,
                "$schema": "http://json-schema.org/draft-07/schema#",
            },
        },
    },
    "Edit": {
        "type": "function",
        "function": {
            "name": "Edit",
            "description": "Performs exact string replacements in files. \n\nUsage:\n- You must use your `Read` tool before evert time editing. This tool will error if you attempt an edit without reading the file. \n- When editing text from Read tool output, ensure you preserve the exact indentation (tabs/spaces) as it appears AFTER the line number prefix. The line number prefix format is: spaces + line number + tab. Everything after that tab is the actual file content to match. Never include any part of the line number prefix in the old_string or new_string.\n- ALWAYS prefer editing existing files in the codebase. NEVER write new files unless explicitly required.\n- Only use emojis if the user explicitly requests it. Avoid adding emojis to files unless asked.\n- The edit will FAIL if `old_string` is not unique in the file. Either provide a larger string with more surrounding context to make it unique or use `replace_all` to change every instance of `old_string`. \n- Use `replace_all` for replacing and renaming strings across the file. This parameter is useful if you want to rename a variable for instance.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "The absolute path to the file to modify"
                    },
                    "old_string": {
                        "type": "string",
                        "description": "The text to replace. 【必须】使用 @SPORE:CONTENT内容@SPORE:CONTENT_END 格式"
                    },
                    "new_string": {
                        "type": "string",
                        "description": "The text to replace it with (must be different from old_string). 【必须】使用 @SPORE:CONTENT内容@SPORE:CONTENT_END 格式"
                    },
                    "replace_all": {
                        "type": "boolean",
                        "default": False,
                        "description": "Replace all occurences of old_string (default false)"
                    },
                    "validate_syntax": {
                        "type": "boolean",
                        "default": True,
                        "description": "Validate syntax after editing (Python/C). Set to false to skip validation."
                    },
                    "normalize_indent": {
                        "type": "boolean",
                        "default": True,
                        "description": "Auto-normalize indentation (tab/space conversion). Helps handle mixed indentation."
                    }
                },
                "required": [
                    "file_path",
                    "old_string",
                    "new_string"
                ],
                "additionalProperties": False,
                "$schema": "http://json-schema.org/draft-07/schema#"
            }
        }
    },
    "MultiEdit": {
        "type": "function",
        "function": {
            "name": "MultiEdit",
            "description": "This is a tool for making multiple edits to a single file in one operation. It is built on top of the Edit tool and allows you to perform multiple find-and-replace operations efficiently. Prefer this tool over the Edit tool when you need to make multiple edits to the same file.\n\nEVERY TIME before using this tool:\n\n1. Use the Read tool to understand the file's contents and context\n2. Verify the directory path is correct\n\nTo make multiple file edits, provide the following:\n1. file_path: The absolute path to the file to modify (must be absolute, not relative)\n2. edits: An array of edit operations to perform, where each edit contains:\n    - old_string: The text to replace (must match the file contents exactly, including all whitespace and indentation)\n    - new_string: The edited text to replace the old_string\n    - replace_all: Replace all occurences of old_string. This parameter is optional and defaults to false.\n\nIMPORTANT:\n- All edits are applied in sequence, in the order they are provided\n- Each edit operates on the result of the previous edit\n- All edits must be valid for the operation to succeed - if any edit fails, none will be applied\n- This tool is ideal when you need to make several changes to different parts of the same file\n- For Jupyter notebooks (.ipynb files), use the NotebookEdit instead\n\nCRITICAL REQUIREMENTS:\n1. All edits follow the same requirements as the single Edit tool\n2. The edits are atomic - either all succeed or none are applied\n3. Plan your edits carefully to avoid conflicts between sequential operations\n\nWARNING:\n- The tool will fail if edits.old_string doesn't match the file contents exactly (including whitespace)\n- The tool will fail if edits.old_string and edits.new_string are the same\n- Since edits are applied in sequence, ensure that earlier edits don't affect the text that later edits are trying to find\n\nWhen making edits:\n- Ensure all edits result in idiomatic, correct code\n- Do not leave the code in a broken state\n- Always use absolute file paths (starting with /)\n- Only use emojis if the user explicitly requests it. Avoid adding emojis to files unless asked.\n- Use replace_all for replacing and renaming strings across the file. This parameter is useful if you want to rename a variable for instance.\n\nIf you want to create a new file, use:\n- A new file path, including dir name if needed\n- First edit: empty old_string and the new file's contents as new_string\n- Subsequent edits: normal edit operations on the created content",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "The absolute path to the file to modify"
                    },
                    "edits": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "old_string": {
                                    "type": "string",
                                    "description": "The text to replace. 【必须】使用 @SPORE:CONTENT内容@SPORE:CONTENT_END 格式"
                                },
                                "new_string": {
                                    "type": "string",
                                    "description": "The text to replace it with. 【必须】使用 @SPORE:CONTENT内容@SPORE:CONTENT_END 格式"
                                },
                                "replace_all": {
                                    "type": "boolean",
                                    "default": False,
                                    "description": "Replace all occurences of old_string (default false)."
                                }
                            },
                            "required": [
                                "old_string",
                                "new_string"
                            ],
                            "additionalProperties": False
                        },
                        "minItems": 1,
                        "description": "Array of edit operations to perform sequentially on the file"
                    },
                    "validate_syntax": {
                        "type": "boolean",
                        "default": True,
                        "description": "Validate syntax after all edits (Python/C). Set to false to skip validation."
                    },
                    "normalize_indent": {
                        "type": "boolean",
                        "default": True,
                        "description": "Auto-normalize indentation (tab/space conversion). Helps handle mixed indentation."
                    }
                },
                "required": [
                    "file_path",
                    "edits"
                ],
                "additionalProperties": False,
                "$schema": "http://json-schema.org/draft-07/schema#"
            }
        }
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
    "character_manage": {
        "type": "function",
        "function": {
            "name": "character_manage",
            "description": "管理角色系统，支持选择/切换角色、取消当前角色、查看所有可用角色。同一时间只能激活一个角色。请先查询所有可用角色，再进行角色选择。",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["select", "remove", "list"],
                        "description": "操作类型: select(选择/切换角色), remove(取消当前角色), list(查看所有可用角色)"
                    },
                    "character_name": {
                        "type": "string",
                        "description": "角色名称。当action为select或remove时必需；当action为list时可忽略"
                    }
                },
                "required": ["action"]
            }
        }
    },
    "python_exec": {
        "type": "function",
        "function": {
            "name": "python_exec",
            "description": "在当前Python环境中执行Python代码（支持单行或多行代码）。可以执行表达式获取返回值，也可以执行语句块。执行结果包含标准输出、错误输出和返回值。",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "要执行的Python代码。多行代码【必须】使用 @SPORE:CONTENT代码@SPORE:CONTENT_END 格式，注意缩进对齐。仅用于执行，不会被写入本地。由于python代码在真实环境上执行，不可执行对windows系统有害的代码。"
                    }
                },
                "required": ["code"]
            }
        }
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
        return execute_command(cmd, timeout=timeout)  # 返回 Dict
    
    return safe_tool_execution("execute_command", _impl, args, return_json=True)


def handle_write_text_file(args: Dict[str, Any]) -> str:
    # system_io.write_text_file 已自动处理路径规范化
    return safe_tool_execution("write_text_file", lambda a: write_text_file(**a), args)

def handle_write_text(args: Dict[str, Any]) -> str:
    """写入报告 - write_text 已返回 JSON 字符串，不需要再序列化"""
    # write_text 已自动处理路径规范化
    return safe_tool_execution("report_output", write_text, args, return_json=False)


def handle_delete_path(args: Dict[str, Any]) -> str:
    def _impl(a):
        paths = a.get("paths", [])
        # 处理字符串类型的paths（LLM可能输出 paths="[...]" 格式）
        if isinstance(paths, str):
            try:
                parsed = json.loads(paths)
                if isinstance(parsed, list):
                    paths = parsed
                else:
                    paths = [paths]  # 单个路径字符串
            except json.JSONDecodeError:
                paths = [paths]  # 单个路径字符串
        
        # delete_path 已自动处理路径规范化
        a["paths"] = paths
        return delete_path(**a)
    return safe_tool_execution("delete_path", _impl, args)


def handle_read(args: Dict[str, Any]) -> str:
    # read_text_file 已自动处理路径规范化
    return safe_tool_execution("Read", lambda a: read_text_file(**a), args)


def handle_edit(args: Dict[str, Any]) -> str:
    # edit_text_exact 已自动处理路径规范化
    return safe_tool_execution("Edit", lambda a: edit_text_exact(**a), args)


def handle_multi_edit(args: Dict[str, Any]) -> str:
    def _impl(a):
        # multi_edit_text 已自动处理路径规范化
        
        edits = a.get("edits", [])
        # 处理字符串类型的edits（LLM可能输出 edits="[...]" 格式）
        if isinstance(edits, str):
            try:
                edits = json.loads(edits)
            except json.JSONDecodeError:
                edits = []
        if not isinstance(edits, list):
            edits = []
        a["edits"] = edits
        return multi_edit_text(**a)
    return safe_tool_execution("MultiEdit", _impl, args)


def handle_grep(args: Dict[str, Any]) -> str:
    # grep 函数接受路径参数，但不需要预处理（grep 内部会处理）
    return safe_tool_execution("Grep", grep, args)


def handle_web_browser(args: Dict[str, Any]) -> str:
    return safe_tool_execution("web_browser", lambda a: web_browser(**a), args)


def handle_character_manage(args: Dict[str, Any]) -> str:
    """角色管理工具处理函数"""
    def _impl(a):
        action = a.get("action", "").strip().lower()
        character_name = a.get("character_name", "").strip()
        
        if action == "list":
            # 查看所有可用角色
            all_characters = get_all_characters_summary()
            current_characters = get_selected_characters()
            current_name = current_characters[0]["name"] if current_characters else "无"
            
            return {
                "success": True,
                "action": "list",
                "current_character": current_name,
                "available_characters": all_characters,
                "message": f"当前激活角色: {current_name}\n\n可用角色列表:\n{all_characters}"
            }
        
        elif action == "select":
            # 选择/切换角色
            if not character_name:
                raise ValueError("必须提供角色名称（character_name 参数）")
            
            result = select_character(character_name)
            result["action"] = "select"
            return result
        
        elif action == "remove":
            # 取消当前角色
            if not character_name:
                # 如果没有提供角色名，获取当前激活的角色
                current_characters = get_selected_characters()
                if not current_characters:
                    raise ValueError("当前没有激活的角色")
                character_name = current_characters[0]["name"]
            
            result = remove_character(character_name)
            result["action"] = "remove"
            return result
        
        else:
            raise ValueError(f"不支持的操作类型: {action}，支持的操作: select, remove, list")
    
    return safe_tool_execution("character_manage", _impl, args, return_json=True)


def handle_python_exec(args: Dict[str, Any]) -> str:
    """Python代码执行工具处理函数"""
    def _impl(a):
        code = a.get("code", "").strip()
        if not code:
            raise ValueError("code 参数缺失")
        return execute_python(code)
    
    return safe_tool_execution("python_exec", _impl, args, return_json=True)


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
            
            # 累加所有子 Agent 的 token 消耗到主对话
            from .chat_process import add_to_token_count
            total_sub_agent_tokens = sum(
                db.total_tokens for db in result.databases.values()
            )
            if total_sub_agent_tokens > 0:
                add_to_token_count(total_sub_agent_tokens)
            
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
    "write_text_file": handle_write_text_file,
    "report_output": handle_write_text,
    "delete_path": handle_delete_path,
    "Read": handle_read,
    "Edit": handle_edit,
    "MultiEdit": handle_multi_edit,
    "Grep": handle_grep,
    "web_browser": handle_web_browser,
    "character_manage": handle_character_manage,
    "python_exec": handle_python_exec,
    "multi_agent_dispatch": handle_multi_agent_dispatch,
}
