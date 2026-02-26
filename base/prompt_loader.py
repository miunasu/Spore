import os
import sys
import json
import ast
from typing import Optional, Dict

from .utils.skills import collect_skills_md_features
from .character_manager import get_current_characters_for_prompt
from .utils.characters import get_all_characters_summary
from .utils.env import get_environment_snapshot
from .utils.shell import execute_command
from .todo_manager import get_current_todos_for_prompt
from .logger import log_error
from .text_protocol import ProtocolManager
from .tools import TOOL_DEFINITIONS


def _get_resource_dir() -> str:
    """
    获取资源目录路径
    
    PyInstaller 打包环境下，资源文件在 SPORE_RESOURCE_DIR 环境变量指定的目录
    开发环境下，资源文件在项目根目录
    """
    # 优先使用环境变量
    resource_dir = os.environ.get('SPORE_RESOURCE_DIR')
    if resource_dir and os.path.exists(resource_dir):
        return resource_dir
    
    # 开发环境：从 __file__ 推断项目根目录
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(base_dir)


def _get_project_root() -> str:
    """
    获取项目根目录（工作目录）
    
    PyInstaller 打包环境下，使用 cwd（由 main.rs 设置）
    开发环境下，从 __file__ 推断
    """
    if getattr(sys, 'frozen', False):
        # 打包环境：使用当前工作目录
        return os.getcwd()
    else:
        # 开发环境：从 __file__ 推断
        base_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.dirname(base_dir)


def load_agent_type_prompt(agent_name: str) -> Optional[str]:
    """
    从 prompt 文件夹动态加载子 Agent 的 prompt。
    
    Args:
        agent_name: Agent 类型名称，如 "Coder", "Analyst"
    
    Returns:
        str: prompt 内容，如果文件不存在返回 None
    
    文件命名规则: {agent_name}_prompt.md
    例如: Coder_prompt.md, Analyst_prompt.md
    """
    from .config import get_config
    config = get_config()
    
    resource_dir = _get_resource_dir()
    
    prompt_filename = f"{agent_name}_prompt.md"
    prompt_path = os.path.join(resource_dir, config.prompt_dir, prompt_filename)
    
    try:
        if os.path.exists(prompt_path):
            with open(prompt_path, "r", encoding="utf-8") as f:
                return f.read().strip()
    except Exception as e:
        log_error("AGENT_PROMPT_LOAD_ERROR", f"Failed to load agent prompt: {agent_name}", e,
                 context={"file_path": prompt_path})
    
    return None


def get_all_agent_type_prompts() -> Dict[str, str]:
    """
    扫描 prompt 文件夹，加载所有子 Agent 的 prompt。
    
    Returns:
        Dict[str, str]: {agent_name: prompt_content} 的字典
    
    文件命名规则: {agent_name}_prompt.md
    """
    from .config import get_config
    config = get_config()
    
    resource_dir = _get_resource_dir()
    prompt_dir = os.path.join(resource_dir, config.prompt_dir)
    
    prompts = {}
    
    if not os.path.exists(prompt_dir):
        return prompts
    
    try:
        for filename in os.listdir(prompt_dir):
            if filename.endswith("_prompt.md") and filename != "prompt.md":
                agent_name = filename.replace("_prompt.md", "")
                prompt_path = os.path.join(prompt_dir, filename)
                try:
                    with open(prompt_path, "r", encoding="utf-8") as f:
                        prompts[agent_name] = f.read().strip()
                except Exception as e:
                    log_error("AGENT_PROMPT_READ_ERROR", f"Failed to read agent prompt: {filename}", e)
    except Exception as e:
        log_error("AGENT_PROMPT_SCAN_ERROR", "Failed to scan agent prompts", e)
    
    return prompts


def collect_subagents_docs() -> str:
    """
    收集 SubAgent 文件夹下所有 Python 文件开头的文档字符串。
    
    返回:
        str: 所有子 Agent 的文档字符串，以 Markdown 格式组合
    """
    # AutoAgent 是代码目录，打包后在临时目录中，开发环境在项目根目录
    # 但实际上打包后不需要读取 Python 源码，这个功能在打包环境下可以跳过
    project_root = _get_project_root()
    subagent_dir = os.path.join(project_root, "AutoAgent")
    
    if not os.path.exists(subagent_dir):
        return "当前无可用子 Agent"
    
    docs = []
    
    # 遍历 SubAgent 文件夹下的所有 Python 文件
    try:
        for filename in sorted(os.listdir(subagent_dir)):
            if not filename.endswith(".py"):
                continue
            
            # 跳过 __init__.py
            if filename == "__init__.py":
                continue
            
            filepath = os.path.join(subagent_dir, filename)
            
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                
                # 使用 ast 解析获取文档字符串
                try:
                    tree = ast.parse(content)
                    docstring = ast.get_docstring(tree)
                    
                    if docstring:
                        # 文件名（不含扩展名）作为标题
                        agent_name = os.path.splitext(filename)[0]
                        docs.append(f"### {agent_name}\n{docstring.strip()}")
                except SyntaxError as e:
                    # 如果 AST 解析失败，尝试手动提取开头的三引号内容
                    log_error("SUBAGENT_DOC_PARSE_ERROR", f"Failed to parse AST for {filename}", e, 
                             context={"file_path": filepath})
                    content = content.strip()
                    if content.startswith('"""') or content.startswith("'''"):
                        quote = '"""' if content.startswith('"""') else "'''"
                        end_pos = content.find(quote, 3)
                        if end_pos != -1:
                            docstring = content[3:end_pos].strip()
                            agent_name = os.path.splitext(filename)[0]
                            docs.append(f"### {agent_name}\n{docstring}")
                            
            except Exception as e:
                # 忽略单个文件的错误，继续处理其他文件
                log_error("SUBAGENT_DOC_READ_ERROR", f"Failed to read SubAgent file {filename}", e, 
                         context={"file_path": filepath})
                continue
    
    except Exception as e:
        log_error("SUBAGENT_DOC_COLLECT_ERROR", "Failed to collect SubAgent docs", e, 
                 context={"directory": subagent_dir})
        return f"读取子 Agent 文档失败: {e}"
    
    if not docs:
        return "当前无可用子 Agent"
    
    return "\n\n".join(docs)


def load_system_prompt(prompt_file: str = None) -> Optional[str]:
    """
    组合技能说明并渲染 prompt.md：
    1) 扫描 skills/ 下所有 .md 文件
    2) 提取每个文档的 `## 功能` 段落
    3) 以 md 文件名作为新标题，拼接为统一段落
    4) 读取根目录 prompt.md，将 {skills} 替换为拼接内容
    返回渲染后的字符串；若失败，返回 None。
    """
    # 资源目录（prompt、skills 等）
    resource_dir = _get_resource_dir()
    # 项目根目录（工作目录）
    project_root = _get_project_root()

    combined_md = collect_skills_md_features()

    def read_text(path: str) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            log_error("PROMPT_FILE_READ_ERROR", f"Failed to read prompt file: {path}", e)
            return None

    # 渲染 prompt 文件（prompt 文件在资源目录中）
    if prompt_file is None:
        from .config import get_config
        config = get_config()
        # 使用配置的 prompt 文件名
        prompt_path = os.path.join(resource_dir, config.prompt_dir, config.system_prompt_file)
    else:
        prompt_path = os.path.join(resource_dir, prompt_file)
    prompt_template = read_text(prompt_path)
    if not prompt_template:
        return combined_md or None
    rendered = prompt_template.replace("{skills}", combined_md)
    
    # {characters} - 显示所有可用角色的列表
    all_characters = get_all_characters_summary()
    rendered = rendered.replace("{characters}", all_characters)
    
    # {current_characters} - 显示当前选择的角色完整内容
    current_characters = get_current_characters_for_prompt()
    rendered = rendered.replace("{current_characters}", current_characters)
    
    env_json = json.dumps(get_environment_snapshot(), ensure_ascii=False)
    rendered = rendered.replace("{env}", env_json)
    rendered = rendered.replace("{character}", "")

    dir_output = ""
    try:
        # execute_command 会自动使用智能编码检测（Windows优先GBK，Linux优先UTF-8）
        dir_result = execute_command("dir")
        if isinstance(dir_result, dict):
            if dir_result.get("ok") and dir_result.get("stdout"):
                dir_output = dir_result.get("stdout", "")
            else:
                fallback_parts = []
                stdout_text = dir_result.get("stdout")
                stderr_text = dir_result.get("stderr")
                if stdout_text:
                    fallback_parts.append(stdout_text)
                if stderr_text:
                    fallback_parts.append(stderr_text)
                if fallback_parts:
                    dir_output = "\n".join(fallback_parts)
                else:
                    dir_output = f"dir 命令执行失败，返回码 {dir_result.get('returncode')}"
    except Exception as exc:
        log_error("DIR_COMMAND_ERROR", "Failed to execute dir command", exc)
        dir_output = f"dir 命令执行异常: {exc}"

    dir_output = dir_output.strip()
    rendered = rendered.replace("{dir}", dir_output)
    
    # 替换TODO占位符
    todo_content = get_current_todos_for_prompt()
    rendered = rendered.replace("{TODO}", todo_content)
    
    # 替换 SubAgents 占位符
    subagents_docs = collect_subagents_docs()
    rendered = rendered.replace("{subagents}", subagents_docs)
    
    return rendered
