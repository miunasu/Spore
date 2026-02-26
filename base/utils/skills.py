import os
import sys
from typing import Any, Dict, List, Optional

import yaml
from ..logger import log_error


SKILL_FILE_NAME = "SKILL.md"


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
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.dirname(base_dir)


def _read_text(path: str) -> Optional[str]:
    """读取文本文件，自动尝试多种编码"""
    encodings = ["utf-8", "gbk", "gb2312", "utf-16", "latin-1"]
    for enc in encodings:
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
        except Exception as e:
            log_error("SKILL_FILE_READ_ERROR", f"Failed to read skill file: {path}", e)
            return None
    log_error("SKILL_FILE_READ_ERROR", f"Failed to decode skill file with any encoding: {path}")
    return None


def _parse_skill_content(content: str) -> tuple[Dict[str, Any], str]:
    if not content.startswith("---"):
        return {}, content

    lines = content.splitlines()
    closing_index: Optional[int] = None
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            closing_index = index
            break

    if closing_index is None:
        return {}, content

    frontmatter_text = "\n".join(lines[1:closing_index])
    body = "\n".join(lines[closing_index + 1 :]).lstrip("\n")

    try:
        metadata = yaml.safe_load(frontmatter_text) or {}
    except yaml.YAMLError as e:
        log_error("SKILL_YAML_PARSE_ERROR", "Failed to parse skill YAML frontmatter", e, 
                 context={"frontmatter_length": len(frontmatter_text)})
        metadata = {}

    if not isinstance(metadata, dict):
        metadata = {}

    return metadata, body


def _load_claude_skills() -> List[Dict[str, Any]]:
    from ..config import get_config
    resource_dir = _get_resource_dir()
    config = get_config()
    skills_root = os.path.join(resource_dir, config.skills_dir)

    if not os.path.isdir(skills_root):
        return []

    skills: List[Dict[str, Any]] = []

    try:
        for entry in os.scandir(skills_root):
            if not entry.is_dir():
                continue

            skill_md_path = os.path.join(entry.path, SKILL_FILE_NAME)
            if not os.path.isfile(skill_md_path):
                continue

            raw_content = _read_text(skill_md_path)
            if raw_content is None:
                continue

            metadata, body = _parse_skill_content(raw_content)

            skills.append(
                {
                    "directory": entry.name,
                    "path": skill_md_path,
                    "raw": raw_content,
                    "body": body,
                    "metadata": metadata,
                }
            )
    except Exception as e:
        log_error("SKILL_SCAN_ERROR", "Failed to scan skills directory", e, 
                 context={"skills_root": skills_root, "loaded_count": len(skills)})
        return skills

    return skills


def find_skill_md_content(md_name: str) -> Optional[str]:
    """根据技能名称或目录查找 Claude Skill 的 SKILL.md 内容。"""

    if not md_name:
        return None

    query = md_name.strip().lower()
    if not query:
        return None

    query_no_ext = query[:-3] if query.endswith(".md") else query
    query_with_ext = query if query.endswith(".md") else f"{query}.md"

    for skill in _load_claude_skills():
        metadata = skill.get("metadata", {})
        directory = skill.get("directory", "")
        path = skill.get("path", "")

        candidates = {
            directory.lower(),
            f"{directory.lower()}.md",
            os.path.basename(path).lower(),
        }

        name = metadata.get("name")
        if isinstance(name, str) and name.strip():
            normalized_name = name.strip().lower()
            candidates.add(normalized_name)
            candidates.add(f"{normalized_name}.md")

        if query_no_ext in candidates or query_with_ext in candidates:
            return skill.get("raw")

    return None


def collect_skills_md_features() -> str:
    """汇总所有 Claude Skill 的名称与描述，返回 Markdown 列表。"""

    skills = _load_claude_skills()
    if not skills:
        return ""

    def sort_key(skill: Dict[str, Any]) -> str:
        metadata = skill.get("metadata", {})
        name = metadata.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip().lower()
        return skill.get("directory", "").lower()

    lines: List[str] = []
    for skill in sorted(skills, key=sort_key):
        metadata = skill.get("metadata", {})
        directory = skill.get("directory", "")

        name = metadata.get("name") if isinstance(metadata.get("name"), str) else None
        description = metadata.get("description") if isinstance(metadata.get("description"), str) else None
        allowed_tools = metadata.get("allowed-tools")

        display_name = name.strip() if name and name.strip() else directory

        description_text = ""
        if description and description.strip():
            description_text = " ".join(description.strip().splitlines())

        extras: List[str] = []
        if isinstance(allowed_tools, list) and allowed_tools:
            tools = ", ".join(str(tool) for tool in allowed_tools)
            extras.append(f"Allowed tools: {tools}")

        suffix = ""
        if description_text and extras:
            suffix = f": {description_text} ({'; '.join(extras)})"
        elif description_text:
            suffix = f": {description_text}"
        elif extras:
            suffix = f" ({'; '.join(extras)})"

        lines.append(f"- **{display_name}**{suffix}")

    return "\n".join(lines)
