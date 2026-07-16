"""
Tool policy: mode baselines + session-level enable/disable for tools and sub-tools.

Sub-tools (enum-level):
  - file: read / write / delete
  - edit: single / multi / line  (line modes are not split further)
  - web_browser: visit / search
  - multi_agent_dispatch: Coder / WebInfoCollector / FileContentAnalyzer / TextEditor
Leaf tools (no subs): skill_query, execute_command, Grep
"""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Tuple, Union

from .agent_types import get_tools_for_mode, LONG_CONTEXT_TOOLS, STRONG_CONTEXT_TOOLS
from .tools import TOOL_DEFINITIONS

# ---------------------------------------------------------------------------
# Catalog metadata (for UI + validation)
# ---------------------------------------------------------------------------

SUBTOOL_KEY_BY_TOOL: Dict[str, str] = {
    "file": "type",
    "edit": "type",
    "web_browser": "action",
    "multi_agent_dispatch": "agent_type",
}

TOOL_CATALOG: Dict[str, Dict[str, Any]] = {
    "skill_query": {
        "label": "skill_query",
        "description": "查询 skill 文档",
        "subs": None,
    },
    "execute_command": {
        "label": "execute_command",
        "description": "执行 PowerShell 命令",
        "subs": None,
    },
    "file": {
        "label": "file",
        "description": "文件读写删除",
        "subs": [
            {"id": "read", "label": "read", "description": "读取文件"},
            {"id": "write", "label": "write", "description": "写入文件"},
            {"id": "delete", "label": "delete", "description": "删除文件/目录"},
        ],
    },
    "edit": {
        "label": "edit",
        "description": "编辑文件内容",
        "subs": [
            {"id": "single", "label": "single", "description": "单次字符串替换"},
            {"id": "multi", "label": "multi", "description": "批量字符串替换"},
            {"id": "line", "label": "line", "description": "按行号编辑"},
        ],
    },
    "Grep": {
        "label": "Grep",
        "description": "ripgrep 内容搜索",
        "subs": None,
    },
    "web_browser": {
        "label": "web_browser",
        "description": "访问网页或搜索",
        "subs": [
            {"id": "visit", "label": "visit", "description": "访问 URL"},
            {"id": "search", "label": "search", "description": "DuckDuckGo 搜索"},
        ],
    },
    "multi_agent_dispatch": {
        "label": "multi_agent_dispatch",
        "description": "派发子 Agent 任务",
        "subs": [
            {"id": "Coder", "label": "Coder", "description": "代码编写/修改"},
            {"id": "WebInfoCollector", "label": "WebInfoCollector", "description": "网络信息收集"},
            {"id": "FileContentAnalyzer", "label": "FileContentAnalyzer", "description": "本地文件分析"},
            {"id": "TextEditor", "label": "TextEditor", "description": "文本文档编辑"},
        ],
    },
}

MODE_BASELINES = {
    "strong_context": STRONG_CONTEXT_TOOLS,
    "long_context": LONG_CONTEXT_TOOLS,
}

# Policy for one mode: tool_name -> True | False | {sub_id: bool}
ToolModePolicy = Dict[str, Union[bool, Dict[str, bool]]]
# Session policies: mode -> ToolModePolicy
SessionToolPolicies = Dict[str, ToolModePolicy]


def effective_mode_name(context_mode: str, selected_auto_mode: Optional[str] = None) -> str:
    """Resolve auto/strong/long to a concrete tool-baseline mode."""
    mode = (context_mode or "strong_context").strip().lower()
    if mode == "auto":
        if selected_auto_mode in ("strong_context", "long_context"):
            return selected_auto_mode
        return "strong_context"
    if mode in ("strong_context", "long_context"):
        return mode
    return "strong_context"


def default_mode_policy(mode: str) -> ToolModePolicy:
    """All baseline tools fully enabled for the given mode."""
    baseline = get_tools_for_mode(effective_mode_name(mode))
    policy: ToolModePolicy = {}
    for name in baseline:
        meta = TOOL_CATALOG.get(name)
        if not meta:
            policy[name] = True
            continue
        subs = meta.get("subs")
        if not subs:
            policy[name] = True
        else:
            policy[name] = {s["id"]: True for s in subs}
    return policy


def normalize_mode_policy(mode: str, raw: Optional[Dict[str, Any]] = None) -> ToolModePolicy:
    """
    Merge raw policy onto mode defaults.

    Accepts:
      - tool: true/false
      - tool: {sub: true/false}
    Unknown tools/subs are ignored. Tools outside the mode baseline are dropped.
    """
    base = default_mode_policy(mode)
    if not raw or not isinstance(raw, dict):
        return base

    result: ToolModePolicy = copy.deepcopy(base)
    for tool_name, value in raw.items():
        if tool_name not in result:
            continue
        base_val = result[tool_name]
        if isinstance(base_val, dict):
            if value is False:
                result[tool_name] = {k: False for k in base_val}
            elif value is True:
                result[tool_name] = {k: True for k in base_val}
            elif isinstance(value, dict):
                merged = dict(base_val)
                for sub_id, enabled in value.items():
                    if sub_id in merged:
                        merged[sub_id] = bool(enabled)
                result[tool_name] = merged
            # else keep default
        else:
            if isinstance(value, bool):
                result[tool_name] = value
            elif isinstance(value, dict):
                # leaf tool given as object -> any false means disabled if all false? treat as enabled if any true
                # better: ignore invalid shape, keep default
                pass
    return result


def get_session_mode_policy(
    tool_policies: Optional[SessionToolPolicies],
    mode: str,
) -> ToolModePolicy:
    mode = effective_mode_name(mode)
    raw = None
    if tool_policies and isinstance(tool_policies, dict):
        raw = tool_policies.get(mode)
    return normalize_mode_policy(mode, raw)


def is_tool_enabled(policy: ToolModePolicy, tool_name: str) -> bool:
    if tool_name not in policy:
        return False
    val = policy[tool_name]
    if isinstance(val, bool):
        return val
    if isinstance(val, dict):
        return any(bool(v) for v in val.values())
    return False


def enabled_subtools(policy: ToolModePolicy, tool_name: str) -> Optional[List[str]]:
    """Return enabled sub ids, or None if tool is a leaf (no subs). Empty list = tool disabled."""
    val = policy.get(tool_name)
    if val is None:
        return []
    if isinstance(val, bool):
        return None if val else []
    if isinstance(val, dict):
        return [k for k, v in val.items() if v]
    return []


def resolve_enabled_tool_names(
    mode: str,
    policy: Optional[ToolModePolicy] = None,
) -> List[str]:
    mode = effective_mode_name(mode)
    pol = normalize_mode_policy(mode, policy)
    names: List[str] = []
    for name in get_tools_for_mode(mode):
        if is_tool_enabled(pol, name):
            names.append(name)
    return names


def _filter_enum_property(
    definition: Dict[str, Any],
    param_name: str,
    allowed: List[str],
) -> Dict[str, Any]:
    """Return a deep-copied definition with enum restricted to allowed values."""
    defn = copy.deepcopy(definition)
    func = defn.get("function") or {}
    params = func.get("parameters") or {}
    props = params.get("properties") or {}
    if param_name not in props:
        return defn
    prop = props[param_name]
    if "enum" in prop:
        prop["enum"] = [v for v in prop["enum"] if v in allowed]
    # Update description briefly if empty enum already handled by caller
    props[param_name] = prop
    params["properties"] = props
    func["parameters"] = params
    defn["function"] = func
    return defn


def _annotate_enabled_subs(
    definition: Dict[str, Any],
    tool_name: str,
    allowed: List[str],
) -> Dict[str, Any]:
    """Append a concise enabled-sub list so prompt docs omit disabled capabilities."""
    if not allowed:
        return definition
    meta = TOOL_CATALOG.get(tool_name) or {}
    subs = meta.get("subs") or []
    if not subs:
        return definition

    all_ids = [s["id"] for s in subs]
    # Only annotate when something is actually restricted.
    if set(allowed) >= set(all_ids):
        return definition

    labels = []
    for s in subs:
        if s["id"] in allowed:
            desc = s.get("description") or s["id"]
            labels.append(f"{s['id']}({desc})" if desc != s["id"] else s["id"])
    note = "、".join(labels) if labels else "无"
    func = definition.get("function") or {}
    desc = (func.get("description") or "").rstrip()
    marker = "【当前会话启用的子能力】"
    if marker in desc:
        head = desc.split(marker)[0].rstrip()
        desc = head
    func["description"] = f"{desc}\n\n{marker}: {note}"
    definition["function"] = func
    return definition


def filter_tool_definitions(
    mode: str,
    policy: Optional[ToolModePolicy] = None,
) -> Dict[str, Dict[str, Any]]:
    """Build TOOL_DEFINITIONS subset with sub-tool enums filtered by policy."""
    mode = effective_mode_name(mode)
    pol = normalize_mode_policy(mode, policy)
    result: Dict[str, Dict[str, Any]] = {}

    for name in resolve_enabled_tool_names(mode, pol):
        if name not in TOOL_DEFINITIONS:
            continue
        base_def = TOOL_DEFINITIONS[name]
        sub_key = SUBTOOL_KEY_BY_TOOL.get(name)
        if not sub_key:
            result[name] = copy.deepcopy(base_def)
            continue

        allowed = enabled_subtools(pol, name) or []
        if not allowed:
            continue

        # multi_agent_dispatch nests agent_type under tasks.items.properties
        if name == "multi_agent_dispatch":
            defn = copy.deepcopy(base_def)
            try:
                props = defn["function"]["parameters"]["properties"]
                tasks = props.get("tasks") or {}
                items = tasks.get("items") or {}
                item_props = items.get("properties") or {}
                agent_type = item_props.get("agent_type") or {}
                if "enum" in agent_type:
                    agent_type["enum"] = [v for v in agent_type["enum"] if v in allowed]
                    adesc = agent_type.get("description") or ""
                    if adesc and isinstance(adesc, str):
                        kept_lines = []
                        for line in adesc.splitlines():
                            stripped = line.strip()
                            if stripped.startswith("- "):
                                agent_name = stripped[2:].split(":", 1)[0].strip()
                                if agent_name in allowed:
                                    kept_lines.append(line)
                            else:
                                kept_lines.append(line)
                        if kept_lines:
                            agent_type["description"] = "\n".join(kept_lines)
                    item_props["agent_type"] = agent_type
                    items["properties"] = item_props
                    tasks["items"] = items
                    props["tasks"] = tasks
                    defn["function"]["parameters"]["properties"] = props
            except Exception:
                defn = _filter_enum_property(base_def, "agent_type", allowed)
            result[name] = _annotate_enabled_subs(defn, name, allowed)
        else:
            defn = _filter_enum_property(base_def, sub_key, allowed)
            result[name] = _annotate_enabled_subs(defn, name, allowed)

    return result


def _extract_sub_value(tool_name: str, params: Dict[str, Any]) -> Optional[str]:
    key = SUBTOOL_KEY_BY_TOOL.get(tool_name)
    if not key:
        return None
    if tool_name == "multi_agent_dispatch":
        # dispatch validates per task; top-level has no single agent_type
        return None
    raw = params.get(key)
    if raw is None and tool_name == "edit":
        # default edit type is single
        return "single"
    if raw is None and tool_name == "file":
        return None
    return str(raw) if raw is not None else None


def check_action_allowed(
    tool_name: str,
    params: Optional[Dict[str, Any]],
    mode: str,
    policy: Optional[ToolModePolicy] = None,
) -> Optional[str]:
    """
    Return an error message if the tool/sub-tool is disabled; otherwise None.
    """
    mode = effective_mode_name(mode)
    pol = normalize_mode_policy(mode, policy)
    params = params or {}

    baseline = get_tools_for_mode(mode)
    if tool_name not in baseline:
        return f"当前模式 ({mode}) 不提供工具: {tool_name}"

    if not is_tool_enabled(pol, tool_name):
        return f"工具已在当前会话禁用: {tool_name}"

    # multi_agent_dispatch: validate each task's agent_type
    if tool_name == "multi_agent_dispatch":
        allowed = set(enabled_subtools(pol, tool_name) or [])
        tasks = params.get("tasks") or []
        if isinstance(tasks, str):
            # LLM may emit tasks as a JSON string; parse for policy checks.
            try:
                import json
                tasks = json.loads(tasks)
            except Exception:
                return None
        if not isinstance(tasks, list):
            return None
        for i, task in enumerate(tasks):
            if not isinstance(task, dict):
                continue
            agent_type = task.get("agent_type")
            if agent_type is None:
                continue
            if str(agent_type) not in allowed:
                return (
                    f"子 Agent 类型已禁用: {agent_type} "
                    f"(可用: {', '.join(sorted(allowed)) or '无'})"
                )
        return None

    sub_key = SUBTOOL_KEY_BY_TOOL.get(tool_name)
    if not sub_key:
        return None

    sub_val = _extract_sub_value(tool_name, params)
    if sub_val is None:
        # missing required sub — let handler validate
        return None

    allowed = enabled_subtools(pol, tool_name) or []
    if sub_val not in allowed:
        return (
            f"工具子能力已禁用: {tool_name}.{sub_val} "
            f"(可用: {', '.join(allowed) or '无'})"
        )
    return None


def catalog_for_mode(mode: str) -> List[Dict[str, Any]]:
    """UI catalog: tools available in mode baseline with sub-tool metadata."""
    mode = effective_mode_name(mode)
    items: List[Dict[str, Any]] = []
    for name in get_tools_for_mode(mode):
        meta = TOOL_CATALOG.get(name, {"label": name, "description": "", "subs": None})
        items.append({
            "id": name,
            "label": meta.get("label", name),
            "description": meta.get("description", ""),
            "subs": meta.get("subs"),
            "sub_key": SUBTOOL_KEY_BY_TOOL.get(name),
        })
    return items


def build_tool_policy_view(
    context_mode: str,
    tool_policies: Optional[SessionToolPolicies],
    selected_auto_mode: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Full payload for settings UI / API.

    For auto context mode, `policy_mode` is the baseline being edited
    (selected_auto_mode or strong_context).
    """
    context_mode = (context_mode or "strong_context").strip().lower()
    if context_mode == "auto":
        policy_mode = selected_auto_mode if selected_auto_mode in ("strong_context", "long_context") else "strong_context"
    else:
        policy_mode = effective_mode_name(context_mode)

    policy = get_session_mode_policy(tool_policies, policy_mode)
    return {
        "context_mode": context_mode,
        "policy_mode": policy_mode,
        "available_policy_modes": [
            {"value": "strong_context", "label": "强上下文"},
            {"value": "long_context", "label": "长上下文"},
        ],
        "catalog": catalog_for_mode(policy_mode),
        "policy": policy,
        "enabled_tools": resolve_enabled_tool_names(policy_mode, policy),
    }


def set_session_mode_policy(
    tool_policies: Optional[SessionToolPolicies],
    mode: str,
    policy: Dict[str, Any],
) -> SessionToolPolicies:
    """Return updated session policies dict with one mode replaced."""
    mode = effective_mode_name(mode)
    normalized = normalize_mode_policy(mode, policy)
    result: SessionToolPolicies = dict(tool_policies or {})
    result[mode] = normalized
    return result
