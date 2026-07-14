"""
规则提醒模块 - 定期向 LLM 注入关键规则提醒
防止长对话中 LLM 遗忘工具格式和重要规则
"""
from typing import List, Optional


# 完整版关键规则提醒模板
RULE_REMINDER_TEMPLATE = """[系统提醒] 请严格遵守以下规则：

## 格式规范
所有协议块标识符必须独占一行，使用 REPLY_START/END、TODO_START/END、{action_block_marker_text} 和 `@SPORE:STOP_REASON=<自然语言原因>`。

工具调用示例：

@SPORE:REPLY_START
给用户的回复内容
@SPORE:REPLY_END

@SPORE:ACTION_SINGLE_START
tool_name param1=value1 param2=value2
@SPORE:ACTION_SINGLE_END


## 工具调用规则
1. **每次回复只能包含一个 ACTION 块**
2. 输出 ACTION 后立即停止，等待系统返回工具执行结果
3. 不要自己输出 RESULT 或继续回复

## 回复格式
给用户的回复内容必须放在 @SPORE:REPLY_START / @SPORE:REPLY_END 块中

## 任务完成标记
完成后最后一次输出用 `@SPORE:STOP_REASON=` 写自然语言终止原因（不要再写 REPLY 块）；多行原因用 CONTENT 包裹

{multi_agent_reminder}

## 其他规则
- 操作后验证结果
- 禁止编造、敷衍、重复

## 可用工具
{tools}

## 可用技能
{skills}""".strip()


# 精简版本（token 敏感时使用）
RULE_REMINDER_SHORT_TEMPLATE = """[系统提醒] 关键规则：
1. **工具调用必须输出 {action_blocks} 块；完成时输出 @SPORE:STOP_REASON=<自然语言原因>（不要 REPLY）**
2. 所有 START/END 标识符必须独占一行并成对出现
3. 回复必须放在 @SPORE:REPLY_START / @SPORE:REPLY_END 块中
4. 任务完成后输出 @SPORE:STOP_REASON=<自然语言原因>

可用工具: {tools_short}
可用技能: {skills_short}""".strip()


def _get_tool_names() -> List[str]:
    """获取主 Agent 的工具名称"""
    try:
        from .agent_types import MAIN_AGENT_TOOLS
        return MAIN_AGENT_TOOLS.copy()
    except Exception:
        return []


def _get_skill_names() -> List[str]:
    """获取所有技能名称"""
    try:
        from .utils.skills import _load_claude_skills
        skills = _load_claude_skills()
        if not skills:
            return []
        
        names = []
        for skill in skills:
            metadata = skill.get("metadata", {})
            name = metadata.get("name")
            if isinstance(name, str) and name.strip():
                names.append(name.strip())
            else:
                directory = skill.get("directory", "")
                if directory:
                    names.append(directory)
        return names
    except Exception:
        return []


def _visibility_for_tools(tool_names: List[str]) -> tuple[bool, bool]:
    has_multi_agent = "multi_agent_dispatch" in tool_names
    return not has_multi_agent, has_multi_agent


def get_rule_reminder(
    short: bool = False,
    tool_names: Optional[List[str]] = None,
) -> str:
    """
    获取规则提醒文本（包含动态工具和技能列表）

    Args:
        short: 是否使用精简版本

    Returns:
        规则提醒文本
    """
    tool_names = tool_names if tool_names is not None else _get_tool_names()
    skill_names = _get_skill_names()
    show_parallel, show_multi_agent = _visibility_for_tools(tool_names)
    visible_tool_names = [name for name in tool_names if show_multi_agent or name != "multi_agent_dispatch"]
    action_blocks = "ACTION_SINGLE、ACTION_SEQUENCE 或 ACTION_PARALLEL" if show_parallel else "ACTION_SINGLE 或 ACTION_SEQUENCE"

    if short:
        tools_short = ", ".join(visible_tool_names) if visible_tool_names else "无"
        skills_short = ", ".join(skill_names) if skill_names else "无"
        return RULE_REMINDER_SHORT_TEMPLATE.format(
            action_blocks=action_blocks,
            tools_short=tools_short,
            skills_short=skills_short
        )
    else:
        tools = "\n".join(f"- {name}" for name in visible_tool_names) if visible_tool_names else "无"
        skills = "\n".join(f"- {name}" for name in skill_names) if skill_names else "无"
        multi_agent_reminder = """## 多Agent协作
你可以派发子Agent：
- 代码编写 → Coder
- 网络搜索 → WebInfoCollector
- 文件分析 → FileContentAnalyzer
- 文档编辑 → TextEditor""" if show_multi_agent else ""
        return RULE_REMINDER_TEMPLATE.format(
            action_block_marker_text="ACTION_SINGLE/SEQUENCE/PARALLEL_START/END" if show_parallel else "ACTION_SINGLE/SEQUENCE_START/END",
            multi_agent_reminder=multi_agent_reminder,
            tools=tools,
            skills=skills
        )


def should_remind(llm_reply_count: int, interval: int) -> bool:
    """
    判断是否应该发送规则提醒

    Args:
        llm_reply_count: 当前 LLM 回复计数
        interval: 提醒间隔（每 N 次 LLM 回复提醒一次）

    Returns:
        是否应该提醒
    """
    if interval <= 0:
        return False
    return llm_reply_count > 0 and llm_reply_count % interval == 0
