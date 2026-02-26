"""
Agent 类型配置模块

定义子Agent的类型配置，包括工具列表和系统提示词。
支持从 prompt 文件夹动态加载 prompt。
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


# ============================================================================
# 主 Agent 工具集配置
# ============================================================================

# 强上下文关联模式工具集（默认模式）
# 包含完整的工具集，适合需要精确上下文关联的任务
STRONG_CONTEXT_TOOLS = [
    "skill_query",
    "execute_command",
    "write_text_file",
    "delete_path",
    "python_exec",
    "Read",
    "Grep",
    "character_manage",
    "multi_agent_dispatch",
    "web_browser",
    "MultiEdit",
    "Edit",
]

# 长上下文处理模式工具集
LONG_CONTEXT_TOOLS = [
    "skill_query",
    "execute_command",
    "delete_path",
    "multi_agent_dispatch",
    "character_manage",
    "Read",
    "Grep",
    "report_output",
]

# 向后兼容：默认使用强上下文模式
MAIN_AGENT_TOOLS = STRONG_CONTEXT_TOOLS


@dataclass
class AgentTypeConfig:
    """
    子Agent类型配置
    
    定义子Agent的能力配置，包含可用工具列表和系统提示词。
    
    Attributes:
        name: 类型名称，如 "Coder", "Analyst"
        tools_list: 工具名称列表，如 ["Read", "Edit", "Grep"]
        prompt: 系统提示词
    """
    name: str
    tools_list: List[str] = field(default_factory=list)
    prompt: str = ""
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentTypeConfig':
        """
        从字典创建配置
        
        Args:
            data: 配置字典，包含以下字段：
                - name: 类型名称
                - tools: 逗号分隔的工具列表字符串
                - prompt: 系统提示词
        
        Returns:
            AgentTypeConfig: 解析后的配置对象
        
        Example:
            >>> config = AgentTypeConfig.from_dict({
            ...     "name": "Coder",
            ...     "tools": "Read,Edit,Grep",
            ...     "prompt": "You are a coding assistant."
            ... })
            >>> config.tools_list
            ['Read', 'Edit', 'Grep']
        """
        name = data.get("name", "")
        tools_str = data.get("tools", "")
        prompt = data.get("prompt", "")
        
        # 解析工具列表字符串
        if tools_str:
            tools_list = [t.strip() for t in tools_str.split(",") if t.strip()]
        else:
            tools_list = []
        
        return cls(
            name=name,
            tools_list=tools_list,
            prompt=prompt
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典格式
        
        Returns:
            Dict: 配置字典
        """
        return {
            "name": self.name,
            "tools": ",".join(self.tools_list),
            "prompt": self.prompt
        }
    
    def __repr__(self) -> str:
        tools_preview = self.tools_list[:3]
        if len(self.tools_list) > 3:
            tools_preview.append("...")
        return f"AgentTypeConfig(name={self.name!r}, tools={tools_preview})"


# 预定义的Agent类型配置（只定义工具列表，prompt 从文件动态加载）
PREDEFINED_AGENT_TYPES: Dict[str, AgentTypeConfig] = {
    "Coder": AgentTypeConfig(
        name="Coder",
        tools_list=["execute_command", "Grep", "write_text_file", "MultiEdit", "Edit", "Read", "delete_path","skill_query"],
    ),
    "WebInfoCollector": AgentTypeConfig(
        name="WebSearcher",
        tools_list=["web_browser", "report_output","skill_query"],
    ),
    "FileContentAnalyzer": AgentTypeConfig(
        name="FileSearcher",
        tools_list=["Read", "Grep", "execute_command", "report_output","skill_query"],
    ),
    "TextEditor": AgentTypeConfig(
        name="TextEditor",
        tools_list=["Read", "Grep", "report_output", "Edit", "MultiEdit", "skill_query"],
    ),
}


def get_agent_type(name: str) -> Optional[AgentTypeConfig]:
    """
    获取 Agent 类型配置，prompt 从文件动态加载
    
    Args:
        name: 类型名称
    
    Returns:
        AgentTypeConfig: 配置对象，如果不存在返回 None
    
    加载规则:
        - 工具列表从 PREDEFINED_AGENT_TYPES 获取
        - prompt 从 prompt/{name}_prompt.md 动态加载
        - 如果 prompt 文件不存在，prompt 为空字符串
    """
    config = PREDEFINED_AGENT_TYPES.get(name)
    if config is None:
        return None
    
    from .prompt_loader import load_agent_type_prompt
    dynamic_prompt = load_agent_type_prompt(name) or ""
    
    return AgentTypeConfig(
        name=config.name,
        tools_list=config.tools_list.copy(),
        prompt=dynamic_prompt
    )


def register_agent_type(config: AgentTypeConfig) -> None:
    """
    注册新的Agent类型配置
    
    Args:
        config: 要注册的配置对象
    """
    PREDEFINED_AGENT_TYPES[config.name] = config


def reload_agent_prompts() -> Dict[str, bool]:
    """
    重新加载所有 Agent 类型的 prompt
    
    Returns:
        Dict[str, bool]: {agent_name: 是否成功加载} 的字典
    """
    from .prompt_loader import get_all_agent_type_prompts
    
    loaded_prompts = get_all_agent_type_prompts()
    results = {}
    
    for name in PREDEFINED_AGENT_TYPES:
        if name in loaded_prompts:
            results[name] = True
        else:
            results[name] = False
    
    return results


def get_tools_for_mode(mode: str) -> List[str]:
    """
    根据上下文处理模式获取对应的工具集
    
    Args:
        mode: 上下文处理模式，可选值：
            - "strong_context": 强上下文关联模式
            - "long_context": 长上下文处理模式
            - 其他值返回默认工具集
    
    Returns:
        List[str]: 工具名称列表
    """
    if mode == "strong_context":
        return STRONG_CONTEXT_TOOLS.copy()
    elif mode == "long_context":
        return LONG_CONTEXT_TOOLS.copy() if LONG_CONTEXT_TOOLS else STRONG_CONTEXT_TOOLS.copy()
    else:
        return MAIN_AGENT_TOOLS.copy()
