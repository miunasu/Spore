"""
子Agent数据库模块

记录子Agent的任务执行历史，包括工具调用记录。
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import time
import json


# 文件操作类工具列表
FILE_OPERATION_TOOLS = {
    "Read", "Edit", "MultiEdit", "write_text_file", "delete_path", "report_output"
}


class AgentStatus(Enum):
    """Agent状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    WAITING = "waiting"      # 等待LLM响应
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"
    ERROR = "error"


@dataclass
class ToolCallRecord:
    """
    工具调用记录
    
    Attributes:
        tool_name: 工具名称
        arguments: 工具参数（非文件操作工具保存完整参数）
        llm_content: LLM调用工具时的content
        target_path: 文件操作工具的目标路径
        timestamp: 调用时间戳
        is_file_operation: 是否为文件操作
    """
    tool_name: str
    arguments: Optional[Dict[str, Any]] = None
    llm_content: Optional[str] = None
    target_path: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    is_file_operation: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
            "is_file_operation": self.is_file_operation
        }
        if self.is_file_operation:
            result["target_path"] = self.target_path
        else:
            result["arguments"] = self.arguments
            result["llm_content"] = self.llm_content
        return result


@dataclass
class SubAgentDatabase:
    """
    子Agent数据库
    
    记录子Agent的任务和执行历史。
    
    Attributes:
        agent_id: Agent唯一标识
        agent_type_name: Agent类型名称
        initial_task: 初始任务内容
        tool_calls: 工具调用记录列表
        status: 当前状态
        start_time: 开始时间
        end_time: 结束时间
        final_result: 最终结果
        error_message: 错误信息
    """
    agent_id: str
    agent_type_name: str
    initial_task: str
    tool_calls: List[ToolCallRecord] = field(default_factory=list)
    status: AgentStatus = AgentStatus.PENDING
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    final_result: Optional[str] = None
    error_message: Optional[str] = None
    total_tokens: int = 0  # 总 token 消耗
    
    def record_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        llm_content: Optional[str] = None
    ) -> ToolCallRecord:
        """
        记录工具调用
        
        对于文件操作类工具，只记录工具名称和目标路径。
        对于其他工具，记录完整的参数和LLM content。
        
        Args:
            tool_name: 工具名称
            arguments: 工具参数
            llm_content: LLM调用工具时的content
        
        Returns:
            ToolCallRecord: 创建的记录对象
        """
        is_file_op = tool_name in FILE_OPERATION_TOOLS
        
        if is_file_op:
            # 文件操作：只记录目标路径
            target_path = self._extract_target_path(tool_name, arguments)
            record = ToolCallRecord(
                tool_name=tool_name,
                target_path=target_path,
                is_file_operation=True
            )
        else:
            # 非文件操作：记录完整参数
            record = ToolCallRecord(
                tool_name=tool_name,
                arguments=arguments,
                llm_content=llm_content,
                is_file_operation=False
            )
        
        self.tool_calls.append(record)
        return record
    
    def _extract_target_path(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[str]:
        """
        从参数中提取目标路径
        
        Args:
            tool_name: 工具名称
            arguments: 工具参数
        
        Returns:
            str: 目标路径
        """
        # 不同工具的路径参数名称
        path_keys = ["file_path", "path", "target_path"]
        
        for key in path_keys:
            if key in arguments:
                return arguments[key]
        
        return None
    
    def set_status(self, status: AgentStatus) -> None:
        """设置状态"""
        self.status = status
        if status in (AgentStatus.COMPLETED, AgentStatus.INTERRUPTED, AgentStatus.ERROR):
            self.end_time = time.time()
    
    def set_error(self, error_message: str) -> None:
        """设置错误状态"""
        self.error_message = error_message
        self.set_status(AgentStatus.ERROR)
    
    def set_completed(self, result: str) -> None:
        """设置完成状态"""
        self.final_result = result
        self.set_status(AgentStatus.COMPLETED)
    
    def to_summary(self) -> str:
        """
        生成执行摘要供主Agent分析
        
        Returns:
            str: 执行摘要文本
        """
        lines = [
            f"=== Agent: {self.agent_id} ({self.agent_type_name}) ===",
            f"状态: {self.status.value}",
            f"初始任务: {self.initial_task[:200]}{'...' if len(self.initial_task) > 200 else ''}",
            f"执行时长: {self._format_duration()}",
            f"工具调用次数: {len(self.tool_calls)}",
            f"Token 消耗: {self.total_tokens}",
        ]
        
        if self.tool_calls:
            lines.append("\n工具调用历史:")
            for i, record in enumerate(self.tool_calls[-10:], 1):  # 最多显示最后10个
                if record.is_file_operation:
                    lines.append(f"  {i}. {record.tool_name} -> {record.target_path}")
                else:
                    args_preview = str(record.arguments)[:50] if record.arguments else ""
                    lines.append(f"  {i}. {record.tool_name}({args_preview}...)")
        
        if self.error_message:
            lines.append(f"\n错误信息: {self.error_message}")
        
        if self.final_result:
            lines.append(f"\n最终结果: {self.final_result[:200]}{'...' if len(self.final_result) > 200 else ''}")
        
        return "\n".join(lines)
    
    def _format_duration(self) -> str:
        """格式化执行时长"""
        end = self.end_time or time.time()
        duration = end - self.start_time
        
        if duration < 60:
            return f"{duration:.1f}秒"
        elif duration < 3600:
            return f"{duration / 60:.1f}分钟"
        else:
            return f"{duration / 3600:.1f}小时"
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "agent_id": self.agent_id,
            "agent_type_name": self.agent_type_name,
            "initial_task": self.initial_task,
            "tool_calls": [tc.to_dict() for tc in self.tool_calls],
            "status": self.status.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "final_result": self.final_result,
            "error_message": self.error_message,
            "total_tokens": self.total_tokens
        }
    
    def to_json(self) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)



@dataclass
class AgentTask:
    """
    Agent任务定义
    
    Attributes:
        task_id: 任务唯一标识
        task_content: 任务内容描述
        agent_type_name: Agent类型名称
        agent_type_config: Agent类型配置（可选，如果为None则使用预定义配置）
        working_dir: 工作目录（绝对路径，子Agent的工作/输出目录）
        skill: 指定使用的skill名称（可选）
        priority: 任务优先级（数字越大优先级越高）
    """
    task_id: str
    task_content: str
    agent_type_name: str
    agent_type_config: Optional[Any] = None  # AgentTypeConfig
    working_dir: Optional[str] = None  # 工作目录绝对路径
    skill: Optional[str] = None  # 指定使用的skill
    priority: int = 0
    
    def __repr__(self) -> str:
        return f"AgentTask(id={self.task_id!r}, type={self.agent_type_name!r}, skill={self.skill!r})"


@dataclass
class MultiAgentResult:
    """
    多Agent执行结果
    
    Attributes:
        success: 是否全部成功完成
        completed_agents: 成功完成的Agent ID列表
        interrupted_agents: 被中断的Agent ID列表
        failed_agents: 失败的Agent ID列表
        databases: 所有Agent的数据库字典
        total_time: 总执行时间（秒）
        user_correction: 用户更正信息（如果有中断）
    """
    success: bool
    completed_agents: List[str] = field(default_factory=list)
    interrupted_agents: List[str] = field(default_factory=list)
    failed_agents: List[str] = field(default_factory=list)
    databases: Dict[str, 'SubAgentDatabase'] = field(default_factory=dict)
    total_time: float = 0.0
    user_correction: Optional[str] = None
    
    def get_summary(self) -> str:
        """获取执行结果摘要"""
        total_tokens = sum(db.total_tokens for db in self.databases.values())
        
        lines = [
            "=== 多Agent执行结果 ===",
            f"总体状态: {'成功' if self.success else '部分失败/中断'}",
            f"总执行时间: {self.total_time:.2f}秒",
            f"完成: {len(self.completed_agents)}个",
            f"中断: {len(self.interrupted_agents)}个",
            f"失败: {len(self.failed_agents)}个",
            f"总 Token 消耗: {total_tokens}",
        ]
        
        if self.user_correction:
            lines.append(f"\n用户更正: {self.user_correction}")
        
        return "\n".join(lines)
    
    def get_all_summaries(self) -> str:
        """获取所有Agent的执行摘要"""
        summaries = [self.get_summary(), "\n"]
        for agent_id, db in self.databases.items():
            summaries.append(db.to_summary())
            summaries.append("\n")
        return "\n".join(summaries)
