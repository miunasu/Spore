"""
工具文档生成器

从 TOOL_DEFINITIONS 生成人类可读的工具文档，用于注入到 system prompt 中。
"""
from typing import Dict, Any, List, Optional


class ToolDocGenerator:
    """工具文档生成器"""
    
    def generate(self, tool_definitions: Dict[str, Dict[str, Any]]) -> str:
        """
        生成所有工具的文档
        
        Args:
            tool_definitions: 工具定义字典，格式为 {tool_name: tool_spec}
            
        Returns:
            格式化的工具文档字符串
        """
        if not tool_definitions:
            return "（无可用工具）"
        
        docs = []
        for name, definition in tool_definitions.items():
            doc = self.generate_tool_doc(name, definition)
            if doc:
                docs.append(doc)
        
        return "\n\n".join(docs)
    
    def generate_tool_doc(self, name: str, definition: Dict[str, Any]) -> str:
        """
        生成单个工具的文档
        
        Args:
            name: 工具名称
            definition: 工具定义
            
        Returns:
            格式化的工具文档字符串
        """
        # 提取函数定义
        func_def = definition.get("function", {})
        if not func_def:
            return ""
        
        tool_name = func_def.get("name", name)
        description = func_def.get("description", "无描述")
        parameters = func_def.get("parameters", {})
        
        # 构建文档
        lines = [f"#### {tool_name}"]
        
        # 添加描述（截取第一段或前200字符）
        desc_lines = description.strip().split('\n')
        short_desc = desc_lines[0] if desc_lines else description
        if len(short_desc) > 200:
            short_desc = short_desc[:200] + "..."
        lines.append(short_desc)
        
        # 添加参数说明
        param_doc = self.format_parameters(parameters)
        if param_doc:
            lines.append("")
            lines.append("**参数:**")
            lines.append(param_doc)
        
        return "\n".join(lines)
    
    def format_parameters(self, parameters: Dict[str, Any]) -> str:
        """
        格式化参数说明
        
        Args:
            parameters: 参数定义（JSON Schema 格式）
            
        Returns:
            格式化的参数说明字符串
        """
        if not parameters:
            return ""
        
        properties = parameters.get("properties", {})
        required = set(parameters.get("required", []))
        
        if not properties:
            return ""
        
        lines = []
        for param_name, param_def in properties.items():
            param_type = self._get_type_string(param_def)
            param_desc = param_def.get("description", "")
            is_required = param_name in required
            
            # 截取描述的第一行
            if param_desc:
                desc_lines = param_desc.strip().split('\n')
                short_desc = desc_lines[0]
                if len(short_desc) > 100:
                    short_desc = short_desc[:100] + "..."
            else:
                short_desc = ""
            
            # 构建参数行
            req_marker = "（必需）" if is_required else "（可选）"
            if short_desc:
                lines.append(f"- `{param_name}` ({param_type}) {req_marker}: {short_desc}")
            else:
                lines.append(f"- `{param_name}` ({param_type}) {req_marker}")
        
        return "\n".join(lines)
    
    def _get_type_string(self, param_def: Dict[str, Any]) -> str:
        """
        获取参数类型的字符串表示
        
        Args:
            param_def: 参数定义
            
        Returns:
            类型字符串
        """
        param_type = param_def.get("type", "any")
        
        # 处理枚举类型
        if "enum" in param_def:
            enum_values = param_def["enum"]
            if len(enum_values) <= 5:
                return f"enum[{', '.join(str(v) for v in enum_values)}]"
            else:
                return f"enum[{', '.join(str(v) for v in enum_values[:3])}, ...]"
        
        # 处理数组类型
        if param_type == "array":
            items = param_def.get("items", {})
            item_type = items.get("type", "any")
            # 如果数组元素是对象，显示对象的字段结构
            if item_type == "object" and "properties" in items:
                fields = self._format_object_fields(items)
                if fields:
                    return f"array[{{{fields}}}]"
            return f"array[{item_type}]"
        
        # 处理对象类型
        if param_type == "object":
            return "object"
        
        return param_type
    
    def _format_object_fields(self, obj_def: Dict[str, Any]) -> str:
        """
        格式化对象的字段结构
        
        Args:
            obj_def: 对象定义
            
        Returns:
            字段结构字符串，如 "content: string, status: string"
        """
        properties = obj_def.get("properties", {})
        required = set(obj_def.get("required", []))
        
        if not properties:
            return ""
        
        fields = []
        for field_name, field_def in properties.items():
            field_type = field_def.get("type", "any")
            # 标记必需字段
            if field_name in required:
                fields.append(f"{field_name}*: {field_type}")
            else:
                fields.append(f"{field_name}: {field_type}")
        
        return ", ".join(fields)
    
    def generate_usage_examples(self, tool_definitions: Dict[str, Dict[str, Any]]) -> str:
        """
        生成工具使用示例
        
        Args:
            tool_definitions: 工具定义字典
            
        Returns:
            使用示例字符串
        """
        examples = []
        
        # 为常用工具生成示例
        common_tools = ["Read", "Edit", "Grep", "execute_command", "write_text_file"]
        
        for tool_name in common_tools:
            if tool_name in tool_definitions:
                example = self._generate_tool_example(tool_name, tool_definitions[tool_name])
                if example:
                    examples.append(example)
        
        if not examples:
            return ""
        
        return "**使用示例:**\n\n" + "\n\n".join(examples)
    
    def _generate_tool_example(self, name: str, definition: Dict[str, Any]) -> Optional[str]:
        """生成单个工具的使用示例"""
        func_def = definition.get("function", {})
        parameters = func_def.get("parameters", {})
        properties = parameters.get("properties", {})
        required = parameters.get("required", [])
        
        if not properties:
            return f"```\n@SPORE:ACTION\n{name}\n```"
        
        # 构建示例参数
        example_params = []
        for param_name in required[:3]:  # 最多显示3个必需参数
            param_def = properties.get(param_name, {})
            example_value = self._get_example_value(param_name, param_def)
            example_params.append(f"{param_name}={example_value}")
        
        if example_params:
            params_str = " ".join(example_params)
            return f"```\n@SPORE:ACTION\n{name} {params_str}\n```"
        else:
            return f"```\n@SPORE:ACTION\n{name}\n```"
    
    def _get_example_value(self, param_name: str, param_def: Dict[str, Any]) -> str:
        """获取参数的示例值"""
        param_type = param_def.get("type", "string")
        
        # 根据参数名推断示例值
        if "path" in param_name.lower() or "file" in param_name.lower():
            return "/path/to/file.txt"
        if "command" in param_name.lower():
            return '"ls -la"'
        if "pattern" in param_name.lower():
            return '"search_pattern"'
        if "content" in param_name.lower():
            return '"content here"'
        
        # 根据类型生成示例值
        if param_type == "string":
            return '"value"'
        if param_type == "number" or param_type == "integer":
            return "10"
        if param_type == "boolean":
            return "true"
        if param_type == "array":
            return '["item1", "item2"]'
        if param_type == "object":
            return '{"key": "value"}'
        
        return '"value"'
