"""
CLI命令处理器

处理用户在命令行输入的各种命令。
"""
import os
from typing import Optional, Tuple
import pyperclip
from .state_manager import ConversationState
from .utils import collect_skills_md_features, count_tokens, clear_last_todo_content
from .todo_manager import todo_write
from .memory_manager import save_messages, load_messages, get_latest_history_file
from .logger import log_error
from .text_protocol import is_standalone_marker
from . import config as _config
from AutoAgent import character_choose_agent


class CLICommandHandler:
    """CLI命令处理器"""
    
    def __init__(self, state: ConversationState):
        self.state = state
    
    def print_help(self) -> None:
        """打印帮助信息"""
        print("[系统] 启动对话。输入内容后回车发送。")
        print("[多进程模式] Chat 进程已启动，按 Ctrl+C 可随时打断 LLM 回复")
        print("当前具有命令:")
        print("0.prompt ->查看当前系统提示")
        print("1.q、quit、exit ->退出")
        print("2.context、mem、memory fullmem(完整)->查看上下文（记忆）")
        print("3.memclean ->清除记忆")
        print("4.cls ->清屏")
        print("5.skills ->查看当前所有skills")
        print("6.savemode ->节省上下文模式，通过消除多步骤任务中的上下文，以压缩上下文，防止长对话中上下文超限，默认关闭")
        print("7.paste ->从剪贴板粘贴多行文本，先用剪贴板复制你要输入的内容，以paste开头，输入你想说的话")
        print("8.save ->保存当前对话历史")
        print("9.load ->加载对话历史, 会覆盖当前对话历史，格式 load <对话历史文件名>")
        print("A.token ->计算当前记忆使用的token数")
        print("B.character ->手动触发角色选择分析")
        print("C.continue ->继续最近保存的历史对话")
        print("D.mode ->查看或切换上下文处理模式，格式: mode [strong_context|long_context|auto]")
    
    def handle_command(
        self, 
        user_input: str, 
        system_prompt: str
    ) -> Tuple[str, bool]:
        """
        处理命令
        
        参数:
            user_input: 用户输入
            system_prompt: 系统提示词
        
        返回:
            (处理后的输入, 是否应该继续主循环)
            - 如果是命令，返回 ("", True) 表示已处理，继续循环
            - 如果是普通输入，返回 (处理后的输入, False) 表示需要进入对话
            - 如果是退出命令，返回 ("", False) 且会在外部处理退出
        """
        # 空输入
        if not user_input:
            return "", True
        
        # 退出命令
        if user_input.lower() in {"q", "exit", "quit"}:
            print("\n我们会再见的")
            return "EXIT", False
        
        # 查看上下文
        if user_input.lower() in {"context", "mem", "memory", "fullmem"}:
            self._handle_context_command(user_input)
            return "", True
        
        # 清除记忆
        if user_input.lower() in {"memclean", "cleanmem"}:
            self._handle_memclean_command()
            return "", True
        
        # 清屏
        if user_input.lower() == "cls":
            os.system('cls' if os.name == 'nt' else 'clear')
            return "", True
        
        # 查看skills
        if user_input.lower() == "skills":
            print(collect_skills_md_features())
            return "", True
        
        # 切换savemode
        if user_input.lower() == "savemode":
            self._handle_savemode_command()
            return "", True
        
        # 查看提示词
        if user_input.lower() == "prompt":
            print(f'当前系统提示词使用的token数：{count_tokens(system_prompt)}')
            print(system_prompt)
            return "", True
        
        # 粘贴命令
        if user_input.startswith("paste"):
            processed_input = self._handle_paste_command(user_input)
            if processed_input is None:
                return "", True
            return processed_input, False
        
        # 保存对话
        if user_input.lower() == "save":
            save_messages(self.state.messages)
            return "", True
        
        # 加载对话
        if user_input.startswith("load "):
            self._handle_load_command(user_input)
            return "", True
        
        # 计算token
        if user_input.lower() == "token":
            print(f'当前记忆使用的token数：{count_tokens(self.state.messages)}')
            return "", True
        
        # 角色选择
        if user_input.lower() == "character":
            self._handle_character_command()
            return "", True
        
        # 继续对话
        if user_input.lower() == "continue":
            self._handle_continue_command()
            return "", True
        
        # 模式切换
        if user_input.lower().startswith("mode"):
            self._handle_mode_command(user_input)
            return "", True
        
        # 不是命令，返回原始输入
        return user_input, False
    
    def _handle_context_command(self, user_input: str) -> None:
        """处理查看上下文命令"""
        if user_input.lower() == "fullmem":
            print(self.state.messages)
        else:
            print("\n" + "="*60)
            print(f"对话历史 (共 {len(self.state.messages)} 条消息)")
            print("="*60)
            for i, msg in enumerate(self.state.messages, 1):
                role = msg.get("role", "unknown")
                content = msg.get("content", "")
                
                # 角色标记
                role_label = {
                    "system": "系统",
                    "user": "用户",
                    "assistant": "助手",
                    "tool": "工具"
                }.get(role, role)
                
                print(f"\n[{i}] {role_label}:")
                
                # 处理内容显示
                if isinstance(content, str):
                    # 限制显示长度
                    if len(content) > 200:
                        print(f"  {content[:200]}... (共{len(content)}字符)")
                    else:
                        print(f"  {content}")
                else:
                    print(f"  {content}")
                
                # 显示工具调用信息（文本协议模式，检查标记是否独占一行）
                if role == "assistant" and is_standalone_marker(content, "@SPORE:ACTION"):
                    print(f"  [包含工具调用]")
                if role == "user" and is_standalone_marker(content, "@SPORE:RESULT"):
                    print(f"  [工具返回结果]")
            
            print("\n" + "="*60 + "\n")
    
    def _handle_memclean_command(self) -> None:
        """处理清除记忆命令"""
        confirm = input("are you sure you want clean the memory?(y/n):")
        if confirm == "y":
            self.state.clear_all()
            clear_last_todo_content()
            todo_write([])
            print("[提示] 记忆已清除，所有状态已重置")
    
    def _handle_savemode_command(self) -> None:
        """处理savemode切换命令"""
        is_enabled = self.state.toggle_save_mode()
        if is_enabled:
            print("节省上下文模式已开启")
        else:
            print("节省上下文模式已关闭")
    
    def _handle_paste_command(self, user_input: str) -> Optional[str]:
        """
        处理粘贴命令
        
        返回:
            处理后的输入文本，如果失败返回None
        """
        try:
            text = pyperclip.paste()
            if text:
                # 去除首尾空白，但保留中间的多行格式
                paste_content = text.strip()
                processed_input = user_input[5:] + '\n' + paste_content 
                if paste_content or len(paste_content) <= 4:
                    print(f"[已从剪贴板读取 {len(paste_content)} 个字符]")
                    if len(processed_input) > 100:
                        print(f"[预览前100个字符:\n {processed_input[:100]}...]")
                    else:
                        print(f"[内容:\n {processed_input}]")
                    return processed_input
                else:
                    print("[剪贴板为空或只包含空白字符，剪贴板内容小于4个字符]")
                    return None
            else:
                print("[剪贴板为空]")
                return None
        except Exception as e:
            print(f"[错误] 无法读取剪贴板: {e}")
            log_error("CLIPBOARD_ERROR", "Failed to read from clipboard", e)
            return None
    
    def _handle_load_command(self, user_input: str) -> None:
        """处理加载对话命令"""
        try:
            self.state.messages = load_messages(user_input[5:])
            self.state.user_message_count = 0
        except Exception as e:
            print(f"[错误] 无法加载对话历史: {e}")
            log_error("MEMORY_LOAD_ERROR", "Failed to load conversation history", e, 
                    context={"file_path": user_input[5:]})
    
    def _handle_character_command(self) -> None:
        """处理角色选择命令"""
        if not self.state.messages:
            print("[角色推荐] 没有对话历史，无法分析")
        else:
            print("[角色推荐] 正在分析对话历史...")
            character_choose_agent(self.state.messages)
    
    def _handle_continue_command(self) -> None:
        """处理继续对话命令 - 加载最近的历史对话"""
        try:
            latest_file = get_latest_history_file()
            self.state.messages = load_messages(latest_file)
            self.state.user_message_count = 0
            _config.memory_continued = True  # 标记已继承记忆
            print(f"[对话已加载] 继续最近的对话: {latest_file}")
        except Exception as e:
            print(f"[错误] 无法加载最近的对话历史: {e}")
            log_error("MEMORY_CONTINUE_ERROR", "Failed to continue conversation", e)
    
    def _handle_mode_command(self, user_input: str) -> None:
        """处理模式切换命令"""
        from AutoAgent import get_mode_description
        
        parts = user_input.strip().split()
        
        if len(parts) == 1:
            # 只输入 mode，显示当前对话的模式
            print(f"[当前模式] {self.state.context_mode}")
            print(f"[说明] {get_mode_description(self.state.context_mode)}")
            print("\n可用模式:")
            print("  - strong_context: 适合需要上下文强关联的任务和精确推理")
            print("  - long_context: 适合大文本处理、大项目编程和信息检索汇总报告。偏向多agent")
            print("  - auto: 根据任务自动判断使用哪种模式")
            print("\n使用 'mode <模式名>' 切换模式")
        else:
            # 切换当前对话的模式
            new_mode = parts[1].lower()
            if new_mode in ["strong_context", "long_context", "auto"]:
                self.state.context_mode = new_mode
                print(f"[模式已切换] {new_mode}")
                print(f"[说明] {get_mode_description(new_mode)}")
                print("[提示] 新模式将在下一次对话时生效")
            else:
                print(f"[错误] 未知模式: {new_mode}")
                print("可用模式: strong_context, long_context, auto")
