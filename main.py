"""Spore 主程序入口"""
import sys
import time
from colorama import init

# 抑制 httpx/anthropic SDK 在中断时的清理错误
# 这是 SDK 内部的问题，在强制中断时 __del__ 会出现 AttributeError
_original_unraisablehook = sys.unraisablehook
def _custom_unraisablehook(unraisable):
    # 忽略 httpx 客户端清理时的 AttributeError
    if (unraisable.exc_type == AttributeError and 
        "SyncHttpxClientWrapper" in str(unraisable.exc_value)):
        return
    _original_unraisablehook(unraisable)
sys.unraisablehook = _custom_unraisablehook

from base.config import get_config
from base.ipc_manager import initialize_ipc_system
from base.prompt_loader import load_system_prompt
from base.text_protocol import ProtocolManager
from base.tools import TOOL_DEFINITIONS
from base.logger import log_error
from base.state_manager import ConversationState
from base.cli_commands import CLICommandHandler
from base.conversation_loop import ConversationLoop
from base.rule_reminder import should_remind, get_rule_reminder
from base.agent_types import get_tools_for_mode
from AutoAgent import character_choose_agent, select_context_mode, get_mode_description

# 初始化colorama以支持Windows的ANSI转义序列
init(autoreset=True)

# 全局 IPC 管理器（仅用于 main() 函数和异常清理）
# 注意：其他模块不应该导入此变量，应使用 initialize_ipc_system() 创建自己的实例
ipc_manager = None


def main() -> int:
    """主函数入口"""
    # 立即初始化日志系统，启动监控终端
    from base.logger import get_logger
    logger = get_logger()
    print("[系统] 日志系统已启动，监控终端窗口应该已打开")
    
    # 加载并验证配置
    config = get_config()
    try:
        config.validate()
        print(f"[系统] 配置加载成功: SDK={config.llm_sdk}, 模型={config.get_model()}, 温度={config.temperature_main}")
    except RuntimeError as e:
        print(f"[错误] {e}")
        log_error("CONFIG_ERROR", "Configuration validation failed", e)
        return 1
    
    # 使用统一的 IPC 初始化系统
    global ipc_manager
    ipc_manager = initialize_ipc_system()
    time.sleep(0.5)
    
    # 设置 AutoAgent 的 IPC 管理器
    from AutoAgent import supervisor, character_selector, mode_selector
    supervisor.set_ipc_manager(ipc_manager)
    character_selector.set_ipc_manager(ipc_manager)
    mode_selector.set_ipc_manager(ipc_manager)
    
    # 初始化状态管理器
    state = ConversationState()
    
    # 初始化CLI命令处理器
    cli_handler = CLICommandHandler(state)
    
    # 获取当前对话的上下文处理模式（从state读取，已在初始化时从config读取）
    context_mode = state.context_mode
    print(f"[系统] 上下文处理模式: {context_mode}")
    
    # 初始化工具列表（如果是auto模式，先使用默认的strong_context）
    if context_mode == "auto":
        print(f"[系统] {get_mode_description('auto')}")
        current_tools = get_tools_for_mode("strong_context")
    else:
        print(f"[系统] {get_mode_description(context_mode)}")
        current_tools = get_tools_for_mode(context_mode)
    
    # 加载系统提示
    base_prompt = load_system_prompt()
    if base_prompt is None:
        print("警告，系统提示未成功加载")
        base_prompt = ""
    
    # 注入文本协议（主agent使用指定的工具子集）
    tool_definitions = {name: TOOL_DEFINITIONS[name] for name in current_tools if name in TOOL_DEFINITIONS}
    protocol_manager = ProtocolManager()
    system_prompt = protocol_manager.inject_protocol(base_prompt, tool_definitions)

    # 设置主 Agent 的 agent_id（用于文件修改标志）
    from base.utils.system_io import set_current_agent_id
    set_current_agent_id("main_agent")

    # 初始化对话循环处理器（传入工具列表用于动态重载prompt时注入协议）
    conv_loop = ConversationLoop(state, ipc_manager, config, system_prompt, tool_names=current_tools)
    
    # 打印帮助信息
    cli_handler.print_help()
    
    # 主循环
    while True:
        try:
            user_input = input("User> ")
            user_input = user_input.strip()
        except EOFError:
            break
        
        # 处理CLI命令
        processed_input, should_continue = cli_handler.handle_command(user_input, system_prompt)
        
        # 如果是退出命令
        if processed_input == "EXIT":
            break
        
        # 如果是其他命令，已处理完成，继续下一轮
        if should_continue:
            continue
        
        # 使用processed_input或原始user_input作为实际输入
        actual_input = processed_input if processed_input else user_input
        
        # 如果是auto模式，先判断应该使用哪种模式
        if state.context_mode == "auto":
            selected_mode = select_context_mode(actual_input)
            print(f"[系统] 自动选择模式: {selected_mode}")
            
            # 如果模式发生变化，重新加载工具集和系统提示
            new_tools = get_tools_for_mode(selected_mode)
            if new_tools != current_tools:
                current_tools = new_tools
                tool_definitions = {name: TOOL_DEFINITIONS[name] for name in current_tools if name in TOOL_DEFINITIONS}
                system_prompt = protocol_manager.inject_protocol(base_prompt, tool_definitions)
                conv_loop.system_prompt = system_prompt
                conv_loop.tool_names = current_tools
                print(f"[系统] 已切换到 {selected_mode} 模式的工具集")
        
        # 如果连续 3 次 LLM 没有使用 ACTION，在用户输入后注入工具列表和技能列表提醒
        if getattr(conv_loop, '_no_action_count', 0) >= 3:
            from base.utils.skills import collect_skills_md_features
            tool_list = conv_loop._get_tool_names_list()
            skills_list = collect_skills_md_features()
            actual_input += f"\n\n### 可用工具\n{tool_list}"
            if skills_list:
                actual_input += f"\n\n### 可用技能\n{skills_list}"
        
        # 添加用户消息
        state.add_user_message(actual_input)
        
        # 检查是否需要注入规则提醒（防止长对话遗忘）
        # 基于 LLM 回复次数触发，而不是用户消息次数
        if should_remind(state.llm_reply_count, config.rule_reminder_interval):
            reminder = get_rule_reminder(short=config.rule_reminder_short)
            # 将提醒追加到最后一条用户消息中
            if state.messages and state.messages[-1]["role"] == "user":
                state.messages[-1]["content"] += f"\n\n{reminder}"
        
        # 根据配置的频率自动调用角色选择agent
        if state.user_message_count % config.character_recommend_interval == 0:
            character_choose_agent(state.messages)
        
        # 进入对话循环（文本协议模式）
        try:
            while True:
                # 管理上下文长度
                conv_loop.manage_context_length()
                
                # 修复不完整的消息
                conv_loop.fix_incomplete_messages()
                
                # 发送聊天请求并获取响应
                response = conv_loop.send_chat_request()
                if response is None:
                    break
                
                # 解析响应数据
                reply_data = response.get("data", {})
                reply = reply_data.get("content", "")
                
                # 使用文本协议验证和处理响应
                # validate_and_check_response 会解析 ACTION/FINAL_RESPONSE 并处理
                validation_result = conv_loop.validate_and_check_response(reply)
                if validation_result == "continue":
                    continue
                elif validation_result == "break":
                    break
        
        except KeyboardInterrupt:
            conv_loop.handle_keyboard_interrupt()
            continue
        
        # 内循环结束后，清理状态变量，避免下一轮对话时打印旧内容
        state.last_answer = ""
        state.current_answer = ""
    
    # 停止 Chat 进程
    print("\nCleaning up...")
    ipc_manager.stop_chat_process()
    print("We will meet again.")
    return 0


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCleaning up...")
        if ipc_manager:
            ipc_manager.stop_chat_process()
        print("We will meet again.")
    except EOFError:
        print("Cleaning up...")
        if ipc_manager:
            ipc_manager.stop_chat_process()
        print("We will meet again.")
    except Exception as e:
        print(f"\n[错误] {e}")
        log_error("MAIN_EXCEPTION", "Unhandled exception in main", e)
        try:
            import traceback
            traceback.print_exc()
        except KeyboardInterrupt:
            print("\n[提示] 异常处理被中断")
        finally:
            try:
                if ipc_manager:
                    ipc_manager.stop_chat_process()
            except:
                pass
