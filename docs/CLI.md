# CLI 模式使用指南

> 注意：由于后期开发重心转移到 GUI 上，CLI 模式长期未测试，可能存在兼容性问题。推荐使用桌面 GUI 模式。

## 启动 CLI 模式

```bash
# 方式 1：通过统一入口
python main_entry.py

# 方式 2：直接启动
python main.py
```

## CLI 命令列表

### 系统命令

```
prompt             - 查看当前系统提示词
q/quit/exit        - 退出程序
cls                - 清屏
```

### 对话管理

```
context/mem/memory - 查看对话历史（简略）
fullmem            - 查看完整对话历史
memclean           - 清除记忆（需确认）
save               - 保存当前对话历史
load <文件名>      - 加载对话历史（覆盖当前）
continue           - 继续最近保存的历史对话
```

### 工具与技能

```
skills             - 查看所有可用技能
token              - 计算当前记忆使用的 Token 数
```

### 模式与角色

```
mode               - 查看当前上下文处理模式
mode <模式名>      - 切换模式（strong_context/long_context/auto）
character          - 手动触发角色选择分析
```

### 高级功能

```
savemode           - 切换节省上下文模式（压缩历史）
paste <文本>       - 从剪贴板粘贴多行文本
```

## 使用示例

### 保存和加载对话

```bash
# 保存当前对话
User> save
[系统] 对话已保存到 memory/conversation_20240213_143022.mem

# 加载历史对话
User> load conversation_20240213_143022.mem
[系统] 对话已加载

# 继续最近的对话
User> continue
[对话已加载] 继续最近的对话: conversation_20240213_143022.mem
```

### 切换模式

```bash
# 查看当前模式
User> mode
[当前模式] strong_context
[说明] 强上下文关联模式 - 适合需要上下文强关联的任务和精确推理

# 切换模式
User> mode long_context
[模式已切换] long_context
[说明] 长上下文处理模式 - 适合大文本处理、大项目编程和信息检索汇总报告
[提示] 新模式将在下一次对话时生效
```

### 粘贴多行文本

```bash
# 先复制要输入的内容到剪贴板，然后：
User> paste 请分析这段代码
[已从剪贴板读取 1234 个字符]
[预览前100个字符:
 请分析这段代码
def hello():
    print("Hello, World!")
...]
```

## 中断执行

在 CLI 模式下，按 `Ctrl+C` 可以随时中断 Agent 执行：

```bash
User> 帮我分析这个大文件
Agent> 正在读取文件...
^C
[提示] 用户中断，已停止执行
```

## 多进程模式

CLI 模式使用 IPC 架构，Chat 进程独立运行：

- 主进程负责用户交互和工具执行
- Chat 进程负责 LLM API 调用
- 按 Ctrl+C 只中断 Chat 进程，主进程继续运行
