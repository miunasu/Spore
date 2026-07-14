# CLI 模式使用指南（v3.0）

> 注意：当前产品重心在桌面 GUI。CLI 仍可运行，但部分交互体验（确认 UI、多会话等）弱于桌面模式。推荐：`LAUNCH_MODE=desktop`。

## 启动

```bash
# 确保 .env 中 LAUNCH_MODE=cli（默认即为 cli）

# 方式 1：统一入口
uv run python main_entry.py

# 方式 2：直接 CLI
uv run python main.py
```

依赖安装：

```bash
uv sync
```

---

## 命令列表

### 系统

```
prompt             - 查看当前系统提示词（含协议注入后的有效提示）
q / quit / exit    - 退出
cls                - 清屏
```

### 对话与记忆

```
context / mem / memory - 查看对话历史（简略）
fullmem                - 查看完整对话历史
memclean / cleanmem    - 清除当前记忆
save                   - 手动保存到 history/时间戳.mem
load <文件名>          - 从 history/ 加载（可写 autosave/xxx.mem）
continue               - 加载最近一份历史并继续
```

自动短记忆：

- 路径：`history/autosave/session_<会话ID>.mem`
- 按会话覆盖更新，默认最多保留约 10 个会话
- 可用 `load autosave/session_xxx.mem` 恢复

### 工具与技能

```
skills             - 汇总 skills/ 下各技能的功能摘要
```

> `token` 命令已废弃：上下文 token 以 LLM API 返回的精确用量为准（桌面 UI 会展示）。

### 模式与角色

```
mode                           - 查看当前会话上下文模式
mode strong_context|long_context|auto
char                           - 角色帮助
char list                      - 列出 characters/
char select <角色名>           - 选择角色（同时只能一个）
char remove                    - 移除当前角色
```

`.env` 中 `DEFAULT_CHARACTER` 可在启动时自动选择角色。

### 其他

```
savemode           - 切换节省上下文模式（压缩多步中间过程）
paste [附加说明]   - 读取剪贴板多行文本作为用户输入
```

---

## 使用示例

### 保存 / 加载

```text
User> save
[对话已保存] 文件: history/2026-07-14_153012.mem

User> load 2026-07-14_153012.mem
[对话已加载]

User> continue
[对话已加载] 继续最近的对话: ...
```

### 切换模式

```text
User> mode
[当前模式] strong_context

User> mode long_context
[模式已切换] long_context
[提示] 新模式将在下一次对话时生效
```

模式与工具集关系：

- `strong_context`：单 Agent 完整文件/命令/网络工具，**无**多 Agent 派发
- `long_context`：额外开放 `multi_agent_dispatch`
- `auto`：由 ModeSelector 判定

### 粘贴多行

```text
# 先把内容复制到剪贴板
User> paste 请分析以下代码
[已从剪贴板读取 ...]
```

---

## 中断

- 在 LLM 回复或工具执行过程中按 **Ctrl+C**
- 会中断当前 Chat 请求，并尝试终止本会话子 Agent
- 主进程通常继续，可输入下一条指令

---

## 多进程结构

CLI 与桌面共用同一套 IPC 架构：

| 进程 | 职责 |
|------|------|
| 主进程 | 用户输入、协议解析、工具执行、子 Agent 协调 |
| Chat 进程 | OpenAI / Anthropic API 调用、流式输出 |

初始化由 `base.ipc_manager.initialize_ipc_system()` 完成。

日志：默认会打开日志监控终端（见 `logs/` 与 `LOG_MONITOR_*` 配置）。

---

## 与桌面模式差异（摘要）

| 能力 | CLI | Desktop |
|------|-----|---------|
| 多会话标签 | 弱 / 单会话为主 | 多会话 + 每会话独立 ConversationLoop |
| 危险操作确认 | 有限（命令拦截） | WebSocket 确认栏 |
| 实时面板 | 日志终端 | 日志 / TODO / Agent 监控 / 文件树 |
| 配置档案 | 手改 `.env` | GUI + profiles |

更多：

- [配置说明](CONFIGURATION.md)
- [架构设计](ARCHITECTURE.md)
- [前端使用](FRONTEND.md)