# CLI 模式使用指南（v4.0）

> [English](en/CLI.md)

> 注意：当前产品重心在桌面 GUI。CLI 仍可运行，但部分交互体验（确认 UI、多会话、异步子 Agent 通知等）弱于桌面模式。推荐：`LAUNCH_MODE=desktop`。

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

日志监控终端默认自动打开；也可手动运行 `start_log_monitor.bat` 或 `uv run python base/log_monitor.py`。

CLI 没有命令行参数，全部行为由 `.env` 决定；运行时命令在 `User>` 提示符输入。

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

### 备份与回滚（v4.0）

```
rollback <文件路径> [--to <版本号>|--steps <N>]  - 文件级回滚到指定版本 / 后退 N 个版本
filehistory [<文件路径>]                        - 查看当前 session 的文件历史；不带路径列出当前 session 跟踪的文件
checkpoints                                     - 列出当前 session 的两类对话点检查点
rewind [<checkpoint_id>|--turns <N>]            - 回滚到对话点（文件+对话历史+TODO 一起恢复）
```

- Agent 每次写/删文件前自动留底（`.spore/`，bsdiff4 增量存储）
- 对话点有两类：发送用户消息时立即创建的 `user_message` 点，可回到「消息已发送、Agent 尚未操作」；仅在某条 LLM 回复实际改动文件时创建的 `action` 点，可回到该回复之前
- `filehistory` / `rollback` 和 `checkpoints` / `rewind` 都以当前 session 为范围；`rewind` 还会截断该 session 的对话历史并清空 TODO
- 会话隔离的是备份元数据和版本链，不是工作区副本。多个 session 仍操作同一批物理文件；若并发修改同一路径，`rollback` 或 `rewind` 写回旧内容时可能覆盖另一 session 的结果，回滚前应先停止相关任务并确认文件现状
- 总开关与限额见 [CONFIGURATION.md](CONFIGURATION.md)「备份与回滚」

### Learning

Learning 无需 CLI 命令：启用后，系统会在任务开始时自动检索相关历史经验，并在任务结束时自动记录本次执行。当前 CLI **没有**手动触发 consolidation 的命令；`learning/consolidation.py` 中的 consolidation 能力不是 CLI 命令面的一部分。

### 安全白名单（v4.0）

```
whitelist            - 用法帮助
whitelist list       - 查看信任命令列表
whitelist add <命令> - 将命令加入白名单（basic 模式下跳过安全守卫确认）
```

白名单存于 `security_whitelist.json`，在 `basic` 安全模式下生效（默认 `full` 模式不做事前确认，无需白名单）；安全审计日志见 `.spore/security_audit.jsonl`。安全 Agent 档位（`off`/`basic`/`full`）见 [CONFIGURATION.md](CONFIGURATION.md)「安全」。

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

### 文件回滚

```text
User> filehistory output/report.md
[版本历史] output/report.md
  v3  2026-07-20 14:22:01  (当前)
  v2  2026-07-20 14:05:47
  v1  2026-07-20 13:58:12

User> rollback output/report.md --to 2
[已回滚] output/report.md → v2

User> checkpoints
[对话点快照] cp_0001 [用户消息] "整理报告结构"
[对话点快照] cp_0002 [文件改动] "正在调整章节顺序"
User> rewind --turns 1
[已回滚] 文件与对话历史已恢复到上一对话点
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
- `auto`：由 ModeSelector 每轮判定

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
| 主进程 | 用户输入、协议解析、工具执行、安全守卫、子 Agent 协调 |
| Chat 进程 | OpenAI / Anthropic API 调用、流式输出（主/子/辅助 Agent 共用） |

初始化由 `base.ipc_manager.initialize_ipc_system()` 完成。

日志：默认会打开日志监控终端（见 `logs/` 与 `LOG_MONITOR_*` 配置）。

---

## 与桌面模式差异（摘要）

| 能力 | CLI | Desktop |
|------|-----|---------|
| 多会话标签 | 弱 / 单会话为主 | 多会话 + 每会话独立 ConversationLoop |
| 任务执行 | 前台同步循环 | 后端自驱任务循环，关窗口不中断 |
| 子 Agent 派发 | 同步阻塞等待 | 异步派发 + `[系统通知]` 回注 |
| 危险操作确认 | 终端确认 + 命令拦截 | WebSocket 确认栏 + 安全弹窗 |
| 实时面板 | 日志终端 | 日志 / TODO / Agent 监控 / 文件树 / Mini 模式 |
| 配置档案 | 手改 `.env` | GUI + profiles |
| 备份回滚 | 当前 session 的 `filehistory` / `rollback` / `checkpoints` / `rewind` 命令 | 设置菜单「备份/回滚」可视化操作 |

更多：

- [配置说明](CONFIGURATION.md)
- [架构设计](ARCHITECTURE.md)
- [前端使用](FRONTEND.md)
