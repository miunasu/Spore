# Spore AI Agent 架构设计（v4.0）

> [English](en/ARCHITECTURE.md)

本文档描述 **Spore 4.0** 的实际代码架构。入口、对话循环、文本协议、多会话桌面后端、工具系统与 v4.0 新增的安全 Agent / 工具策略 / 备份回滚均以当前仓库为准。

---

## 系统架构概览

```
┌─────────────────────────────────────────────────────────────────────┐
│                          用户界面层                                   │
├─────────────────────────────────┬───────────────────────────────────┤
│         GUI 模式 (Tauri)        │        CLI 模式 (Terminal)        │
│  React + TypeScript + Zustand   │  命令行交互界面                     │
│  - 多标签页 / 多会话对话        │  - CLICommandHandler               │
│  - 文件管理 / Mini 模式 / i18n  │  - 日志监控独立终端                 │
│  - 日志 / TODO / 确认 / 安全弹窗│  - 直接 stdin 对话循环              │
│  - WebSocket 事件流 (task_event)│                                    │
└─────────────┬───────────────────┴──────────────┬───────────────────┘
              │ HTTP :8765 + WS :8766            │ 进程内调用
┌─────────────┴──────────────────────────────────┴───────────────────┐
│                     应用入口 (main_entry.py)                         │
│  LAUNCH_MODE=cli|desktop → main.py | desktop_app.backend.server      │
│  打包环境：resource_manager 校正工作目录与资源路径                     │
└─────────────┬──────────────────────────────────┬───────────────────┘
              │                                  │
    ┌─────────┴─────────┐              ┌─────────┴──────────┐
    │ Desktop Backend   │              │ CLI Main Loop      │
    │ FastAPI + WS 进程 │              │ ConversationLoop   │
    │ 后端自驱任务循环   │              └─────────┬──────────┘
    └─────────┬─────────┘                        │
┌─────────────┴──────────────────────────────────┴───────────────────┐
│                          业务逻辑层                                   │
│  ConversationLoop（文本协议驱动）                                     │
│  ├─ ConversationState / MultiSessionManager                         │
│  ├─ ProtocolManager + ActionParser                                  │
│  ├─ Tools + ToolPolicy（会话/全局工具策略过滤与运行时拦截）            │
│  ├─ SecurityGuard（命令拦截 / 风险评估 / 熔断）                       │
│  ├─ BackupManager（文件版本 + 对话检查点）                            │
│  ├─ ModeSelector / CharacterManager / TodoManager / RuleReminder    │
│  └─ multi_agent_dispatch → AgentProcessManager / SubAgentThread     │
└─────────────┬──────────────────────────────────────────────────────┘
              │ multiprocessing Queue IPC
┌─────────────┴──────────────────────────────────────────────────────┐
│  Chat 进程 (base/chat_process.py)                                    │
│  - OpenAI / Anthropic SDK（主 Agent、子 Agent、辅助 Agent 共用）      │
│  - 按 Agent 档位（supervisor/mode_selector/security）缓存独立客户端   │
│  - 线程池并发请求 (CHAT_MAX_WORKERS)，流式 token 与响应缓存           │
└────────────────────────────────────────────────────────────────────┘
```

---

## 目录与模块地图

```
Spore/
├── main_entry.py              # 统一入口：cli / desktop
├── main.py                    # CLI 主循环
├── pyproject.toml             # Python 依赖与版本
├── build_installer.bat        # 一键打包安装器（6 阶段）
├── spore_backend.spec         # PyInstaller onefile 规格
├── tool_policy.json           # 全局工具策略（scope=global 时生效）
│
├── base/                      # 核心运行时
│   ├── config.py              # .env → Config 单例；resolve_agent_llm 档位解析
│   ├── config_profiles.py     # API 配置档案（.spore_config_profiles.json）
│   ├── client.py              # LLM 客户端工厂（含 CleanHeadersTransport）
│   ├── chat_process.py        # 独立 Chat 子进程（多档位客户端缓存）
│   ├── ipc_manager.py         # 主进程 ↔ Chat 进程 IPC（请求匹配/取消）
│   ├── conversation_loop.py   # 主对话循环（协议解析+工具执行+检查点）
│   ├── state_manager.py       # ConversationState / MultiSessionManager
│   ├── session_context.py     # ContextVar：conversation_id / task_epoch
│   ├── memory_manager.py      # history/ 与 autosave 持久化
│   ├── cli_commands.py        # CLI 命令（含 rollback/rewind/whitelist）
│   ├── tools.py               # TOOL_DEFINITIONS + 处理器
│   ├── tool_policy.py         # 工具策略：模式基线 + 子工具开关 + 双层执行
│   ├── security_guard.py      # 命令安全守卫：关键字规则/白名单/审计
│   ├── backup_manager.py      # 备份回滚：bsdiff4 文件版本 + 对话检查点
│   ├── agent_types.py         # 主 Agent 工具集 / 预定义子 Agent 类型
│   ├── agent_process.py       # 多 Agent 派发引擎（含桌面异步派发）
│   ├── agent_database.py      # 子 Agent 任务与工具调用记录
│   ├── character_manager.py   # 角色选择（单角色）
│   ├── todo_manager.py        # 声明式 TODO（按会话）
│   ├── rule_reminder.py       # 周期性规则提醒
│   ├── prompt_loader.py       # prompt / skills / characters 装配
│   ├── interrupt_handler.py   # 中断与级联终止
│   ├── event_signal.py        # 事件信号
│   ├── logger.py / log_monitor.py / multi_agent_monitor.py
│   ├── text_protocol/         # 文本协议
│   │   ├── protocol_manager.py
│   │   ├── action_parser.py
│   │   ├── result_formatter.py
│   │   └── tool_doc_generator.py
│   └── utils/                 # 工具实现细节
│       ├── system_io.py       # 文件读写/编辑/删除 + 桌面确认挂钩
│       ├── shell.py / grep.py / web_browser.py / skills.py ...
│
├── AutoAgent/                 # 辅助 Agent（通过 IPC 调 Chat）
│   ├── mode_selector.py       # auto 模式时选择 strong/long
│   ├── supervisor.py          # 循环/终止判定辅助
│   └── security_agent.py      # 安全 Agent：意图分析 / 风险评估 / 恶意熔断
│
├── desktop_app/
│   ├── resource_manager.py    # 打包环境初始化
│   ├── backend/
│   │   ├── server.py          # FastAPI 主服务（:8765）
│   │   ├── standalone.py      # 多实例子进程入口
│   │   ├── core.py            # 复用 CLI 初始化逻辑；热更新配置
│   │   ├── conversation_loop_manager.py  # 每会话独立 ConversationLoop
│   │   ├── instance_manager.py
│   │   ├── routes/            # chat / task / commands / files / agents /
│   │   │                      # settings / instances / confirm / backup
│   │   └── websocket/         # WS 推送进程（:8766）、日志桥、确认管理、
│   │                          # 安全熔断桥、子 Agent 通知
│   └── frontend/              # React + Tauri（含 src/i18n 中英双语）
│
├── prompt/                    # 系统与各 Agent 提示词
│   ├── prompt.md              # 主 Agent 系统提示
│   ├── model_prompt.md        # ModeSelector
│   ├── supervisor_prompt.md   # Supervisor
│   ├── security_prompt.md     # 风险评估（basic+）
│   ├── security_intent_prompt.md      # 意图+恶意分析（full）
│   ├── security_remediation_prompt.md # 熔断后修复建议（full）
│   └── <Type>_prompt.md       # 各子 Agent 类型提示
│
├── skills/                    # Claude Skills 风格技能包
├── characters/                # 角色 Markdown
├── history/                   # 对话存档与 autosave
├── .spore/                    # 备份数据与安全审计（运行时生成）
├── docs/                      # 文档（本目录；en/ 为英文版）
└── example/                   # 案例输出
```

---

## 启动与运行路径

### 1. 统一入口 `main_entry.py`

1. `multiprocessing.freeze_support()`（Windows / PyInstaller）
2. 若 `sys.frozen`：调用 `desktop_app.resource_manager.initialize_app()`
3. `load_dotenv(.env)`
4. 读取 `LAUNCH_MODE`：
   - `cli` → `main.main()`
   - `desktop` → `desktop_app.backend.server.run_desktop_app()`

### 2. CLI 路径 `main.py`

1. 初始化日志 / 配置校验
2. `initialize_ipc_system()` 启动 Chat 子进程，接线 supervisor / mode_selector / security_agent
3. 创建 `ConversationState`、注册工具策略会话查询、`CLICommandHandler`、`ConversationLoop`
4. 按 `CONTEXT_MODE` 与工具策略解析工具集，经 `ProtocolManager.inject_protocol` 注入系统提示
5. 用户输入循环：命令处理 →（auto 模式可选 ModeSelector）→ LLM 请求 → 协议校验 → 工具执行

### 3. Desktop 路径

1. FastAPI lifespan：`initialize_desktop_backend()`（复用 main 初始化）
2. 启动独立 WebSocket 推送进程（端口 = HTTP + 1），接线日志 / TODO / Agent 监控 / 确认桥
3. 每个会话由 `ConversationLoopManager` 维护独立 `ConversationLoop`
4. **后端自驱任务循环**：前端 `POST /api/task/submit` 提交任务后，后端在线程池内自动逐轮推进直至终态，前端只消费 WebSocket `task_event` 事件流（`task_started / round_reply / tool_call / tool_result / todo_update / task_finished`，以及异步旁路事件 `command_intent / security_malicious / security_remediation`）。因此关闭前端页面或切换标签不影响任务继续执行。

---

## 核心子系统

### 对话状态

| 组件 | 文件 | 职责 |
|------|------|------|
| `ConversationState` | `base/state_manager.py` | 单会话消息、token、TODO、context_mode、interrupt_epoch、会话级工具策略 |
| `MultiSessionManager` | 同上 | 多会话创建/切换/删除（桌面） |
| `session_context` | `base/session_context.py` | ContextVar 绑定 conversation_id / task_source / task_epoch |

### 对话循环 `ConversationLoop`

- 每轮重建系统提示（动态 TODO / 目录 / 角色）
- 管理上下文长度与过大工具结果（压缩 / 截断）
- 通过 IPC 向 Chat 进程发请求
- 解析 `@SPORE:ACTION_*` 并执行工具（single / sequence / parallel）
- 工具策略运行时拦截：被禁用的工具或子工具即使被模型调用也会以拒绝信息作为 RESULT 返回
- `execute_command` 先经 SecurityGuard；文件写删挂接 BackupManager 检查点
- 回写 `@SPORE:RESULT` / 处理 `@SPORE:STOP_REASON=`
- Supervisor 辅助判定连续无 ACTION 轮次是否陷入循环
- 支持中断清理（epoch 校验）与 TODO 块更新

### 文本协议 `base/text_protocol`

**不使用 OpenAI Function Calling**，统一用可读文本协议，兼容 OpenAI / Anthropic / 第三方兼容接口。

常见标记：

```text
@SPORE:ACTION_SINGLE_START
file type=read file_path="C:/demo.txt"
@SPORE:ACTION_SINGLE_END

@SPORE:ACTION_SEQUENCE_START
... 顺序多工具 ...
@SPORE:ACTION_SEQUENCE_END

@SPORE:ACTION_PARALLEL_START
... 并行多工具 ...
@SPORE:ACTION_PARALLEL_END

@SPORE:RESULT_START
... 工具结果 ...
@SPORE:RESULT_END

@SPORE:STOP_REASON=任务已完成
```

组件：

- `ProtocolManager`：协议注入、响应扫描、结果/错误格式化；会按当前可用工具隐藏并行/多 Agent 文档
- `ActionParser`：解析工具名与参数 DSL（含 `@SPORE:CONTENT_START/END` 多行值）
- `ResultFormatter` / `ToolDocGenerator`：结果与工具文档

> 终止标记为 **`STOP_REASON`**（自然语言终止原因）；过程性回复放在 `@SPORE:REPLY_START/END`。主 Agent 的回复语言跟随用户消息语言。

### 工具系统 `base/tools.py` + `base/utils/`

主 Agent 可用工具（定义名）：

| 工具 | 子工具 | 说明 |
|------|--------|------|
| `skill_query` | — | 查询 `skills/<name>/SKILL.md` |
| `execute_command` | — | PowerShell（EncodedCommand），可设 timeout / working_dir；受 SecurityGuard 管控 |
| `file` | read / write / delete | 文件读写删 |
| `edit` | single / multi / line | 精确替换 / 批量 / 按行编辑 |
| `Grep` | — | 内置 ripgrep 内容搜索 |
| `web_browser` | visit / search | 打开网页或搜索 |
| `multi_agent_dispatch` | 按子 Agent 类型 | 派发子 Agent（**仅 long_context 工具集**） |
| `check_subagent_status` | — | 查询异步子 Agent 进度（桌面异步派发场景） |

工具集基线见 `base/agent_types.py`：

- `strong_context`：不含 `multi_agent_dispatch`
- `long_context`：含 `multi_agent_dispatch`
- `auto`：由 `AutoAgent.mode_selector` 判定后加载对应工具集

### 工具策略（v4.0）`base/tool_policy.py`

在模式基线之上，可对**每个工具乃至子工具**单独开关：

- 粒度：`file.read/write/delete`、`edit.single/multi/line`、`web_browser.visit/search`、`multi_agent_dispatch.<AgentType>` 及各叶子工具
- 作用域：`session`（策略存于各会话 `ConversationState.tool_policies`）或 `global`（持久化到根目录 `tool_policy.json`），由 `TOOL_POLICY_SCOPE` 或桌面 UI 切换
- 双层执行：
  1. **提示词过滤**：`filter_tool_definitions` 将禁用项从工具文档与参数枚举中剔除，模型根本看不到
  2. **运行时守卫**：`check_action_allowed` 在执行前再次校验，拒绝时以说明文字作为 RESULT
- 桌面端在设置的「工具」页可视化编辑（`/api/settings/tools/*`）

### 多 Agent

- `AgentProcessManager` / `SubAgentThread`：线程级子 Agent，独立日志与可选监控终端，按会话注册、epoch 感知中断
- `AgentDatabase`：工具调用记录与任务摘要
- 预定义类型（prompt 动态加载，`prompt/<Type>_prompt.md`）：`Coder`、`WebInfoCollector`、`FileContentAnalyzer`、`TextEditor`
- **派发方式**：
  - CLI：同步阻塞等待，Ctrl+C 可级联终止
  - 桌面：**异步派发**（fire-and-forget），主 Agent 可继续推进其他工作，子 Agent 完成后以 `[系统通知]` 回注对话，期间可用 `check_subagent_status` 查询进度

### 辅助 Agent `AutoAgent/`

| 模块 | 档位 | 作用 |
|------|------|------|
| `mode_selector` | `mode_selector` | `CONTEXT_MODE=auto` 时按用户输入选择 strong/long |
| `supervisor` | `supervisor` | 判定回合是否结束/是否重复（YES/NO） |
| `security_agent` | `security` | 命令意图分析、风险评估、恶意熔断与修复建议（见下节） |

三者均通过 IPC 走 Chat 进程，可经 `AGENT_SUPERVISOR_*` / `AGENT_MODE_SELECTOR_*` / `AGENT_SECURITY_*` 配置**各自独立的模型**（回退链：档位专属 → `SUB_AGENT_*` → 主配置），见 `Config.resolve_agent_llm`。

### 安全体系（v4.0）

由**静态命令拦截**（始终可用）与**安全 Agent 研判**（`SECURITY_AGENT_MODE` 选择策略）两部分组成：

1. **命令拦截**（静态规则）：`COMMAND_INTERCEPT` 总开关 + `INTERCEPT_SHELL_DELETE` / `INTERCEPT_SHELL_WRITE`，直接拦下 shell 删除/写文件命令，引导走 `file` 工具（有确认与备份）。
2. **安全 Agent 研判**：`SECURITY_AGENT_MODE` 三档，`basic` 与 `full` 是**两种互斥策略**（不叠加）：
   - `off`：不研判，直接放行
   - `basic`（事前把关）：`base/security_guard.py` 用高危关键字规则表（服务、注册表 HKLM、防火墙、驱动、磁盘、Defender、启动项、卷影副本、计划任务、执行策略、账户、ACL、电源、关键进程等）预筛，命中才送 AI 风险评估（`security_prompt.md`），按风险等级与 `SECURITY_GUARD_MODE`（`strict`/`balanced`/`permissive`）决定**自动放行（低）/ 快速确认（中）/ 强制详细确认（高）**；白名单 `security_whitelist.json`（CLI `whitelist` 命令 / 确认时可加入）直接放行；经确认的高危操作记入审计日志 `.spore/security_audit.jsonl`
   - `full`（默认，异步旁路）：**不做关键词预筛、没有确认弹窗**，每条 `execute_command` 都交给 `AutoAgent/security_agent.py` 后台异步研判，不阻塞执行：
     - **异步意图分析**：生成人话意图说明（`command_intent` 事件，前端以脚注展示）
     - **恶意熔断**：判定为恶意时写审计、**中断当前会话**（epoch 提升 + 终止子 Agent）、推送 `security_malicious`
     - **修复建议**：熔断后生成 `security_remediation`（含 `auto_fix_prompt`），前端弹窗提供「手动处理」或「自动修复」（新开会话执行）
3. 面向用户的文字语言跟随 `SYSTEM_LANGUAGE`。

### 备份与回滚（v4.0）`base/backup_manager.py`

双层「时间机器」，数据存于 `.spore/`：

- **文件级**：Agent 每次写/删文件前自动留底（基线 + `bsdiff4` 增量补丁，按内容哈希去重）；`rollback <文件> [--to <版本>|--steps N]`、`filehistory` 查看/恢复
- **对话点检查点**：每轮任务开始时记录文件与对话状态；`rewind [<checkpoint_id>|--turns N]` 一键把**文件 + 对话历史 + TODO** 一起回到该时点
- 桌面端对应 `/api/backup/*` 与设置菜单「备份/回滚」页
- 开关与限额：`BACKUP_ENABLED` / `BACKUP_DIR` / `BACKUP_MAX_FILE_BYTES` / `BACKUP_MAX_DELETE_FILES`

### IPC 与 Chat 进程

- `IPCManager`：`multiprocessing` 队列 + 请求分发线程，按 `request_id` 匹配响应，支持逻辑取消
- Chat 进程：双 SDK 调用、重试策略（0/5/15/25s）、流式输出、响应过期清理、按 Agent 档位缓存客户端
- 中断：主进程发取消信号，可级联终止当前会话子 Agent

### 桌面后端

| 区域 | 说明 |
|------|------|
| REST routes | `/api/chat`（单轮/中断/历史/会话管理）、`/api/task`（自驱任务）、`/api/commands`（模式/记忆/角色/历史）、`/api/files`（沙箱文件 CRUD）、`/api/agents`、`/api/settings`（.env/档案/语言/工具策略）、`/api/backup`、`/api/instances`、`/api/confirm` |
| WebSocket（:8766，独立进程） | 事件：`log` / `agent_register` / `agent_output` / `agent_status` / `todo_update` / `confirm_request` / `confirm_cancel` / `task_event`；批量下发（5 条或 50ms 刷新） |
| confirm_manager | 文件写删与高危命令经 WS `confirm_request` 阻塞等待前端确认 |
| security_interrupt | 恶意命令熔断桥：会话自中断 + 合成 `task_event` |
| settings / profiles | 读写 `.env`、配置档案、命令拦截开关、系统语言、工具策略 |
| instance_manager | 多后端实例（端口隔离） |

文件路由沙箱：仅允许 `output` / `skills` / `prompt` / `history` / `characters` 及根目录 `note.txt`、`.env`；`prompt/skills/characters` 为只读资源根。

### 配置

- 权威源：`base/config.py` + 项目根 `.env`
- 桌面「环境配置」：基础（SDK + Key/URL/模型）与高级（折叠）两栏；配置档案见 `config_profiles.py`
- 桌面可热应用：`apply_runtime_config()`（重载 `.env`、重启 Chat 进程、按会话重解析工具）
- 详见 [CONFIGURATION.md](CONFIGURATION.md)

### 日志与推送

- 落盘：`base/logger.py` 按 `session_context` 写入 `logs/<启动时间>/conversations/<id>/`
- 推送：`websocket/log_bridge.py` 附加 `conversation_id`；前端 `logStore` 按会话分桶
- 正文不嵌入 `session_id`（仅路由字段携带会话信息）

### 记忆与历史

- 手动保存：`history/YYYY-mm-dd_HHMMSS.mem`
- 自动短记忆：`history/autosave/session_<id>.mem`（按会话 upsert，容量约 10）
- `savemode`：压缩多步中间过程，仅保留用户消息与最终回复倾向

### 国际化（v4.0）

- 后端：`SYSTEM_LANGUAGE=zh|en` 决定辅助 Agent 面向用户的输出语言（命令意图、修复建议）；`/api/settings/language` 读写
- 前端：`src/i18n/` 自研轻量 i18n（Zustand，中英文 23+ 命名空间），标题栏「中/EN」开关，切换时同步后端
- 主 Agent 回复语言始终跟随用户消息语言（`prompt/prompt.md` 规则 8）

---

## 数据流

### 单轮用户消息

```
用户输入 (GUI/CLI)
  → ConversationLoop.send_chat_request
  → IPC → Chat 进程 → LLM
  → ProtocolManager.parse_response
  → 若 ACTION_*：工具策略校验 → (execute_command 先过 SecurityGuard)
      → 执行工具 → BackupManager 留底 → format_result → 再请求 LLM
  → 若 STOP_REASON：结束本轮并展示
```

### 桌面自驱任务

```
前端 POST /api/task/submit
  → 后端线程池逐轮驱动 run_single_round（1800s 看门狗）
  → 每个节点推送 WS task_event（round_reply / tool_call / ...）
  → 异步旁路：command_intent / security_malicious / security_remediation
  → task_finished → 前端渲染终态；断线重连后可拉快照恢复
```

### 多 Agent（long_context）

```
主 Agent multi_agent_dispatch
  → AgentProcessManager.dispatch_tasks
  → SubAgentThread（独立工具循环 + 日志）
  → CLI：阻塞汇总 → 回主 Agent RESULT
  → 桌面：异步执行 → 完成后 [系统通知] 回注对话
```

---

## 扩展点

### 新工具

1. 在 `base/utils/` 实现逻辑
2. `base/tools.py` 的 `TOOL_DEFINITIONS` 增加定义
3. 增加 `handle_*` 并注册
4. 按需加入 `STRONG_CONTEXT_TOOLS` / `LONG_CONTEXT_TOOLS` 或子 Agent `tools_list`；如需细粒度开关，在 `base/tool_policy.py` 注册子工具

### 新技能

1. `skills/<skill-name>/SKILL.md`
2. 可选 scripts / references / requirements.txt
3. Agent 通过 `skill_query` 按需加载

### 新角色

1. `characters/*.md`
2. CLI `char select` 或桌面设置 / `DEFAULT_CHARACTER`

### 新子 Agent 类型

1. `base/agent_types.py` 的 `PREDEFINED_AGENT_TYPES` 注册工具列表
2. `prompt/<Type>_prompt.md`
3. 由 `multi_agent_dispatch` 指定类型名使用

---

## 性能相关

- Chat 线程池：`CHAT_MAX_WORKERS`（默认 5）
- 子 Agent 并发：`MULTI_AGENT_MAX_COUNT`（默认 5）
- 上下文：`CONTEXT_MAX_TOKENS` + 压缩 / savemode / `LIMIT_WRITE_TOOL_RETURN`
- 技能按需查询，避免全量塞进 system prompt
- WebSocket 批量下发；日志轮转与响应缓存过期清理
- 备份采用哈希去重 + 二进制增量，正常使用下磁盘占用可控

---

## 版本

文档对应 **Spore 4.0**（git 提交 `v4.0`）。

所有版本字段（`pyproject.toml`、前端 `package.json`、`tauri.conf.json`、`Cargo.toml`、后端 API `version`）均为 `4.0.0`。

更多：

- [配置说明](CONFIGURATION.md)
- [CLI 模式](CLI.md)
- [构建指南](BUILD.md)
- [技能开发](SKILLS.md)
- [前端使用](FRONTEND.md)
- [银狐案例](SILVERFOX.md)
