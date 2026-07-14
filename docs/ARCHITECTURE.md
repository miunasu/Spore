# Spore AI Agent 架构设计（v3.0）

本文档描述 **Spore 3.0** 重构后的实际代码架构。入口、对话循环、文本协议、多会话桌面后端与工具系统均以当前仓库为准。

---

## 系统架构概览

```
┌─────────────────────────────────────────────────────────────────────┐
│                          用户界面层                                   │
├─────────────────────────────────┬───────────────────────────────────┤
│         GUI 模式 (Tauri)        │        CLI 模式 (Terminal)        │
│  React + TypeScript             │  命令行交互界面                     │
│  - 多标签页 / 多会话对话        │  - CLICommandHandler               │
│  - 文件管理与编辑               │  - 日志监控独立终端                 │
│  - 实时日志 / TODO / 确认栏     │  - 直接 stdin 对话循环              │
│  - WebSocket 推送               │                                    │
└─────────────┬───────────────────┴──────────────┬───────────────────┘
              │ HTTP + WebSocket                 │ 进程内调用
┌─────────────┴──────────────────────────────────┴───────────────────┐
│                     应用入口 (main_entry.py)                         │
│  LAUNCH_MODE=cli|desktop → main.py | desktop_app.backend.server      │
│  打包环境：resource_manager 校正工作目录与资源路径                     │
└─────────────┬──────────────────────────────────┬───────────────────┘
              │                                  │
    ┌─────────┴─────────┐              ┌─────────┴──────────┐
    │ Desktop Backend   │              │ CLI Main Loop      │
    │ FastAPI + WS 进程 │              │ ConversationLoop   │
    └─────────┬─────────┘              └─────────┬──────────┘
              │                                  │
┌─────────────┴──────────────────────────────────┴───────────────────┐
│                          业务逻辑层                                   │
│  ConversationLoop（文本协议驱动）                                     │
│  ├─ ConversationState / MultiSessionManager                         │
│  ├─ ProtocolManager + ActionParser                                  │
│  ├─ Tools (file/edit/Grep/execute_command/web_browser/...)          │
│  ├─ ModeSelector / CharacterManager / TodoManager / RuleReminder    │
│  └─ multi_agent_dispatch → AgentProcessManager / SubAgentThread     │
└─────────────┬──────────────────────────────────────────────────────┘
              │ multiprocessing Queue IPC
┌─────────────┴──────────────────────────────────────────────────────┐
│  Chat 进程 (base/chat_process.py)                                    │
│  - OpenAI / Anthropic SDK                                            │
│  - 线程池并发请求 (CHAT_MAX_WORKERS)                                 │
│  - 流式 token 与响应缓存                                              │
└────────────────────────────────────────────────────────────────────┘
```

---

## 目录与模块地图

```
Spore/
├── main_entry.py              # 统一入口：cli / desktop
├── main.py                    # CLI 主循环
├── pyproject.toml             # Python 依赖与版本
├── build_installer.bat        # 一键打包安装器
├── spore_backend.spec         # PyInstaller 规格
│
├── base/                      # 核心运行时
│   ├── config.py              # .env → Config 单例
│   ├── config_profiles.py     # 配置档案（桌面设置）
│   ├── client.py              # LLM 客户端工厂
│   ├── chat_process.py        # 独立 Chat 子进程
│   ├── ipc_manager.py         # 主进程 ↔ Chat 进程 IPC
│   ├── conversation_loop.py   # 主对话循环（协议解析+工具执行）
│   ├── state_manager.py       # ConversationState / MultiSessionManager
│   ├── session_context.py     # 当前会话上下文（线程局部）
│   ├── memory_manager.py      # history/ 与 autosave 持久化
│   ├── cli_commands.py        # CLI 命令
│   ├── tools.py               # TOOL_DEFINITIONS + 处理器
│   ├── agent_types.py         # 主 Agent 工具集 / 子 Agent 类型
│   ├── agent_process.py       # 多 Agent 线程与协调
│   ├── agent_database.py      # 子 Agent 任务与工具调用记录
│   ├── character_manager.py   # 角色选择
│   ├── todo_manager.py        # 声明式 TODO（按会话）
│   ├── rule_reminder.py       # 周期性规则提醒
│   ├── prompt_loader.py       # prompt / skills 装配
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
│   └── supervisor.py          # 结束判定辅助
│
├── desktop_app/
│   ├── resource_manager.py    # 打包环境初始化
│   ├── backend/
│   │   ├── server.py          # FastAPI 主服务
│   │   ├── standalone.py      # 多实例子进程入口
│   │   ├── core.py            # 复用 CLI 初始化逻辑
│   │   ├── conversation_loop_manager.py  # 每会话独立 ConversationLoop
│   │   ├── confirm_manager.py # 危险操作 WebSocket 确认
│   │   ├── instance_manager.py
│   │   ├── routes/            # chat / task / files / settings / ...
│   │   └── websocket/         # 推送进程、日志桥、IPC 桥
│   └── frontend/              # React + Tauri
│
├── prompt/                    # 系统与子 Agent 提示词
├── skills/                    # Claude Skills 风格技能包
├── characters/                # 角色 Markdown
├── history/                   # 对话存档与 autosave
├── docs/                      # 文档
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
2. `initialize_ipc_system()` 启动 Chat 子进程
3. 创建 `ConversationState` + `CLICommandHandler` + `ConversationLoop`
4. 按 `CONTEXT_MODE` 加载工具集，经 `ProtocolManager.inject_protocol` 注入系统提示
5. 用户输入循环：命令处理 →（auto 模式可选 ModeSelector）→ LLM 请求 → 协议校验 → 工具执行

### 3. Desktop 路径

1. FastAPI lifespan：`initialize_desktop_backend()`（复用 main 初始化）
2. 启动 WebSocket 推送进程、日志/TODO/确认桥
3. 每个会话由 `ConversationLoopManager` 维护独立 `SessionConversationLoop`
4. 前端经 REST 提交任务（`/api/task`、`/api/chat`），经 WebSocket 接收流式事件

---

## 核心子系统

### 对话状态

| 组件 | 文件 | 职责 |
|------|------|------|
| `ConversationState` | `base/state_manager.py` | 单会话消息、token、TODO、context_mode、节省模式等 |
| `MultiSessionManager` | 同上 | 多会话创建/切换/删除（桌面） |
| `session_context` | `base/session_context.py` | 线程级当前 conversation_id |

### 对话循环 `ConversationLoop`

- 管理上下文长度与过大工具结果
- 通过 IPC 向 Chat 进程发请求
- 解析 `@SPORE:ACTION_*` 并执行工具
- 回写 `@SPORE:RESULT` / 处理 `@SPORE:STOP_REASON=`
- 支持中断清理与 TODO 块更新

桌面端封装：`SessionConversationLoop` 绑定固定会话，不再总是读 “current session”。

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

- `ProtocolManager`：协议注入、响应扫描、结果/错误格式化
- `ActionParser`：解析工具名与参数 DSL（含 `@SPORE:CONTENT_START/END` 多行值）
- `ResultFormatter` / `ToolDocGenerator`：结果与工具文档

> 注意：终止标记为 **`STOP_REASON`**，不是旧文档中的 `FINAL`。

### 工具系统 `base/tools.py` + `base/utils/`

主 Agent 可用工具（定义名）：

| 工具 | 说明 |
|------|------|
| `skill_query` | 查询 `skills/<name>/SKILL.md` |
| `execute_command` | PowerShell（EncodedCommand），可设 timeout / working_dir |
| `file` | read / write / delete |
| `edit` | 精确替换 / 批量 / 按行编辑 |
| `Grep` | 基于 ripgrep 的内容搜索 |
| `web_browser` | 打开网页或搜索 |
| `multi_agent_dispatch` | 派发子 Agent（**仅 long_context 工具集**） |

工具集切换见 `base/agent_types.py`：

- `strong_context`：不含 `multi_agent_dispatch`
- `long_context`：含 `multi_agent_dispatch`
- `auto`：由 `AutoAgent.mode_selector` 判定后加载对应工具集

### 多 Agent

- `AgentProcessManager` / `SubAgentThread`：线程级子 Agent，独立日志与可选监控终端
- `MultiAgentCoordinator`：派发、中断收集、纠正后重派
- `AgentDatabase`：工具调用记录与任务摘要
- 预定义类型（prompt 动态加载）：
  - `Coder`
  - `WebInfoCollector`
  - `FileContentAnalyzer`
  - `TextEditor`

### AutoAgent

| 模块 | 作用 |
|------|------|
| `mode_selector` | `CONTEXT_MODE=auto` 时选择 strong/long |
| `supervisor` | 辅助判断是否应结束（文本协议版 end_check） |

### IPC 与 Chat 进程

- `IPCManager`：`multiprocessing` 队列 + 请求分发线程
- Chat 进程：SDK 调用、流式输出、响应过期清理
- 中断：主进程发取消信号，可级联终止当前会话子 Agent

### 桌面后端

| 区域 | 说明 |
|------|------|
| REST routes | chat / task / commands / files / agents / settings / instances / confirm |
| WebSocket | 独立进程推送日志、消息增量、确认请求、Agent 监控 |
| confirm_manager | 写删等高风险操作走前端确认 |
| settings / profiles | 读写 `.env`、配置档案、命令拦截开关 |
| instance_manager | 多后端实例（端口隔离） |

### 配置

- 权威源：`base/config.py` + 项目根 `.env`
- 桌面「环境配置」：`CommandMenu` 分 **基础**（SDK + Key/URL/模型）与 **高级**（折叠）两栏；profiles 见 `config_profiles.py`
- 桌面可热应用部分设置：`apply_runtime_config()` / profiles
- 详见 [CONFIGURATION.md](CONFIGURATION.md)

### 日志与推送

- 落盘：`base/logger.py` 按 `session_context` 写入 `conversations/<id>/`
- 推送：`desktop_app/backend/websocket/log_bridge.py` 附加 `conversation_id`；前端 `logStore` 按会话分桶
- 正文不嵌入 `session_id`（仅路由字段携带会话信息）

### 记忆与历史

- 手动保存：`history/YYYY-mm-dd_HHMMSS.mem`
- 自动短记忆：`history/autosave/session_<id>.mem`（按会话 upsert，容量约 10）
- `savemode`：压缩多步中间过程，仅保留用户消息与最终回复倾向

### 安全与可控

- **命令拦截** `COMMAND_INTERCEPT` + `INTERCEPT_SHELL_DELETE` / `INTERCEPT_SHELL_WRITE`
- **桌面确认**：文件写删等经 `confirm_manager`
- **中断**：CLI `Ctrl+C`；GUI 停止按钮；会话级子 Agent 终止
- **资源限制**：`MULTI_AGENT_MAX_COUNT`、`SUB_AGENT_MAX_ITERATIONS`、工具/Shell 超时

---

## 数据流

### 单轮用户消息

```
用户输入 (GUI/CLI)
  → ConversationLoop.send_chat_request
  → IPC → Chat 进程 → LLM
  → ProtocolManager.parse_response
  → 若 ACTION_*：执行工具 → format_result → 再请求 LLM
  → 若 STOP_REASON：结束本轮并展示
```

### 多 Agent（long_context）

```
主 Agent multi_agent_dispatch
  → AgentProcessManager.dispatch_tasks
  → SubAgentThread（独立工具循环 + 日志）
  → 汇总数据库摘要
  → 回主 Agent RESULT
```

---

## 扩展点

### 新工具

1. 在 `base/utils/` 实现逻辑
2. `base/tools.py` 的 `TOOL_DEFINITIONS` 增加定义
3. 增加 `handle_*` 并注册
4. 按需加入 `STRONG_CONTEXT_TOOLS` / `LONG_CONTEXT_TOOLS` 或子 Agent `tools_list`

### 新技能

1. `skills/<skill-name>/SKILL.md`
2. 可选 scripts / references / requirements.txt
3. Agent 通过 `skill_query` 按需加载

### 新角色

1. `characters/*.md`
2. CLI `char select` 或桌面设置 / `DEFAULT_CHARACTER`

### 新子 Agent 类型

1. `PREDEFINED_AGENT_TYPES` 注册工具列表
2. `prompt/<Name>_prompt.md`
3. 由 `multi_agent_dispatch` 指定类型名使用

---

## 性能相关

- Chat 线程池：`CHAT_MAX_WORKERS`（默认 5）
- 子 Agent 并发：`MULTI_AGENT_MAX_COUNT`（默认 5）
- 上下文：`CONTEXT_MAX_TOKENS` + 压缩 / savemode
- 技能按需查询，避免全量塞进 system prompt
- 日志轮转与响应缓存过期清理

---

## 版本

| 项 | 值 |
|----|----|
| 文档对应版本 | **3.0** |
| Python 包 | `pyproject.toml` → `3.0.0` |
| 桌面前端 / Tauri | `package.json` / `tauri.conf.json` → `3.0.0` |
| 后端 API `version` 字段 | `3.0.0` |

更多：

- [配置说明](CONFIGURATION.md)
- [CLI 模式](CLI.md)
- [构建指南](BUILD.md)
- [技能开发](SKILLS.md)
- [前端使用](FRONTEND.md)