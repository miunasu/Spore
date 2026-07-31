# 配置说明（v4.0）

> [English](en/CONFIGURATION.md)

权威配置源为项目根目录 `.env`，由 `base/config.py` 的 `Config` 加载。  
桌面 GUI「设置 → 环境配置」最终也读写同一套变量：页面分为 **基础配置**（最小可用）与 **高级配置**（默认折叠），并支持 **配置档案（profiles）**。

> 变量名以代码为准。旧文档中的 `OPENAI_BASE_URL`、`MODEL_MAIN`、`MAX_CONTEXT_TOKENS`、`MAX_TOKENS_MAIN`、`DESKTOP_CONFIRM_ENABLED`、`LLM_API_KEY`、`LLM_API_URL` 等 **已不再使用**。

---

## 快速开始（最小可用）

```env
# 选择 SDK
LLM_SDK=openai

# OpenAI 兼容接口（含 DeepSeek 等）
OPENAI_API_KEY=sk-...
OPENAI_API_URL=https://api.deepseek.com
OPENAI_MODEL=deepseek-chat

# 启动桌面
LAUNCH_MODE=desktop
DESKTOP_API_PORT=8765

# 上下文
CONTEXT_MODE=strong_context
CONTEXT_MAX_TOKENS=128000
```

Anthropic 示例：

```env
LLM_SDK=anthropic
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-4-20250514
# ANTHROPIC_EFFORT=medium
# ANTHROPIC_THINKING_MODE=adaptive
```

---

## LLM 配置

### SDK 选择

| 变量 | 默认 | 说明 |
|------|------|------|
| `LLM_SDK` | `openai` | `openai` 或 `anthropic` |
| `LLM_STREAM_ENABLED` | `true` | 主 Agent 使用流式接口，并在生成到用户可见区段时实时更新桌面聊天消息；第三方代理不支持流式时设为 `false` |

### OpenAI / 兼容接口

| 变量 | 默认 | 说明 |
|------|------|------|
| `OPENAI_API_KEY` | 空 | 必需（当 SDK=openai） |
| `OPENAI_API_URL` | 空 | 自定义 Base URL（DeepSeek 等） |
| `OPENAI_MODEL` | `gpt-4o-mini` | 主模型名 |
| `USE_RESPONSES_API` | `false` | `true` 时用 Responses API（o 系列等） |
| `OPENAI_REASONING_EFFORT` | 空 | `low` / `medium` / `high` / `xhigh`，空则不传 |

### Anthropic

| 变量 | 默认 | 说明 |
|------|------|------|
| `ANTHROPIC_API_KEY` | 空 | 必需（当 SDK=anthropic） |
| `ANTHROPIC_API_URL` | 空 | 自定义 API URL |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-20250514` | 模型名 |
| `ANTHROPIC_EFFORT` | 空 | `low`/`medium`/`high`/`xhigh`/`max` → `output_config.effort` |
| `ANTHROPIC_THINKING_MODE` | 空（自动） | `adaptive` / `enabled` / `disabled` |
| `ANTHROPIC_THINKING_BUDGET_TOKENS` | 空 | 仅 `enabled` 模式使用 |

### 代理 / 第三方网关兼容

| 变量 | 默认 | 说明 |
|------|------|------|
| `CLEAN_SDK_HEADERS` | `false` | 清理 x-stainless 等 SDK 头 |
| `CLEAN_AUTH_HEADER` | `false` | Anthropic 场景移除多余 Authorization |

### Embedding / Learning

Learning 使用 OpenAI-compatible embeddings HTTP 接口（`<base_url>/v1/embeddings`）；当 `LLM_SDK=anthropic` 时不会自动切换到 Anthropic embedding API：

| 变量 | 默认 | 说明 |
|------|------|------|
| `EMBEDDING_API_KEY` | 回退 `OPENAI_API_KEY` | Embedding 服务 API Key |
| `EMBEDDING_API_URL` | 回退 `OPENAI_API_URL` | Embedding 服务 Base URL；为空时使用 OpenAI 默认地址 |
| `EMBEDDING_MODEL` | `text-embedding-3-small` | Embedding 模型名 |
| `LEARNING_DB_PATH` | `<runtime_root>/.spore/memory/episodic.db` | Learning SQLite 路径；相对路径相对运行根解析 |
| `EPISODIC_DB_PATH` | 同上 | SQLite 路径兼容别名；`LEARNING_DB_PATH` 优先 |

若主 OpenAI-compatible 模型服务不支持 embeddings，或只配置了 Anthropic Key，应单独设置 `EMBEDDING_API_KEY` / `EMBEDDING_API_URL` / `EMBEDDING_MODEL`。缺少 embedding 配置或请求失败时，Learning 检索/记录会跳过，但主对话继续；没有本地 embedding 或 FTS 回退。

### 子 Agent 独立 LLM（可选，空=继承主 Agent）

| 变量 | 说明 |
|------|------|
| `SUB_AGENT_LLM_SDK` | 子 Agent SDK |
| `SUB_AGENT_OPENAI_API_KEY` / `SUB_AGENT_OPENAI_API_URL` / `SUB_AGENT_OPENAI_MODEL` | 子 Agent OpenAI |
| `SUB_AGENT_ANTHROPIC_API_KEY` / `SUB_AGENT_ANTHROPIC_API_URL` / `SUB_AGENT_ANTHROPIC_MODEL` | 子 Agent Anthropic |

### 辅助 Agent 独立 LLM（v4.0，可选）

三个辅助 Agent 档位可各自指定模型，回退链：**档位专属 → `SUB_AGENT_*` → 主配置**（按字段逐项回退，见 `Config.resolve_agent_llm`）：

| 前缀 | 对应 Agent |
|------|-----------|
| `AGENT_SUPERVISOR_*` | Supervisor（循环/终止判定） |
| `AGENT_MODE_SELECTOR_*` | ModeSelector（auto 模式选择） |
| `AGENT_SECURITY_*` | 安全 Agent（意图/风险/熔断） |

每个前缀支持的后缀与主配置一致：`LLM_SDK`、`OPENAI_API_KEY/API_URL/MODEL`、`ANTHROPIC_API_KEY/API_URL/MODEL` 及 effort / thinking 等。

示例——安全 Agent 用便宜的小模型：

```env
AGENT_SECURITY_LLM_SDK=openai
AGENT_SECURITY_OPENAI_MODEL=gpt-4o-mini
```

### 输出与超时

| 变量 | 默认 | 说明 |
|------|------|------|
| `MAX_OUTPUT_TOKENS` | `15000` | 单次 LLM 输出上限 |
| `API_TIMEOUT` | `300` | API 超时（秒） |

### System Prompt 行为

| 变量 | 默认 | 说明 |
|------|------|------|
| `SYSTEM_PROMPT_FILE` | `prompt.md` | `prompt/` 下的文件名 |
| `SYSTEM_AS_USER` | `false` | 将 system 作为首条 user（兼容部分网关） |

---

## 启动与桌面

| 变量 | 默认 | 说明 |
|------|------|------|
| `LAUNCH_MODE` | `cli` | `cli` 或 `desktop` |
| `DESKTOP_API_HOST` | `127.0.0.1` | FastAPI 监听地址 |
| `DESKTOP_API_PORT` | `8765` | 仅影响 REST 端口。后端会按 REST + 1 推导 WS 监听端口，但当前 React 客户端仍固定连接 `8766`；修改此值不会同步前端 WebSocket 地址 |
| `SYSTEM_LANGUAGE` | `zh` | 系统语言：`zh` 或 `en`。影响面向用户的辅助 Agent 输出（命令意图说明、熔断修复建议）。桌面端标题栏的语言开关会自动同步此项；主 Agent 始终跟随用户消息所用的语言。 |

打包运行时还会使用环境变量（由 Tauri / 安装器注入）：

- `SPORE_RESOURCE_DIR`：资源目录（prompt/skills/characters 等）
- `SPORE_DESKTOP_MODE`：桌面静默标识
- `SPORE_INSTANCE_ID` / `SPORE_INSTANCE_PORT`：多实例子进程

---

## 上下文模式

| 变量 | 默认 | 说明 |
|------|------|------|
| `CONTEXT_MODE` | `strong_context` | 新会话默认模式 |
| `CONTEXT_MAX_TOKENS` | `128000` | 上下文 token 上限 |
| `CONTEXT_WARNING_THRESHOLD` | `0.8` | 压缩触发阈值（比例） |
| `MAX_SINGLE_MESSAGE_RATIO` | `0.3` | 单条消息相对上限 |

### 模式含义

| 模式 | 行为 |
|------|------|
| `strong_context` | 强关联单 Agent 工具集，**无** `multi_agent_dispatch` |
| `long_context` | 长上下文 / 多 Agent 倾向，**含** `multi_agent_dispatch` |
| `auto` | 每轮由 ModeSelector 选择 strong 或 long |

运行时可在 CLI `mode ...` 或 GUI 模式下拉框切换，作用于**当前会话**。

---

## 安全（v4.0）

### 安全 Agent

| 变量 | 默认 | 说明 |
|------|------|------|
| `SECURITY_AGENT_MODE` | `full` | `off` 完全关闭；`basic` 事前把关：高危关键字命中后做 AI 风险评估，按风险等级自动放行 / 确认 / 阻止；`full`（默认）异步旁路：**不做关键词预筛、无确认弹窗**，每条命令后台异步研判意图与恶意，判恶意即熔断并生成修复建议。`basic` 与 `full` 是两种互斥策略 |
| `SECURITY_GUARD_MODE` | `balanced` | 仅 `basic` 模式生效：`strict` 命中即确认 / `balanced` 中高风险确认 / `permissive` 仅高风险确认 |
| `SECURITY_LLM_TIMEOUT` | `30` | 风险评估 LLM 超时（秒） |
| `SECURITY_INTENT_TIMEOUT` | `45` | 意图分析 LLM 超时（秒） |
| `SECURITY_AGENT_SESSION_CONTEXT` | `false` | 仅 `full` 模式：后续安全分析请求携带同 session 已成功研判的命令上下文 |
| `SECURITY_SESSION_CONTEXT_MAX_COMMANDS` | `20` | 上下文最多携带的最近历史命令数 |

`full` 模式会话上下文边界：

- 默认关闭时，命令仍逐条研判，成功研判的完整命令也会按 session 收集在进程内存中，只是不把既往历史发送给后续安全分析请求
- 开启后，最近命令会与当前命令一起发送给配置的安全模型服务。命令可能包含路径、参数、令牌或其他秘密，启用前应评估该服务的数据处理政策
- 历史只在进程内存中；恶意事件另行写入 `.spore/security_audit.jsonl`
- `clear_session_history()` 当前尚未接入新对话、清记忆、reset 或删除 session 的生命周期；这些操作不会清除该历史，只有整个进程退出才自然释放

相关数据文件（自动生成、git 忽略）：

- `security_whitelist.json`：信任命令白名单（`basic` 模式生效；CLI `whitelist` 命令或确认时加入）
- `.spore/security_audit.jsonl`：安全审计日志

### 命令拦截

桌面菜单「拦截开关」与下列变量对应：

| 变量 | 默认 | 说明 |
|------|------|------|
| `COMMAND_INTERCEPT` | `true`（若未设则兼容旧名 `BLOCK_SHELL_DELETE`） | 总开关 |
| `INTERCEPT_SHELL_DELETE` | 开启 | 拦截 del/rm/Remove-Item 等 |
| `INTERCEPT_SHELL_WRITE` | 开启 | 拦截 Set-Content/Out-File 等（建议用 `file type=write`） |

> 桌面端的文件写删确认由 `confirm_manager` 走 WebSocket，**没有** `DESKTOP_CONFIRM_ENABLED` 开关。

### 备份与回滚

| 变量 | 默认 | 说明 |
|------|------|------|
| `BACKUP_ENABLED` | `true` | 文件留底 + 对话检查点总开关 |
| `BACKUP_DIR` | `.spore` | 备份数据目录 |
| `BACKUP_MAX_FILE_BYTES` | 50MB | 超过此大小的文件不留底 |
| `BACKUP_MAX_DELETE_FILES` | `200` | 单次删除操作最多备份的文件数 |

对应 CLI 命令 `rollback` / `filehistory` / `checkpoints` / `rewind`，与桌面「备份/回滚」页。

### 工具策略

| 变量 | 默认 | 说明 |
|------|------|------|
| `TOOL_POLICY_SCOPE` | `session` | `session`：策略按会话独立；`global`：读写根目录 `tool_policy.json` 对所有会话生效 |

可开关粒度到子工具（`file.read/write/delete`、`edit.single/multi/line`、`web_browser.visit/search`、`multi_agent_dispatch.<类型>`）。桌面在「设置 → 工具」编辑；详见 [ARCHITECTURE.md](ARCHITECTURE.md)。

---

## 角色系统

| 变量 | 默认 | 说明 |
|------|------|------|
| `DEFAULT_CHARACTER` | 空 | 启动时自动 `select` 的角色名 |
| `CHARACTERS_DIR` | `characters` | 角色目录 |

- 角色文件：`characters/*.md`
- CLI：`char list|select <名>|remove`
- GUI：设置页角色管理

---

## 规则提醒

| 变量 | 默认 | 说明 |
|------|------|------|
| `RULE_REMINDER_INTERVAL` | `10` | 每 N 次 LLM 回复注入提醒；`0` 禁用 |
| `RULE_REMINDER_SHORT` | `false` | 精简提醒以省 token |

---

## 多 Agent

| 变量 | 默认 | 说明 |
|------|------|------|
| `MULTI_AGENT_MAX_COUNT` | `5` | 最大并发子 Agent |
| `SUB_AGENT_MAX_ITERATIONS` | `100` | 单子 Agent 最大迭代 |
| `MULTI_AGENT_TIMEOUT` | 空 | 等待超时秒数，空=无限 |
| `MULTI_AGENT_TOTAL_TIMEOUT` | `3600` | 整批派发总超时（秒） |
| `MULTI_AGENT_MONITOR_ENABLED` | `true` | 是否弹独立监控终端 |
| `MULTI_AGENT_JOIN_INTERVAL` | `2.0` | 等待轮询间隔（秒） |
| `CODER_MAX_ITERATIONS` | `1000` | Coder 子 Agent 迭代上限 |

---

## Chat 进程与 IPC

| 变量 | 默认 | 说明 |
|------|------|------|
| `CHAT_MAX_WORKERS` | `5` | Chat 进程线程池大小 |
| `CHAT_RESPONSE_EXPIRE` | `300` | 响应缓存过期（秒） |
| `CHAT_RESPONSE_CLEANUP_INTERVAL` | `60` | 缓存清理间隔 |
| `IPC_CHECK_INTERVAL` | `0.1` | IPC 轮询间隔 |

---

## 工具执行

| 变量 | 默认 | 说明 |
|------|------|------|
| `TOOL_EXECUTION_TIMEOUT` | `120` | 通用工具超时（秒） |
| `SHELL_COMMAND_TIMEOUT` | `60` | Shell 默认超时 |
| `LIMIT_WRITE_TOOL_RETURN` | `true` | 限制写工具回传内容以省 token |
| `FILE_READ_DEFAULT_LIMIT` | `2000` | 读文件默认行数 |
| `FILE_MAX_LINE_LENGTH` | `2000` | 单行最大长度 |
| `WEB_BROWSER_TIMEOUT` | `15` | 网页超时 |
| `WEB_PROXY_PORT` | `7897` | 非中文域名代理端口；`0` 禁用 |
| `WEB_MAX_CONTENT_LENGTH` | `15000` | 网页正文截断长度 |

---

## 日志

| 变量 | 默认 | 说明 |
|------|------|------|
| `LOG_TO_FILE` | `true` | 写文件日志 |
| `LOG_DIR` | `logs` | 目录 |
| `LOG_FILE_MAX_SIZE` | 10MB | 单文件大小 |
| `LOG_BACKUP_COUNT` | `5` | 备份数 |
| `LOG_ERROR_FILENAME` 等 | `error.log` 等 | 各类日志文件名 |
| `LOG_MONITOR_TYPES` | `error,llm_validation,tool_execution` | 监控展示类型 |
| `LOG_MONITOR_CHECK_INTERVAL` | `0.5` | 监控刷新间隔 |
| `LOG_MONITOR_MAX_LINE_LENGTH` | `200` | 监控行截断 |
| `LOG_RAW_ENABLED` | `true` | Raw 原始回复日志开关 |
| `LOG_RAW_FILENAME` | `raw.log` | Raw 日志文件名 |

目录约定：

- 进程级：`logs/<启动时间>/...`
- 对话级：`logs/<启动时间>/conversations/<conversation_id>/...`（按会话隔离落盘）
- Raw 日志：`logs/<启动时间>/conversations/<conversation_id>/raw.log`

Raw 日志（`LOG_RAW_ENABLED`）：

- 每次 LLM 调用成功后、响应返回调用方之前，把 provider 的**完整**回复文本及 request/model/profile/usage 元数据写入，不截断、不解析、不脱敏、不加密
- 覆盖主 Agent、子 Agent 与辅助 Agent。可从 request ID 解析 session 的主请求写入对应会话目录；其他辅助请求可能写入进程级 `raw.log`
- **只落盘**，不推送到 Desktop 左栏日志，也不进日志监控终端；它不记录请求 messages/system prompt，但回复可能复述命令、文件内容、路径、凭据或个人数据
- 清空或删除会话不会删除已有 raw 日志。若这些数据不应落盘，应显式设置 `LOG_RAW_ENABLED=false`，不要依赖 `LOG_TO_FILE=false`
- Raw 开关关闭时不会创建 `raw.log`

推送到桌面前端的工具 / general 日志：

- 用 WebSocket 字段 `conversation_id` 做会话路由  
- **日志 JSON 正文不再写入 `session_id`**（避免面板噪音；与落盘隔离无关）

---

## 目录路径

| 变量 | 默认 |
|------|------|
| `SKILLS_DIR` | `skills` |
| `CHARACTERS_DIR` | `characters` |
| `PROMPT_DIR` | `prompt` |
| `LOG_DIR` | `logs` |
| `OUTPUT_DIR` | `output` |
| `UPLOAD_DIR` | `uploads` |

对话历史固定使用工作目录下 `history/`（含 `history/autosave/`）；备份数据固定在 `BACKUP_DIR`（默认 `.spore/`）。

---

## 配置方式

### 1. 直接编辑 `.env`

保存后：

- 多数项需重启进程生效  
- 桌面「应用环境配置」会调用运行时热更新（`reload_config` / `apply_runtime_config`：重载 `.env`、重启 Chat 进程、按会话重解析工具集）

### 2. GUI 设置（桌面）

路径：**设置 → 环境配置**（`CommandMenu`）。

1. **基础配置（始终展开）**：只填最小可用项即可运行  
   - `LLM_SDK`  
   - OpenAI：`OPENAI_API_KEY` / `OPENAI_API_URL` / `OPENAI_MODEL`  
   - Anthropic：`ANTHROPIC_API_KEY` / `ANTHROPIC_API_URL` / `ANTHROPIC_MODEL`  
2. **高级配置（默认折叠）**：Responses/Thinking、子 Agent 与辅助 Agent 档位、上下文阈值、SDK 兼容、日志、路径、多 Agent、安全与拦截开关等  
3. **API 配置套**：把当前 SDK 相关 Key/URL/模型与兼容参数存成 profile，可一键切换  
4. 点 **保存配置** 写回 `.env` 并热应用；或 **打开 .env** 用外部编辑器  

档案实现见 `base/config_profiles.py`（持久化到 `.spore_config_profiles.json`）。

---

## 常见问题

### 如何切换 LLM 提供商？

```env
# OpenAI 官方
LLM_SDK=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o

# DeepSeek（OpenAI 兼容）
LLM_SDK=openai
OPENAI_API_KEY=...
OPENAI_API_URL=https://api.deepseek.com
OPENAI_MODEL=deepseek-chat

# Claude
LLM_SDK=anthropic
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-4-20250514
```

### 如何调整上下文长度？

改 `CONTEXT_MAX_TOKENS`，并保证不超过模型实际窗口。可配合 `savemode` 与 `LIMIT_WRITE_TOOL_RETURN` 控制膨胀。

### 如何关闭安全 Agent / 拦截？

```env
# 完全关闭安全 Agent（不推荐）
SECURITY_AGENT_MODE=off

# 只关闭 shell 命令拦截
COMMAND_INTERCEPT=false

# 或只关单项
INTERCEPT_SHELL_DELETE=false
INTERCEPT_SHELL_WRITE=false
```

也可在桌面菜单切换「拦截开关」，或用 `whitelist add <命令>` 信任特定命令。

### 变量改了不生效？

1. 确认改的是**工作目录**下的 `.env`（打包后为安装目录，不是临时解压目录）  
2. 桌面模式点「应用环境配置」或重启  
3. 检查 `LLM_SDK` 与对应 Key 是否匹配  

### 旧变量对照

| 旧名（勿用） | 现行名 |
|--------------|--------|
| `OPENAI_BASE_URL` | `OPENAI_API_URL` |
| `LLM_API_KEY` / `LLM_API_URL` | `OPENAI_API_KEY`+`OPENAI_API_URL` 或 `ANTHROPIC_API_KEY`+`ANTHROPIC_API_URL` |
| `MODEL_MAIN` | `OPENAI_MODEL` / `ANTHROPIC_MODEL` |
| `MAX_TOKENS_MAIN` | `MAX_OUTPUT_TOKENS` |
| `MAX_CONTEXT_TOKENS` | `CONTEXT_MAX_TOKENS` |
| `BLOCK_SHELL_DELETE` | `COMMAND_INTERCEPT`（仍兼容读取，但请用新名） |
| `DESKTOP_CONFIRM_ENABLED` | （已移除；桌面确认始终可用） |
| `MODEL_SUPERVISOR` | `AGENT_SUPERVISOR_*` 档位配置 |

---

## 相关文档

- [架构设计](ARCHITECTURE.md)
- [CLI 模式](CLI.md)
- [构建指南](BUILD.md)
- [前端使用](FRONTEND.md)
