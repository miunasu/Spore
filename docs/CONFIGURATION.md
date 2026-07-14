# 配置说明（v3.0）

权威配置源为项目根目录 `.env`，由 `base/config.py` 的 `Config` 加载。  
桌面 GUI「设置 → 环境配置」最终也读写同一套变量：页面分为 **基础配置**（最小可用）与 **高级配置**（默认折叠），并支持 **配置档案（profiles）**。

> 变量名以代码为准。旧文档中的 `OPENAI_BASE_URL`、`MODEL_MAIN`、`MAX_CONTEXT_TOKENS`、`MAX_TOKENS_MAIN`、`DESKTOP_CONFIRM_ENABLED` 等 **已不再使用**。

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

### 子 Agent 独立 LLM（可选，空=继承主 Agent）

| 变量 | 说明 |
|------|------|
| `SUB_AGENT_LLM_SDK` | 子 Agent SDK |
| `SUB_AGENT_OPENAI_API_KEY` / `SUB_AGENT_OPENAI_API_URL` / `SUB_AGENT_OPENAI_MODEL` | 子 Agent OpenAI |
| `SUB_AGENT_ANTHROPIC_API_KEY` / `SUB_AGENT_ANTHROPIC_API_URL` / `SUB_AGENT_ANTHROPIC_MODEL` | 子 Agent Anthropic |

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
| `DESKTOP_API_PORT` | `8765` | HTTP 端口；**WebSocket 端口 = HTTP + 1** |

打包运行时还会使用环境变量（由 Tauri / 安装器注入）：

- `SPORE_RESOURCE_DIR`：资源目录（prompt/skills/characters 等）
- `SPORE_DESKTOP_MODE`：桌面静默标识

---

## 上下文模式

| 变量 | 默认 | 说明 |
|------|------|------|
| `CONTEXT_MODE` | `strong_context` | 新会话默认模式 |
| `CONTEXT_MAX_TOKENS` | `128000` | 上下文 token 上限 |
| `CONTEXT_WARNING_THRESHOLD` | `0.8` | 警告阈值（比例） |
| `MAX_SINGLE_MESSAGE_RATIO` | `0.3` | 单条消息相对上限 |

### 模式含义

| 模式 | 行为 |
|------|------|
| `strong_context` | 强关联单 Agent 工具集，**无** `multi_agent_dispatch` |
| `long_context` | 长上下文 / 多 Agent 倾向，**含** `multi_agent_dispatch` |
| `auto` | 每轮可由 ModeSelector 选择 strong 或 long |

运行时可在 CLI `mode ...` 或 GUI 标题栏切换，作用于**当前会话**。

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
| `MULTI_AGENT_MONITOR_ENABLED` | `true` | 是否弹独立监控终端 |
| `MULTI_AGENT_JOIN_INTERVAL` | `2.0` | 等待轮询间隔（秒） |
| `CODER_MAX_ITERATIONS` | `1000` | 历史兼容/Coder 相关上限 |

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

## 命令拦截（安全）

桌面三点菜单「拦截开关」与下列变量对应：

| 变量 | 默认 | 说明 |
|------|------|------|
| `COMMAND_INTERCEPT` | `true`（若未设则兼容旧名 `BLOCK_SHELL_DELETE`） | 总开关 |
| `INTERCEPT_SHELL_DELETE` | 开启 | 拦截 del/rm/Remove-Item 等 |
| `INTERCEPT_SHELL_WRITE` | 开启 | 拦截 Set-Content/Out-File 等（建议用 `file type=write`） |

> 桌面端的文件写删确认由 `confirm_manager` 走 WebSocket，**没有** `DESKTOP_CONFIRM_ENABLED` 开关。

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

目录约定：

- 进程级：`logs/<启动时间>/...`
- 对话级：`logs/<启动时间>/conversations/<conversation_id>/...`（按会话隔离落盘）

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

对话历史固定使用工作目录下 `history/`（含 `history/autosave/`），不由上述变量改名。

---

## 配置方式

### 1. 直接编辑 `.env`

保存后：

- 多数项需重启进程生效  
- 桌面「应用环境配置」会调用运行时热更新（`reload_config` / `apply_runtime_config`）

### 2. GUI 设置（桌面）

路径：**设置 → 环境配置**（`CommandMenu`）。

1. **基础配置（始终展开）**：只填最小可用项即可运行  
   - `LLM_SDK`  
   - OpenAI：`OPENAI_API_KEY` / `OPENAI_API_URL` / `OPENAI_MODEL`  
   - Anthropic：`ANTHROPIC_API_KEY` / `ANTHROPIC_API_URL` / `ANTHROPIC_MODEL`  
2. **高级配置（默认折叠）**：Responses/Thinking、子 Agent、上下文阈值、SDK 兼容、日志、路径、多 Agent、拦截开关等  
3. **API 配置套**：把当前 SDK 相关 Key/URL/模型与兼容参数存成 profile，可一键切换  
4. 点 **保存配置** 写回 `.env` 并热应用；或 **打开 .env** 用外部编辑器  

档案实现见 `base/config_profiles.py`。

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

### 如何关闭 shell 危险命令拦截？

```env
COMMAND_INTERCEPT=false
```

或在桌面菜单切换「拦截开关」。也可只关单项：

```env
INTERCEPT_SHELL_DELETE=false
INTERCEPT_SHELL_WRITE=false
```

### 变量改了不生效？

1. 确认改的是**工作目录**下的 `.env`（打包后为安装目录，不是临时解压目录）  
2. 桌面模式点「应用环境配置」或重启  
3. 检查 `LLM_SDK` 与对应 Key 是否匹配  

### 旧变量对照

| 旧名（勿用） | 现行名 |
|--------------|--------|
| `OPENAI_BASE_URL` | `OPENAI_API_URL` |
| `MODEL_MAIN` | `OPENAI_MODEL` / `ANTHROPIC_MODEL` |
| `MAX_TOKENS_MAIN` | `MAX_OUTPUT_TOKENS` |
| `MAX_CONTEXT_TOKENS` | `CONTEXT_MAX_TOKENS` |
| `DESKTOP_CONFIRM_ENABLED` | （已移除；桌面确认始终可用） |
| `MODEL_SUPERVISOR` | （已无独立监督模型配置） |

---

## 相关文档

- [架构设计](ARCHITECTURE.md)
- [CLI 模式](CLI.md)
- [构建指南](BUILD.md)
- [前端使用](FRONTEND.md)