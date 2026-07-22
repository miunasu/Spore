# 前端使用指南（v4.0）

> [English](en/FRONTEND.md)

本文介绍 Spore 桌面前端各面板功能。前端技术栈：React + TypeScript + Zustand + Tailwind + Tauri 1.x（无边框窗口 + Mica 效果）。

> 面板大小可拖拽调整；编辑器可用 `Ctrl + S` 保存。

---

## 整体布局

| 区域 | 功能 |
|------|------|
| 标题栏 | 窗口控制、Mini 模式、窗口置顶、语言切换（中/EN）、主题切换 |
| 左栏 | 日志系统（system / general / frontend） |
| 中栏 | 对话标签页、模式、历史、发送/中断、TODO、确认、安全提示 |
| 右栏 | 文件管理、子系统切换、Agent 监控、便签 |

后端：FastAPI（默认 `127.0.0.1:8765`）+ 独立 WebSocket 推送进程（`8766`）。  
每会话有独立 `ConversationLoop` 实例；**任务由后端自驱**——提交后即使切换标签或最小化窗口，任务仍在后台推进，前端只渲染事件流，断线重连后自动恢复状态。

---

## 标题栏

- **Mini 模式**：切换到悬浮小窗（见下文）
- **置顶**：窗口始终置于最前
- **中/EN**：切换界面语言（中文/英文），并同步后端 `SYSTEM_LANGUAGE`（影响命令意图说明、修复建议等辅助输出的语言）
- **主题**：暗色 / 亮色
- 拖拽移动、双击最大化（无边框自定义标题栏）

---

## 左栏 - 日志系统

从上到下可包含：

- **system**：系统 / 校验类报错
- **general**：主 Agent 行动与工具执行摘要（如 `Tool executed successfully`）
- **frontend**：前端自身日志（全局，不按会话隔离）

后端日志（system / general）**按当前对话会话过滤**；WebSocket 用 `conversation_id` 路由。

![左栏概览](../img/Left.png)

### 查看详情

点击日志条目展开查看工具调用错误等 JSON 细节：

![错误详情](../img/ToolError.png)

### 全屏

双击某一日志区域可占满左栏，再次双击恢复：

![全屏显示](../img/LeftFull.png)

---

## 右栏 - 文件与监控

### 切换子系统

拖动滑动条可切换视图：**便签（note）/ 输出（output）/ Agent 监控 / prompt / skills / characters / history**。

![子系统切换](../img/RightSystem.png)

### 文件操作

- 创建文件 / 文件夹、重命名、删除、打开所在位置
- 剪切 / 复制 / 粘贴与 **Windows 资源管理器互通**（原生剪贴板，Tauri 实现）
- 可访问范围为沙箱目录：`output` / `skills` / `prompt` / `history` / `characters` 及根目录 `note.txt`、`.env`（`prompt/skills/characters` 只读）

![文件操作](../img/RightFile.png)

### 打开与编辑

- **双击文本文件**：以标签页形式在中栏编辑
- **双击文件夹**：进入目录
- 可将文件拖入中栏编辑区

### Agent 监控（v4.0）

「agents」页实时显示运行中的子 Agent（最多 5 个面板）：滚动日志、JSON 美化与语法高亮、按 Agent 自动滚动。数据来自 WebSocket `agent_register/output/status` 事件。

### 便签（v4.0）

「note」页编辑根目录 `note.txt`，`Ctrl+S` 保存，带未保存标记。

---

## 中栏 - 对话与操作

### 标题区：模式与会话

- **模式下拉框**：`strong_context` / `long_context` / `auto`（带图标，作用于当前会话）
- **加号**：新建会话（浏览器式标签页，可与文件编辑标签混排）
- **时钟**：历史对话列表（`history/`，支持重命名/删除/加载）
- token 用量统计随对话实时刷新

![模式选择](../img/MiddleMode.png)

![历史对话](../img/MiddleHistory.png)

### 对话区

- 展示用户与 Agent 消息；任务执行中逐轮流式渲染（`round_reply` / 工具调用 / 工具结果）
- 「查看详情」展开底层 ACTION / RESULT 与发送给 LLM 的原始消息
- 命令意图脚注：安全 Agent（full 模式）会为每条 shell 命令生成一句「它想干什么」的说明，附在对应消息下

![对话详情](../img/MiddleConversation.png)

靠近中栏边缘可出现隐藏左右栏按钮：

![隐藏按钮](../img/MiddleHide.png)

拖拽右栏文件到中栏编辑：

![拖拽编辑](../img/MiddleEdit.png)

### TODO 栏（v4.0）

Agent 声明式 TODO 通过 WebSocket 推送，按会话显示可折叠的进度条（`✓/✗/○` + 完成百分比）。

### 发送栏

- **选项菜单（⋮）**：设置、角色、拦截开关、节省模式、备份/回滚等（见下文）
- **发送**：Enter 或按钮（输入法安全，Shift+Enter 换行）
- **中断**：停止当前会话回复及子 Agent（仅任务进行中可用）

![选项菜单](../img/MiddleOption.png)

### Agent 活动栏（v4.0）

发送栏上方的非阻塞状态条，实时显示安全 Agent 动态（内容随安全模式不同）：

- 💡 命令意图说明（`full` 模式）
- 🚨 恶意命令告警（`full` 模式）
- 🛡️ 高危命令风险扫描中（`basic` 模式）
- ⚡ 白名单自动放行（`basic` 模式）

### 确认栏与安全弹窗（v4.0）

- **确认栏（ConfirmBar）**：文件删除/覆盖等阻塞式确认；`basic` 安全模式下高危命令的风险确认也在这里出现（默认 `full` 模式下命令不弹确认，全部走异步研判）。多个请求排队处理
- **安全修复弹窗（SecurityRemediationModal）**：安全 Agent 判定命令**恶意**时会熔断当前会话（自动中断 + 终止子 Agent），弹窗展示判定依据与修复建议，可选择：
  - **手动处理**：把建议记录到会话中自行执行
  - **自动修复**：新开一个会话按 `auto_fix_prompt` 自动执行修复任务

### 节省模式（savemode）

减少 token：压缩多步骤中间过程，更偏向保留用户消息与最终回复。与 CLI 命令 `savemode` 同一概念。

---

## Mini 模式（v4.0）

点击标题栏 Mini 按钮进入悬浮小窗（约 380×520，自动置顶，退出时恢复原窗口几何）：

- 显示最近两条 Agent 回复与实时子 Agent 活动
- 命令意图脚注照常显示
- 输入栏悬停/聚焦时浮现，可直接发送新任务
- 适合把 Spore 挂在屏幕角落当「后台助手」

---

## 设置（选项菜单 ⋮）

### 常规

- 主题（暗色 / 亮色）
- 角色 list / select / remove（与 CLI `char` 同源）
- 启动时自动清理短日志等本地偏好

### 环境配置

读写工作目录下的 `.env`（与 [CONFIGURATION.md](CONFIGURATION.md) 同一套变量），并支持配置档案（profiles）。

| 区域 | 说明 |
|------|------|
| **API 配置套** | 顶部：按当前 SDK 保存 / 应用 / 删除 profiles（`base/config_profiles.py`），可一键切换主 Agent 与子 Agent 的整套 Key/URL/模型 |
| **基础配置** | 始终展开；最小可用列表：`LLM_SDK` + 当前 SDK 的 Key / URL / 模型 |
| **高级配置** | 默认折叠；Responses/Thinking、子 Agent 与辅助 Agent 档位、超时、日志、路径、安全与拦截开关等 |

操作：

- **打开 .env**：用系统关联程序打开文件
- **保存配置**：写回 `.env` 并热应用（`/api/settings/env/apply`：重载配置、重启 Chat 进程；能热更新的项立即生效，否则需重启）

### 工具策略（v4.0）

「工具」页可视化开关每个工具乃至**子工具**（如只允许 `file.read` 禁止 `file.delete`；按类型禁用某些子 Agent）：

- 作用域可选 **当前会话** 或 **全局**（全局持久化到 `tool_policy.json`）
- 被禁用的工具会从系统提示中隐藏，且运行时二次拦截
- 支持一键重置为模式默认

### 备份 / 回滚（v4.0）

两个标签页：

- **检查点**：列出当前会话对话点，一键 `rewind`（文件 + 对话历史 + TODO 同时恢复；任务生成中会拒绝并提示）
- **文件历史**：查看任意被 Agent 修改过的文件的版本列表，恢复到指定版本

### 命令拦截

发送栏选项菜单可快捷切换 `COMMAND_INTERCEPT`（拦截 shell 删除/写文件命令）。

---

## 开发提示

```bash
cd desktop_app/frontend
npm install
npm run dev          # Vite http://localhost:1420
npm run tauri dev    # 带壳调试（自动以 uv 拉起 Python 后端）
```

- 状态管理：`src/stores/*`（chat / editor / agent / todo / confirm / security / log / file / settings / miniMode / drag）
- API 封装：`src/services/api.ts`；WebSocket：`src/services/websocket.ts`（批量事件、30s ping、指数退避重连、重连后快照恢复）
- 国际化：`src/i18n/`（中/英，按组件命名空间组织；`useT()` 响应式取词，语言持久化于 `localStorage`）

更多架构见 [ARCHITECTURE.md](ARCHITECTURE.md)。
