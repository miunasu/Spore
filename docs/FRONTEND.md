# 前端使用指南（v3.0）

本文介绍 Spore 桌面前端各面板功能。前端技术栈：React + TypeScript + Zustand + Tauri 1.x。

> 面板大小可拖拽调整；编辑器可用 `Ctrl + S` 保存。

---

## 整体布局

| 区域 | 功能 |
|------|------|
| 左栏 | 日志系统（错误 / 主 Agent / 前端等） |
| 中栏 | 对话、模式、历史、发送/中断、TODO、确认 |
| 右栏 | 文件管理、子系统切换、编辑入口 |
| 标题栏 | 窗口控制（无边框自定义标题栏） |

后端：FastAPI（默认 `127.0.0.1:8765`）+ WebSocket 推送进程（端口 +1）。  
每会话有独立 `ConversationLoop` 实例，支持并行任务隔离。

---

## 左栏 - 日志系统

从上到下可包含：

- **system**：系统 / 校验类报错
- **general**：主 Agent 行动与工具执行摘要（如 `Tool executed successfully`）
- **frontend**：前端自身日志（全局，不按会话隔离）

后端日志（system / general）**按当前对话会话过滤**；WebSocket 用 `conversation_id` 路由，**日志正文不再嵌入 `session_id`**（会话目录落盘仍用 `logs/.../conversations/<id>/`）。

![左栏概览](../img/Left.png)

### 查看详情

点击日志条目展开查看工具调用错误等 JSON 细节：

![错误详情](../img/ToolError.png)

### 全屏

双击某一日志区域可占满左栏，再次双击恢复：

![全屏显示](../img/LeftFull.png)

---

## 右栏 - 文件管理

### 切换子系统

拖动滑动条可切换查看不同子系统视图：

![子系统切换](../img/RightSystem.png)

### 文件操作

- 创建文件 / 文件夹  
- 重命名  
- 删除  
- 打开所在位置（若后端支持）

![文件操作](../img/RightFile.png)

### 打开与编辑

- **双击文本文件**：中栏或侧栏编辑  
- **双击文件夹**：进入目录  
- 可将文件拖入中栏编辑区  

---

## 中栏 - 对话与操作

### 标题区：模式与会话

- 选择上下文模式：`strong_context` / `long_context` / `auto`  
- 加号：新建会话  
- 时钟：历史对话列表（`history/`，含重命名/删除等 API）

![模式选择](../img/MiddleMode.png)

![历史对话](../img/MiddleHistory.png)

### 对话区

- 展示用户与 Agent 消息  
- 「查看详情」展开底层 ACTION / RESULT 等信息  

![对话详情](../img/MiddleConversation.png)

靠近中栏边缘可出现隐藏左右栏按钮：

![隐藏按钮](../img/MiddleHide.png)

拖拽右栏文件到中栏编辑：

![拖拽编辑](../img/MiddleEdit.png)

### 发送栏

- **选项菜单**：配置、角色、拦截开关、节省模式等  
- **发送**：Enter 或按钮  
- **中断**：停止当前会话回复及子 Agent（仅任务进行中可用）

![选项菜单](../img/MiddleOption.png)

### 节省模式（savemode）

减少 token：压缩多步骤中间过程，更偏向保留用户消息与最终回复。  
与 CLI 命令 `savemode` 同一概念。详见 [配置说明](CONFIGURATION.md) 与 [CLI](CLI.md)。

### TODO 栏与确认栏

- Agent 声明式 TODO 通过 WebSocket 推送到 `TodoBar`  
- 文件写删等危险操作弹出 `ConfirmBar`，需用户确认  

---

## 设置

打开中栏选项菜单中的「设置」，含两个标签：

### 常规

- 主题（暗色 / 亮色）
- 角色 list / select / remove（与 CLI `char` 同源）
- 启动时自动清理短日志等本地偏好

### 环境配置

读写工作目录下的 `.env`（与 [CONFIGURATION.md](CONFIGURATION.md) 同一套变量），并支持配置档案（profiles）。

布局：

| 区域 | 说明 |
|------|------|
| **API 配置套** | 顶部：按当前 SDK 保存 / 应用 / 删除 profiles（`base/config_profiles.py`） |
| **基础配置** | 始终展开；**最小可用**列表：`LLM_SDK` + 当前 SDK 的 Key / URL / 模型（OpenAI 与 Anthropic 按所选 SDK 灰显另一侧） |
| **高级配置** | **默认折叠**；兼容参数、Thinking/Reasoning、子 Agent、超时、日志、路径、拦截开关等 |

操作：

- **打开 .env**：用系统关联程序打开文件
- **保存配置**：写回 `.env` 并调用后端 `applyEnvFile` 热应用（能热更新的项立即生效，否则需重启）

命令拦截也可在发送栏选项菜单中快捷切换（`COMMAND_INTERCEPT`）。

---

## 开发提示

```bash
cd desktop_app/frontend
npm install
npm run dev          # Vite http://localhost:1420
npm run tauri dev    # 带壳调试
```

状态管理主要在 `src/stores/*`（chat / log / todo / confirm / file / settings…），  
API 封装：`src/services/api.ts`，WebSocket：`src/services/websocket.ts`。

更多架构见 [ARCHITECTURE.md](ARCHITECTURE.md)。