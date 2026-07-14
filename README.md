<div align="center">
  <img src="desktop_app/frontend/src-tauri/icons/icon_master.png" alt="Spore AI Agent" width="120" height="120">
  
  # Spore AI Agent
  
  **Version 3.0** · 具有现代 GUI、透明可控的 AI Agent | 在主机上完成任何任务
  
  不只是写代码 - 文档处理、逆向分析、网络流量解析、文件管理、系统操作...
  
  实时监控每一步决策和工具调用，随时调整配置。
  
  让 AI 成为你的全能助手，而不仅仅是代码生成器。
  
  **✨ Windows 平台原生支持 | 一键安装部署 | 开箱即用**
  
  ---
  
  📖 [配置说明](docs/CONFIGURATION.md) | 💻 [CLI 模式](docs/CLI.md) | 🔨 [构建指南](docs/BUILD.md) | 🎯 [技能开发](docs/SKILLS.md) | 🏗️ [架构设计](docs/ARCHITECTURE.md) | 📦 [Release](https://github.com/miunasu/Spore/releases)
</div>

---

## 界面预览

<div align="center">
  <img src="img/Spore.png" alt="Spore 界面预览" width="100%">
  <p><i>让你完全掌控整个流程</i></p>
</div>

---

## 为什么选择 Spore？

### 🖥️ 现代化桌面 GUI - 专业的可视化界面

告别命令行黑窗口，Spore 提供完整的桌面应用体验。

**直观易用的图形界面：**

- **多标签页设计**：对话与文件编辑无缝切换，拖拽文件即可打开编辑器
- **实时监控面板**：消息详情展开、TODO 任务栏、确认栏、日志面板一目了然
- **流式显示**：WebSocket 实时推送，Token 计数实时显示
- **一键安装**：Windows 原生安装包，开箱即用

**专业工具的专业界面，让复杂操作变得简单。**

### 🔍 透明可控 - 看得见的 AI

大多数 AI Agent 是黑盒：你不知道它在想什么，不知道它调用了什么工具，出错了也不知道哪里出了问题。

**Spore 让一切透明：**

- **实时监控**：每条消息都可展开查看完整工具调用（文本协议 `ACTION` / `RESULT` / `STOP_REASON`）
- **独立日志**：系统事件和 Agent 行为全部记录，多 Agent 协作时每个子 Agent 可有独立监控窗口
- **危险操作确认**：删除、覆盖文件前可经你确认，并显示详细列表
- **命令拦截**：可拦截高风险 Shell 删除/写入等操作（`COMMAND_INTERCEPT`）
- **随时中断**：Ctrl+C 或停止按钮，可打断当前会话与子 Agent
- **动态调整**：实时切换上下文模式、角色、技能与配置档案

**你不再是旁观者，而是掌控者。**

### 🌟 万能 Agent - 不只是代码助手

大多数 AI 能很好的帮你编写代码，但你的工作远不止于此。

**Spore 是真正的主机级全能助手：**

- **📝 文档处理**：解析和生成 PDF、Word、PowerPoint；可基于模板与原始数据写报告
- **🔍 逆向分析**：结合主机工具链（如 IDA Pro）做二进制分析 [银狐、ShadyPanda 案例](example/MalwareAnalysis/)
- **🌐 网络分析**：PCAP 深度分析 [Remcos、Mirai](example/PcapAnalysis/)
- **📊 数据分析**：收集、处理并生成报告 [2025-2026 全球金融市场综合分析报告](example/MarketReport/)
- **💾 文件操作**：搜索、读写、批量处理本地文件
- **⚙️ 系统管理**：执行 PowerShell、自动化运维
- **💻 代码开发**：编写、调试、重构

[银狐 SilverFox1 案例快速复现指南](docs/SILVERFOX.md)

**从日常办公到专业领域工作，一个 Agent 搞定所有任务。**

---

## 核心特性（3.0）

### 🎯 智能上下文模式

- **强上下文模式 (`strong_context`)**：单 Agent + 完整主机工具集，**不含** `multi_agent_dispatch`；支持单工具 / 顺序 / 并行 ACTION
- **长上下文模式 (`long_context`)**：额外开放 `multi_agent_dispatch`，适合大项目、长文档与可并行拆解任务
- **自动模式 (`auto`)**：由 ModeSelector 按任务选择 strong / long
- 运行时可按**会话**切换，无需重启进程

### 🤖 多 Agent 协作

- 主 Agent 通过 `multi_agent_dispatch` 派发任务
- 子 Agent 类型：Coder / WebInfoCollector / FileContentAnalyzer / TextEditor
- 独立线程执行、独立日志，可选监控终端
- 支持中断、纠正后重派与结果汇总

### 🧩 Claude Skills 扩展系统

- **内置技能包**：`docx` / `pdf` / `pptx` / `pcap-analyst` / `skill-creator`
- **按需加载**：`skill_query` 查询 `SKILL.md`，不把全文塞进 system prompt
- **主机工具**：`file` / `edit` / `Grep` / `execute_command` / `web_browser`
- **易于扩展**：在 `skills/` 添加目录即可（见 [技能开发](docs/SKILLS.md)）

### 🎭 角色系统

- 配置 `DEFAULT_CHARACTER` 后自动注入专业角色
- 预置：恶意代码分析师、Python 专家、数据分析师等（`characters/`）
- CLI：`char list|select|remove`；桌面设置页同样可管理

### 🔧 文本协议交互

- **不依赖** OpenAI Function Calling
- 统一标记：`ACTION_SINGLE` / `ACTION_SEQUENCE` / `ACTION_PARALLEL` / `RESULT` / `STOP_REASON`
- 跨 SDK：OpenAI、Anthropic、DeepSeek 及兼容网关
- 可读性强，便于调试与审计

### 🖥️ 桌面多会话架构

- 每会话独立 `ConversationLoop`
- FastAPI + 独立 WebSocket 推送进程
- 配置档案（profiles）、历史 `history/` 与 autosave

---

## 快速开始

### 1. 下载安装（推荐）

从 [Release 页面](https://github.com/miunasu/Spore/releases) 下载 **3.0** 安装包，一键安装。

### 2. 配置 LLM 参数

启动后打开「设置 → 环境配置」：**基础配置**中填写 SDK 与 API Key / URL / 模型即可使用；高级项默认折叠。也可直接编辑安装目录 / 项目根目录的 `.env`：

```env
LLM_SDK=openai
OPENAI_API_KEY=sk-...
OPENAI_API_URL=https://api.deepseek.com
OPENAI_MODEL=deepseek-chat
LAUNCH_MODE=desktop
CONTEXT_MODE=strong_context
CONTEXT_MAX_TOKENS=128000
MAX_OUTPUT_TOKENS=15000
```

完整变量表见 [配置说明](docs/CONFIGURATION.md)。

### 3. 开始使用

输入任务即可。需要并行拆解时切换到 **long_context** 或 **auto**。

源码运行：

```bash
uv sync
# .env 中 LAUNCH_MODE=desktop 或 cli
uv run python main_entry.py
```

---

## 技术栈

- **后端**：Python 3.10+ · FastAPI · multiprocessing IPC · PyInstaller
- **前端**：React · TypeScript · Vite · Tauri 1.x · Zustand
- **LLM**：OpenAI / Anthropic SDK，兼容第三方 Base URL
- **协议**：Spore 文本协议（`base/text_protocol`）

---

## 系统要求

- Windows 10/11 x64（主要支持平台）
- 源码运行：Python 3.10+

---

## 构建与依赖

### 必需环境（源码 / 打包）

- Python 3.10+
- [uv](https://github.com/astral-sh/uv)
- Node.js 18.x / 20.x LTS
- Rust + Cargo
- Visual Studio Build Tools（含 C++ 工具链）

### 构建

双击 `build_installer.bat` 一键构建。

📖 详情见 [构建指南](docs/BUILD.md)

### 外部工具说明

- `rg.exe`：构建时由脚本下载并校验（SHA256），打包进安装目录
- `NSIS`：Tauri `nsis` 目标生成 setup.exe
- `UPX`：可选，用于压缩后端可执行文件（见 `spore_backend.spec`）

---

### 公众号

![](img/count.jpg)

---

## 许可证

**AGPL-3.0 License (GNU Affero General Public License v3.0)**

本项目采用 GNU Affero 通用公共许可证 v3.0 进行许可。

如需商业使用，请联系 miunasu@foxmail.com

详见 [LICENSE](LICENSE) 文件

---

<div align="center">
  
**Spore AI Agent 3.0** - 透明可控，让你真正掌控 AI 🚀

[GitHub](https://github.com/miunasu/Spore) | [文档](docs/) | [Release](https://github.com/miunasu/Spore/releases)

</div>