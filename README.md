<div align="center">
  <img src="desktop_app/frontend/src-tauri/icons/icon_master.png" alt="Spore AI Agent" width="120" height="120">

  # Spore AI Agent

  **一个敢把整台电脑交给 AI、又让你随时看得住它的桌面助手**

  不用沙箱、不限目录，Agent 直接在真实系统上帮你干活；

  每一步操作**看得见**、危险动作**拦得住**、改错了随时**退得回**。

  **✨ Windows 原生桌面应用 | 图形界面零命令行 | 一键安装开箱即用**

  ---

  📖 [配置说明](docs/CONFIGURATION.md) | 🖥️ [界面指南](docs/FRONTEND.md) | 💻 [CLI 模式](docs/CLI.md) | 🔨 [构建指南](docs/BUILD.md) | 🎯 [技能开发](docs/SKILLS.md) | 🏗️ [架构设计](docs/ARCHITECTURE.md) | 📦 [Release](https://github.com/miunasu/Spore/releases)
</div>

---

## 界面预览

<div align="center">
  <img src="img/Spore.png" alt="Spore 界面预览" width="100%">
  <p><i>AI 在干活，你在掌控</i></p>
</div>

---

## Spore 是什么？

Spore 是一个安装在你电脑上的通用 AI Agent：写报告、整理文件、分析数据、逆向恶意样本、自动化运维、编写代码——你用一句话描述任务，它调用真实的系统工具替你完成。

和大多数 Agent 产品不同，Spore 不把 AI 关进沙箱或某个工作目录。它可以修改系统配置、安装软件、管理服务——**拥有和你一样的完整权限**。

> 这听起来很危险？这正是 Spore 要解决的问题。

现有 Agent 工具在「安全」上只有两种答案：要么限制能力（锁沙箱、锁目录，很多事干不了），要么事后补救（对话能回退，但删掉的文件、改掉的系统设置救不回来）。

**Spore 的答案是第三种：不限制能力，但让一切透明、可控、可回滚。**

### 🔍 看得见 —— 你始终知道 AI 在干什么

- 每条命令执行时，界面同步显示一句**中文意图说明**：「正在安装 Python 依赖库」——看不懂命令没关系，看得懂它想干嘛
- AI 的多步计划以**任务清单进度条**实时展示，做到哪一步一目了然
- 每条回复都能展开「查看详情」，看到发给模型的原始内容和模型的原始输出；系统日志、子 Agent 日志全部在界面上实时滚动
- 想较真时，一切有据可查：高危操作全部记入审计日志

### 🛡️ 拦得住 —— 危险动作过不了你这关

- 内置 30+ 条高危规则，覆盖系统服务、注册表、防火墙、磁盘格式化、账户管理等 20+ 类敏感操作，命中后交给独立的**安全 Agent** 做 AI 风险研判
- 研判结果是一份**普通人看得懂的中文风险报告**：这条命令要干什么、有什么危害、能不能撤销、怎么撤销——然后由你决定放行还是取消

```
🚨 检测到高风险操作

操作: 禁用 Windows Defender 服务
危害: 系统将失去病毒防护能力，易受恶意软件攻击
可逆: 是（附回滚命令）
建议: 不推荐执行

[我已了解风险，继续]  [取消]
```

- 普通命令也不裸奔：安全 Agent 在旁路实时研判意图，一旦识别出**恶意行为模式**（窃取凭据、下载执行未知载荷、植入后门等），立即熔断整个会话——不用你反应过来再去按停止
- 随时可以喊停：停止按钮一键中断当前任务和所有子 Agent

### ⏪ 退得回 —— 每一次修改都有后悔药

- Spore 自带独立于 Git 的**文件时间机器**：AI 的每次文件写入、编辑、删除都自动备份，被删掉的文件也能精确还原
- 每当一条回复实际改动了文件，自动生成**对话点快照**；点一下「回滚到此」，文件和对话历史一起回到「这条回复之前」
- 备份面板全程可视化：哪个文件被改过、改了几版、每版长什么样，点按钮就能恢复；连「恢复」这个动作本身也可以再撤销

### 🖱️ 用得会 —— 全程图形界面，不需要技术背景

- 从安装到开始使用只需三步：**装上 → 填一个 API Key → 开聊**，全程点按钮、填表单，不碰命令行、不改配置文件
- 近 80 个配置项全部图形化，带中文说明和默认值；基础配置只有 SDK / Key / 模型三四项，高级项默认折叠，保存即热生效、无需重启
- 支持保存多套 API 配置档案，一键切换不同模型服务商
- 危险确认、风险报告、回滚按钮都长在聊天界面里——**会用聊天软件，就会用 Spore**

---

## 它能帮你做什么？

Spore 是主机级全能助手，不只是代码助手：

- **📝 文档办公**：解析和生成 Word / PDF / PPT，基于模板和原始数据写正式报告
- **📊 数据研究**：自主联网调研、整理数据、产出长篇分析（[2025-2026 全球金融市场综合分析报告](example/MarketReport/)）
- **🔍 逆向分析**：配合 IDA Pro 等主机工具链分析恶意样本（[银狐、ShadyPanda 案例](example/MalwareAnalysis/)，附可一键重放的分析过程存档）
- **🌐 流量取证**：PCAP 深度分析，识别 C2 通信、自动生成检测规则（[Mirai、Remcos 案例](example/PcapAnalysis/)）
- **💾 文件整理**：搜索、批量读写、重组本地文件
- **⚙️ 系统管理**：执行 PowerShell、自动化运维——现在有 AI 守卫护航
- **💻 代码开发**：编写、调试、重构，多 Agent 并行拆解大项目

> 实战复现：[银狐 SilverFox 案例快速复现指南](docs/SILVERFOX.md)

---

## 三分钟上手

1. **安装**：从 [Release 页面](https://github.com/miunasu/Spore/releases) 下载安装包，一键安装启动
2. **配置**：点输入框旁的「⋮」菜单 → 设置 → LLM 设置，选择 SDK（OpenAI / Anthropic / 任意兼容网关如 DeepSeek），填入 API Key 与模型名，保存即生效
3. **开聊**：直接输入任务。遇到危险操作界面会弹确认，改错了在「备份回滚」面板一键撤销

源码运行（可选）：

```bash
uv sync
# .env 中设置 LAUNCH_MODE=desktop（或 cli）
uv run python main_entry.py
```

`.env` 最小配置示例：

```env
LLM_SDK=openai
OPENAI_API_KEY=sk-...
OPENAI_API_URL=https://api.deepseek.com
OPENAI_MODEL=deepseek-chat
LAUNCH_MODE=desktop
```

安全守卫（`SECURITY_AGENT_MODE=full`）与备份系统（`BACKUP_ENABLED=true`）默认开启，无需额外配置。完整变量表见 [配置说明](docs/CONFIGURATION.md)。

---

## 与同类工具的差异

| | 能力范围 | 删除的文件 | 回滚粒度 | 系统级操作 |
|---|---|---|---|---|
| Codex | 沙箱/工作目录 | 只能靠 AI 重建 | 依赖 Git 手动回滚 | 无保护 |
| Claude Code | 工作目录为主 | checkpoint 内可恢复 | 只能回到对话点 | 无保护 |
| **Spore** | **整个真实系统** | **精确还原** | **对话点整体回滚 + 单文件单版本精确撤销** | **AI 风险报告 + 确认 + 回滚命令 + 审计日志** |

通用 Agent ≠ Coding Agent：配置文件、数据文件、系统设置都不在 Git 里，「Git 一切」救不了它们——所以 Spore 自带独立于 Git 的备份恢复体系，并为系统级操作提供风险研判。

---

# 功能全景

以下为完整功能说明，供进阶用户与开发者参考。

## 🛡️ 安全体系：双 Agent 架构

独立的 Security Agent 与主 Agent 并行工作，在命令执行前后完成风险研判（`base/security_guard.py` · `AutoAgent/security_agent.py`）。

**两阶段检测，几乎零性能损耗：**

1. **本地关键词预筛（零 LLM 开销）**：30+ 条正则规则覆盖系统服务、注册表 (HKLM)、防火墙/netsh、驱动安装、磁盘格式化/分区、Windows Defender、启动配置 (bcdedit)、卷影副本删除、日志清除、计划任务、执行策略、UAC、账户管理、文件权限 (ACL)、组策略、关键进程终止等约 21 类操作；普通文件读写不触发、不阻塞
2. **AI 深度风险评估**：命中规则的命令交给 Security Agent，返回结构化风险报告——风险等级、通俗中文说明、潜在危害、是否可逆、**一键回滚命令**、处置建议；对混淆/Base64 编码的命令直接判高危

**两个独立开关：**

| `SECURITY_AGENT_MODE`（能力档位，默认 `full`） | 行为 |
|---|---|
| `off` | 完全关闭 |
| `basic` | 高危命令 AI 风险评估 + 确认 |
| `full` | basic + 普通命令异步意图解析与恶意研判，恶意即熔断会话 |

| `SECURITY_GUARD_MODE`（风险容忍度，默认 `balanced`） | 行为 |
|---|---|
| `strict` | 命中高危规则一律确认 |
| `balanced` | 低风险自动放行，中/高风险确认 |
| `permissive` | 低+中风险自动放行，高风险确认 |

**配套机制：**

- **白名单**：信任的操作加入 `security_whitelist.json`（精确命令 + 正则），不再拦截；CLI/界面均可管理
- **评估缓存**：命令规范化后复用评估结果（路径、名称等参数替换为占位符），同类命令只调用一次 LLM；风险相关参数值（如 `-StartupType`）刻意保留，避免误复用
- **审计日志**：所有确认、放行、拦截、恶意判定记入 `.spore/security_audit.jsonl`，含回滚命令，可追溯
- **会话熔断**：判定恶意后立即取消在途 LLM 请求、终止所有子 Agent、通知前端；带中断世代（epoch）竞态守护，不会误杀你手动开启的新任务
- **块级批量研判**：一个 ACTION 块内的多条命令合并为一次 LLM 调用，加并发限流，成本可控
- **独立基座**：Security Agent 可单独指定便宜快速的模型（如 gpt-4o-mini / DeepSeek），几秒出结果，不占主 Agent 的智力预算

**命令拦截（与 AI 守卫互补的硬规则）**：shell 直删/直写文件的命令（`rm` / `del` / `Out-File` 等）默认被直接拦下，强制 Agent 走带备份与确认的专用文件工具通道（`COMMAND_INTERCEPT`，界面可一键开关）。

## ⏪ 备份恢复：独立于 Git 的时间机器

**文件级回滚（细粒度）** —— `base/backup_manager.py`：

- Hook 所有文件写入/编辑/删除，前后 SHA256 对比，**内容真正变化才备份**
- 内容寻址存储自动去重；增量版本用 **bsdiff4 二进制 diff**，大文件也只存差量
- 每 20 个版本自动存一次完整快照锚点，限制补丁链长度，恢复始终快速可靠
- 删除目录会展开为文件清单逐个备份（上限可配），删了整个目录也能精确还原
- 恢复操作本身也记录为新版本——**撤销可以被撤销**

**对话点回滚（粗粒度）：**

- 某轮回复实际改动了文件才创建 checkpoint，无改动不产生冗余快照
- `rewind` 同时回滚文件 + 对话历史 + 任务清单，回到「这条回复之前」
- **会话隔离**：只回滚本会话改动的文件，其它会话的修改不受波及

桌面端提供可视化「备份回滚」面板（对话点列表带回复摘要 / 文件版本历史可逐版查看恢复）；CLI 提供对应命令：

```
rollback <文件> [--to 版本号 | --steps N]   # 文件级回滚，版本 0 = 最初状态
filehistory [<文件>]                        # 查看文件备份历史 / 所有被跟踪文件
checkpoints                                 # 列出对话点快照
rewind [<checkpoint_id> | --turns N]        # 回到某条回复之前（文件+对话同步回滚）
whitelist [list | add <命令>]               # 安全守卫白名单管理
```

## 🖥️ 桌面体验

**三栏布局**：左栏三格实时日志（系统/通用/前端，双击全屏）· 中栏浏览器式多标签（聊天 + 文件编辑混排）· 右栏七个面板（便签 / 产出文件 / Agent 监控 / 提示词 / 技能 / 角色 / 历史）。可拖拽调宽、一键隐藏、暗/亮主题。

**透明度落地在每个细节：**

- 消息脚注常驻显示每条命令的 💡 中文意图，恶意判定整块标红 🚨
- **活动栏（非阻塞）**：实时展示意图解析、风险扫描中 🛡️、自动放行 ⚡、恶意告警，与确认栏互补
- **确认队列（阻塞）**：多条高危命令并发时按序排队逐个确认，互不覆盖、精确超时，显示「还有 N 个待确认」
- 任务清单进度条、token 用量统计、每条回复可展开原始 LLM 请求/响应

**🪟 Mini 悬浮模式**：一键缩成 380×520 置顶迷你窗（类音乐播放器 mini 模式），只保留最近回复与 Agent 实时活动，意图脚注常驻；鼠标靠近底部或出现高危确认时输入栏自动浮现；退出时还原窗口原尺寸、位置与置顶状态——挂在桌角看着 Agent 干活。

**多会话**：浏览器式标签页多开会话，每会话独立对话循环、独立日志、独立任务；断线重连自动恢复进行中任务的状态。

**记忆系统**：会话实时自动保存（保留最近 10 个，断电重开接着聊）；重要对话可手动存档、重命名、随时加载重放（示例中的银狐分析 `.mem` 就能直接重放全过程）；**节省模式**自动丢弃中间工具调用只留干净问答，长任务省 token；上下文接近上限时自动总结压缩，用户无感。

**工具策略**：每个工具及子能力（文件读/写/删、编辑、搜索、命令执行、网页、子 Agent 派发）都有图形化开关，作用域可选「仅当前会话 / 全局」；关闭的工具直接从系统提示词移除，模型根本看不到。

## 🧬 Agent 架构

**智能上下文模式**（会话内实时切换）：

- `strong_context`：单 Agent + 完整主机工具集，适合上下文强关联的精确任务
- `long_context`：额外开放 `multi_agent_dispatch`，适合大项目、长文档与可并行拆解任务
- `auto`：由 ModeSelector 按任务自动选择

**多 Agent 协作**：主 Agent 派发任务给四类子 Agent（Coder / WebInfoCollector / FileContentAnalyzer / TextEditor），独立线程、独立日志、界面实时监控，支持中断与结果汇总。

**颗粒化基座配置**：主 Agent、子 Agent、监督 Agent、模式选择、安全 Agent 可各自独立配置 SDK / Key / URL / 模型 / 推理参数：

- 字段级回退链：`AGENT_<PROFILE>_*` → `SUB_AGENT_*` → 主 Agent 配置，不配就继承
- effort 等参数支持 `none`/`off` 显式关闭：主 Agent 开推理、安全 Agent 关推理，互不干扰
- 客户端按 `(sdk, key, url)` 懒加载缓存，多基座不多开销
- 典型玩法：主 Agent 用旗舰模型干活，安全守卫用中档模型盯梢——省钱又提质

**文本协议**：不依赖 Function Calling，统一 `@SPORE:` 标记（`ACTION_SINGLE` / `ACTION_SEQUENCE` / `ACTION_PARALLEL` / `RESULT` / `STOP_REASON`），跨 OpenAI / Anthropic / 兼容网关通用，可读性强、便于审计，对模型输出的转义/引号问题自动容错重试。

**技能与角色**：内置 `docx` / `pdf` / `pptx` / `pcap-analyst` / `skill-creator` 技能包，按需加载不占系统提示词；预置恶意代码分析师、Python 专家、数据分析师等角色，界面下拉即换。在 `skills/` 加目录即可扩展（见 [技能开发](docs/SKILLS.md)）。

## 📡 无头调用：把 Spore 当自动化引擎

桌面后端本身就是一个完整的本地 HTTP + WebSocket 服务（默认 `127.0.0.1:8765` / `8766`），**不启动 GUI 也能直接调用**，将 Spore 嵌入你自己的系统：

- `POST /api/chat/send` 单轮对话；`POST /api/task/submit` 提交自驱任务（后端自主循环执行到完成，带总超时看门狗），WebSocket 推送结构化事件流（回复 / 工具调用 / 任务进度）
- **会话隔离的并发调用**：每个请求带 `conversation_id`，各会话独立对话循环与执行锁，天然支持多任务并行互不串扰
- 会话管理（创建/切换/删除）、历史读取、备份回滚、配置热更新均有对应 REST API
- 三进程架构：FastAPI 主进程 / 独立 LLM 通信进程（IPC + 线程池并发）/ WebSocket 推送进程，LLM 等待不阻塞服务

---

## 技术栈

- **后端**：Python 3.10+ · FastAPI · multiprocessing IPC · PyInstaller
- **前端**：React · TypeScript · Vite · Tauri 1.x · Zustand
- **LLM**：OpenAI / Anthropic SDK，兼容第三方 Base URL；按 Agent 颗粒化配置基座
- **协议**：Spore 文本协议（`base/text_protocol`）
- **备份**：内容寻址存储 + bsdiff4 二进制增量（`base/backup_manager.py`）
- **安全**：双阶段守卫 + 独立 Security Agent（`base/security_guard.py` · `AutoAgent/security_agent.py`）

## 系统要求

- Windows 10/11 x64（主要支持平台）
- 源码运行：Python 3.10+

## 构建

必需环境：Python 3.10+ · [uv](https://github.com/astral-sh/uv) · Node.js 18/20 LTS · Rust + Cargo · Visual Studio Build Tools（含 C++ 工具链）。

双击 `build_installer.bat` 一键构建。`rg.exe` 由脚本下载并做 SHA256 校验；NSIS 生成安装包；UPX 可选压缩。详见 [构建指南](docs/BUILD.md)。

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

**Spore AI Agent 4.0** —— 给 Agent 完整的自主权，让用户始终掌控一切 🚀

[GitHub](https://github.com/miunasu/Spore) | [文档](docs/) | [Release](https://github.com/miunasu/Spore/releases)

</div>
