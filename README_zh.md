<div align="center">
  <img src="desktop_app/frontend/src-tauri/icons/icon_master.png" alt="Spore AI Agent" width="120" height="120">

# Spore AI Agent

### 让 AI 在你真实的 Windows 电脑上干活 —— 而你始终看得见、喊得停、退得回

**主机级通用 Agent · 零门槛桌面 GUI · 不锁模型 · 安全护栏 · 文件时间机器 · 开源可审计**

[下载 Release](https://github.com/miunasu/Spore/releases) · [English README](README.md) · [配置说明](docs/CONFIGURATION.md) · [界面指南](docs/FRONTEND.md) · [CLI 模式](docs/CLI.md) · [架构设计](docs/ARCHITECTURE.md) · [构建指南](docs/BUILD.md)

</div>

---

<div align="center">
  <img src="img/Spore.png" alt="Spore 界面预览" width="100%">
</div>

---

# 一、为什么是 Spore

## 把真实电脑交给 AI，是可怕的 —— 除非它看得见、喊得停、退得回

今天的 AI Agent 越来越聪明，但大多数都被关在笼子里：写代码的 Agent 出不了工作区，云端 Agent 碰不到你本地的文件和软件，几乎所有工具都用"沙箱"来换取安全。它们不是不能做，是**不敢让你做真正的活**。

Spore 走的是另一条路：**它运行在你本机，能接触真实的文件、真实的命令、真实的系统工具**——但它不靠"不让碰"来保证安全，而是给真实的主机能力配上一整套控制体系。

> 别的 Agent 用沙箱保护你，代价是干不了真活。
> Spore 用护栏保护你，所以敢让 AI 上真机。

这套护栏就是产品副标题里那三个词：

| | 能力 | 你得到什么 |
|---|---|---|
| 👁️ **看得见** | 中文命令意图、TODO 进度、子 Agent 监控、可展开的模型原始上下文 | 即使不懂命令行，也知道 AI 正在做什么、有没有走偏 |
| ✋ **喊得停** | 一键停止、高危操作确认、恶意行为自动熔断 | 任何时刻都能叫停；危险的事需要你点头；恶意的事会被自动切断 |
| ⏪ **退得回** | 独立于 Git 的文件版本历史、对话点回滚（rewind） | 改错删错都能恢复，连"恢复"本身都能再撤销 |

## 不只面向代码：主机级通用 Agent

Spore 是**主机级通用 Agent**，不只面向代码。这正是它和 Cursor、Claude Code、Codex 这类工具最根本的区别 —— 它接管的是你整台电脑上的活，而不只是一个代码项目。

| 场景 | 典型工作 |
|---|---|
| 💻 代码开发 | 编写、调试、重构、定位问题、并发拆分项目任务 |
| 📝 文档办公 | 读取与生成 Word / PDF / PPT，结合数据产出报告 |
| 📊 数据研究 | 联网调研、整理资料、生成分析报告 |
| 💾 文件整理 | 搜索、读取、批量编辑、归档本地文件（"把下载文件夹按项目归档"） |
| ⚙️ 系统管理 | 执行 PowerShell、安装依赖、检查服务和配置 |
| 🔍 安全分析 | 配合本机工具链做恶意样本、流量与取证分析 |
| 🌐 流量取证 | 分析 PCAP、识别 C2 通信、生成检测线索 |

仓库里附带了几组**真实任务复现**，不是玩具 Demo：

- `example/MalwareAnalysis/` —— 银狐 SilverFox 等样本分析（[快速复现指南](docs/SILVERFOX.md)）
- `example/PcapAnalysis/` —— Mirai、Remcos 流量取证
- `example/MarketReport/` —— 2025–2026 全球金融市场综合分析报告

## 完整能力，装在一个符合直觉的界面里

Spore 不只提供**主机上完整的 Agent 能力**，还配了一套**符合直觉的前端交互**：浏览器式标签页、三栏可视化面板（日志 / 对话 / 文件）、图形化设置，把命令行翻译成人话。想快速上手，装好填个 Key 就能开工；想极客式深度定制，工具策略、配置档案、各 Agent 独立模型、`.env` 高级参数全都开放。友好的前端交互和可视化把使用门槛降到最低——不懂技术、不碰终端，也能让 AI 在自己的电脑上真正干活。

## 未来的方向：更开放的行动范围 + 更严密的安全闸门

我们相信，今天 LLM 的能力其实被普遍**低估和限制**了。主流工具的安全策略几乎都是同一套：**沙箱圈定范围 + 命令逐条审批**。这套组合看似双保险，实际上两头都不成立：

- **审批是两难的**：开自动放行，审批就形同虚设，安全只剩沙箱兜底；不开自动，普通用户就得面对大量根本看不懂的命令弹窗和无意义审批——最终要么被打扰到烦，要么被训练成无脑点允许；
- **沙箱是漏的**：它限制了 Agent 的能力，用户要真干活就得不断手动扩大工作区；而 LLM 也完全可能借助其他手段绕出沙箱。结果是**安全没有真正保证，能力和体验的代价却实打实付出了**。

未来的 Agent 不该是这样。趋势应当是**放开行动范围，把安全做成智能的闸门**，而不是把 Agent 圈起来、拿弹窗轰炸用户：

- **无害的操作，静默放行**——用户只需要看得见它在做什么，而不是替它按每一次回车；
- **真正可疑的操作，才请用户拍板**——确认应该稀少而有分量，出现即值得认真看一眼；
- **真正恶意的行为，不问、直接熔断**——自动切断执行、给出判定依据，并提供一键自动修复的选项。

这正是 Spore 默认模式在做的事：安全 Agent 异步研判**每条命令**的意图与恶意迹象（不阻塞执行、没有确认弹窗），判定恶意立即熔断并生成修复方案；偏好事前把关的用户，也可以切换到 `basic` 模式，只有命中高危规则的命令才需要确认。**把信任建立在裁决能力上，而不是建立在"圈起来 + 问不停"上**——这是我们对 Agent 未来形态的回答。

---

# 二、产品亮点

## 🚀 能碰真实系统，而不只是一个工作区

大多数 Agent 工具默认被限制在项目目录或沙箱里，让它去动 `C:\Users\你\Downloads`、改系统服务、装个驱动，要么做不到，要么要反复审批。Spore 从设计之初就面向**整台 Windows 电脑**：PowerShell、注册表、系统服务、本机专业工具链，它都能调用。真实的系统能力，是它一切价值的起点。

## 🛡️ 敢放手，是因为兜得住

主机能力如果没有兜底，就是危险品。Spore 的安全体系按模式分工，兼顾"不打扰"与"能把关"：

- **默认（`full` 模式）—— 异步研判与熔断**：不做关键词预筛、没有确认弹窗，安全 Agent 在后台旁路研判**每条命令**的意图与恶意迹象，并用**普通人能看懂的语言**实时标注"它想干什么"，全程不打断执行。一旦确认恶意，Spore 会**熔断当前会话、取消在途请求、终止后台子 Agent**。
- **出事后 —— 不只说"已中断"**：熔断后还会给出影响说明、人工排查步骤，甚至可以**一键新建会话，让 Spore 自己去帮你善后修复**。
- **需要事前把关？切 `basic` 模式**：命中系统级高危规则（服务、注册表、Defender、磁盘、卷影、计划任务、UAC 等）的命令，先由安全 Agent 说明：这是要干什么、风险多大、是否可逆、怎么回滚，再由你决定继续或取消；低风险自动放行，确认粒度由 `strict / balanced / permissive` 控制。

> 我们对安全边界保持诚实：默认的旁路研判不是操作系统级沙箱，个别命令可能在被判定恶意前已经执行。需要严格事前审批时，请使用 `basic` 模式 + 高危确认。这种诚实，正是这个品类最需要的信任基础。

## 🖱️ 一个普通人打开就会用的桌面软件

大多数 Agent 是给会敲命令行的人准备的。Spore 反过来：它首先是一个**符合直觉的 Windows 桌面应用**，会用浏览器、会用文件管理器，就会用它。你不需要懂 Agent、不需要碰终端、不需要改配置文件。

- **浏览器式多标签页**：像开网页一样管理多个对话和打开的文件，标签能重命名、能关闭 —— 一个人人都懂的心智模型，零学习成本。
- **三栏可拖拽布局**：左边看日志、中间对话、右边管文件，左右栏能隐藏、能调宽，布局还会自动记住。像 IDE 一样强，又比 IDE 简单。
- **技术翻译成人话**：不给你看一串 PowerShell，给你看"正在安装依赖""正在修改配置""正在查询文件"。看不懂命令，也看得懂它在干什么。
- **和 Windows 原生打通**：在 Windows 资源管理器中复制文件后，可以直接粘贴到聊天输入框；它们会成为可在发送前删去、按路径去重的路径附件，Spore 引用的是文件路径，而不是把文件内容复制进输入框。右侧文件管理器也支持拖拽文件进来编辑。
- **所有设置图形化**：选 SDK、填 Key、配模型、调工具权限，全在界面里点，不用手写任何配置。
- **现代原生观感**：自定义标题栏、无边框窗口、亚克力半透明效果，视觉上就是一个当代 Windows 应用。

**一句话：把"AI Agent"这种极客概念，做成了你妈也能打开来用的软件。**

## ⏪ 真实文件也有"后悔药"（独立于 Git）

Git 只保护代码仓库，救不了系统配置、数据文件、误删目录和没被 Git 管理的内容。Spore 内置一套独立的备份恢复体系：

- 文件写入 / 编辑 / 删除，只在内容**真正变化**时记录版本（内容寻址 + 二进制增量，成本很低），每个会话各自维护版本链与 metadata；
- 删错的文件能从历史恢复，改错的能回退到任意版本；
- `user_message` 与 `action` 是两类 checkpoint；`rewind` 可以**同时回退文件、对话历史和 TODO**，把整个"这一步做错了"一次性撤销；
- 连"恢复"这个动作本身也会形成新版本 —— 所以恢复还能再撤销。

备份版本链和 metadata 按会话管理，但底层物理文件系统仍由所有会话共享。它能避免不同会话混用恢复记录，不等于会话之间具备完整的文件系统隔离。

## 🧠 不锁模型、不锁厂商

Spore 同时支持 **OpenAI SDK** 与 **Anthropic SDK**，并允许自定义 API URL 和模型名。这意味着：

- 官方 OpenAI / Anthropic；
- 任何 OpenAI 兼容服务与网关，例如 **DeepSeek** 及各类中转；
- 主 Agent、子 Agent、安全 Agent、监督 Agent、模式选择 Agent **各配各的模型**。

一个典型省钱组合：主 Agent 用能力最强的模型，安全 Agent 用又快又便宜的模型做旁路研判。你不会被任何一家模型厂商绑架。

## 🪟 挂在桌角看它干活：Mini 悬浮小窗

一键切换成 **380 × 520 的置顶 Mini 悬浮窗**，像迷你音乐播放器一样常驻桌角，不挡你正在用的 IDE、浏览器或文档。紧凑的信息流准确保留最近回复、命令意图脚注、Agent cards、高危确认和底部输入。退出 Mini 模式后，窗口恢复原来的大小、位置和置顶状态。

在 Windows 上，Mini 支持四边原生吸附：窗口进入工作区边缘 40 px 内即吸附隐藏，只留 8 px 可见；边缘 12 px 热区可将它唤回，鼠标离开后 650 ms 再次隐藏。标题栏中的吸附开关每次启动默认开启，但不会持久化。非 Windows 平台没有这项原生吸附功能。

**这就是产品理念的一镜到底：** 你在主屏写文档，副屏角落 Spore 在整理文件；弹出一个确认，你点一下，它继续。

## ⚙️ 任务后台自驱，不用守着聊天框

提交任务后，后端在专用线程里持续推进 Agent 的多轮工具调用，前端是一个实时控制台而非"点一下等一下"的阻塞界面。于是你可以：

- 切到别的对话、查看文件、调整设置，都不影响正在跑的任务；
- 多个标签页管理不同会话；
- 随时停止当前主任务；
- **页面刷新或断线重连后，恢复本进程中仍在运行的任务状态**。

## 🧬 子 Agent 后台协作，结果自己回来

大任务不该让主 Agent 原地干等。`multi_agent_dispatch` 会把独立子任务交给 Coder、WebInfoCollector、FileContentAnalyzer、TextEditor 等子 Agent 并发处理。桌面模式下，主 Agent 派发后**立即结束当前回合、界面解锁**，你可以继续对话；子 Agent 在后台完成时，系统会自动把结果摘要送回主 Agent，让它继续行动。派发多个任务，不再等于把聊天界面卡死到最慢那个任务完成。

## 🔓 开源可审计 —— 一个要碰你整台电脑的 AI，代码是公开的

Spore 采用 **AGPL-3.0** 开源。对于一个能接触真实主机的 Agent 来说，"代码可审计"比任何安全承诺都更有说服力 —— 这是闭源竞品给不出的信任。

## 🧩 不只是聊天，也是本地自动化引擎

桌面后端同时提供本地 HTTP 与 WebSocket 服务。即使不用 GUI，你也可以把它接入自己的系统：提交任务、读取历史、管理会话、接收结构化事件、调用回滚。REST 默认监听 `127.0.0.1:8765`，可通过 `DESKTOP_API_PORT` 修改；前端 WebSocket 客户端当前固定连接 `127.0.0.1:8766`。它适合作为本地自动化编排层、内网 Agent 服务或桌面工作流后端。

## 🧠 用得久也不会"忘事"、不会"串台"

- 上下文接近阈值时自动压缩，长对话不崩；
- 短记忆自动保存，应用重开能接着聊；
- Learning episodic memory 会在请求前补充最多 3 条相关历史，并记录成功任务；embedding 不可用时会降级，不阻塞任务；
- 会话运行时各自拥有独立的对话循环、日志、任务身份和执行锁；备份 metadata 也按会话管理，但底层物理文件系统仍然共享；
- Stop 一下就真的停、刷新一下任务还在 —— 这些"理所当然"的体验，背后是一整套并发与中断的工程保障。

---

# 三、三分钟上手

1. 从 [Release 页面](https://github.com/miunasu/Spore/releases) 下载并安装；
2. 点击输入框旁的菜单进入设置；
3. 选择 SDK、填写 API Key、模型名和可选 API URL；
4. 直接用中文描述你要做的事。

最小 `.env` 示例（以 DeepSeek 为例）：

```env
LLM_SDK=openai
OPENAI_API_KEY=sk-...
OPENAI_API_URL=https://api.deepseek.com
OPENAI_MODEL=deepseek-chat
LAUNCH_MODE=desktop
```

源码运行：

```bash
uv sync
uv run python main_entry.py
```

完整环境变量见 [配置说明](docs/CONFIGURATION.md)。

> 💡 关于模型选择：Spore 用一套可读的文本协议驱动工具调用，对模型的**指令遵循能力**有一定要求。主 Agent 建议使用能力较强的模型；安全 / 监督 / 模式选择这类辅助 Agent 可以用更快更便宜的模型。

---

# 四、技术说明

以下内容面向需要部署、集成、扩展或审阅实现的用户。

## 1. 总体架构

Spore 采用"桌面控制台 + 本地服务 + 独立推理通信 + WebSocket 推送"的架构：

```text
┌───────────────────────────────────────────────────────┐
│ Tauri + React Desktop UI                               │
│ 聊天 / Mini 窗口 / 日志 / TODO / Agent / 回滚 / 设置     │
└───────────────────────┬───────────────────────────────┘
                        │ HTTP + WebSocket
┌───────────────────────▼───────────────────────────────┐
│ FastAPI Backend                                        │
│ 会话管理 · 任务状态机 · 路由 · 安全确认 · 通知调度       │
└───────────────┬───────────────────────┬───────────────┘
                │ IPC                   │ multiprocessing queue
┌───────────────▼───────────────┐ ┌─────▼────────────────┐
│ 独立 Chat / LLM 通信进程        │ │ 独立 WebSocket 推送进程│
│ 请求隔离 · 并发通信 · 精确取消  │ │ 批量广播 · 前端事件流  │
└───────────────────────────────┘ └──────────────────────┘
```

核心设计原则：

- **循环所有权归后端**：前端提交任务后，由后端驱动 Agent 多轮执行；
- **会话绑定上下文**：日志、TODO、确认、子 Agent 和事件都带会话身份；
- **任务身份隔离**：`task_id`、`submission_id`、`interrupt_epoch` 三重身份防止旧响应覆盖新任务；
- **推理通信解耦**：LLM 请求不阻塞 API 主服务与 WebSocket 推送；
- **base 层不直接依赖桌面 UI**：Desktop 专属能力通过 hook 注入，CLI 继续使用同步行为。

主要实现位置：

- `desktop_app/backend/routes/task.py`：后端自驱任务状态机；
- `desktop_app/backend/routes/chat.py`：单轮会话执行与中断；
- `base/conversation_loop.py`：主 Agent 工具循环；
- `base/ipc_manager.py`：LLM 通信 IPC；
- `desktop_app/backend/websocket/`：独立 WebSocket 推送；
- `desktop_app/backend/core.py`：桌面后端初始化与生命周期。

## 2. 会话与任务状态机

每个会话有独立的 `ConversationState` 与 `ConversationLoop`。任务注册表维护 `running / succeeded / failed / timeout / interrupted` 五种状态。同一会话同一时刻只允许一个主 Agent 任务拥有可见结果权。任务中断时会：

1. 增加 `interrupt_epoch`，让旧 generation 失效；
2. 退役当前 active task；
3. 取消对应的在途 LLM 请求；
4. 丢弃迟到的工具 / 回复事件。

普通 Stop 不会终止已异步派发的后台子 Agent；安全熔断、会话重置、会话删除和后端 shutdown 则会同时作废通知并终止对应子 Agent。

## 3. 异步多 Agent 派发

`multi_agent_dispatch` 底层为每个子 Agent 分配独立的对话历史、工具可见集合、日志文件、监控终端与终止事件。Desktop 模式通过 `agent_notification.py` 将派发改造为异步生命周期：

```text
主 Agent 调用 multi_agent_dispatch
  └─ 预登记 dispatch + generation/epoch fence
      └─ 原子启动子 Agent 线程
          └─ 工具立即返回 dispatch_mode=async
              └─ 主任务自动结束，UI 解锁

子 Agent 终态回调
  └─ 更新全局进度并写入 pending 通知
      ├─ 主会话忙：继续挂起
      └─ 主会话空闲：合并通知并启动 agent_notification 任务
          └─ 主 Agent 获得结果摘要，选择继续等待或继续行动
```

通知调度还包含：dispatch 启动与会话清理互斥、delivery generation guard、多 dispatch 全局进度快照、完成回调去重、watchdog 超时终态兜底、Stop 后短暂延迟的 idle flush、以及禁止通知任务再派发子 Agent（防递归派发链）。CLI 未注册 Desktop 异步 hook，因此仍保留同步等待所有子 Agent 完成的行为。

## 4. 工具系统与文本协议

Spore 不依赖供应商 Function Calling，而使用可读、可审计的文本协议：

```text
@SPORE:ACTION_SINGLE_START
file type=read file_path="C:/workspace/README.md"
@SPORE:ACTION_SINGLE_END

@SPORE:STOP_REASON=任务完成
```

支持 `ACTION_SINGLE`（单工具）、`ACTION_SEQUENCE`（顺序执行）、`ACTION_PARALLEL`（并行执行）、`RESULT`（工具结果回注）、`STOP_REASON`（明确结束回合）。协议位于 `base/text_protocol/`，可跨 OpenAI、Anthropic 与兼容网关复用，并对模型输出中的 JSON 转义、路径和引号问题提供容错。协议错误会被结构化后回灌给模型自我纠错。

工具策略支持按会话或全局控制工具与子能力（文件读/写/删除、编辑、Grep 搜索、命令执行、网页访问、子 Agent 派发）。被关闭的能力会从有效工具定义中**物理移除**，而不仅仅依赖提示词约束。

## 5. LLM 提供商与颗粒化模型配置

核心支持 OpenAI SDK、Anthropic SDK、自定义 Base URL、OpenAI 兼容服务与网关，以及每类 Agent 独立模型配置。配置回退链：

```text
AGENT_<PROFILE>_* → SUB_AGENT_* → 主 Agent 配置
```

可独立配置的 profile 包括：主 Agent、子 Agent、Supervisor、ModeSelector、Security Agent。

## 6. 上下文、记忆与历史

Spore 提供多层会话连续性：内存中的当前会话消息、最近会话自动保存的短记忆、手动保存/重命名/加载的历史文件、对话点 checkpoint、节省模式下的中间工具结果裁剪、上下文接近阈值时的压缩管理。短记忆默认保留最近一组会话；正在运行的任务本身不跨进程持久化。

Learning episodic memory 会在每次请求前检索最多 3 条相关历史，并在任务成功后记录 episode。embedding 服务不可用时，检索会平稳降级而不会阻塞任务；episodic consolidation 目前不会自动执行。

系统默认将每次 LLM 完整回复写入对应会话的 `raw.log`（`LOG_RAW_ENABLED=true`）。日志可能包含提示词、模型输出、路径、工具上下文和其他敏感信息，请按需保护或关闭。路径与开关详见[配置说明](docs/CONFIGURATION.md)。

## 7. 安全设计

安全相关实现位于：

- `base/security_guard.py`：命令安全守卫（高危规则、白名单、评估缓存、审计日志）；
- `AutoAgent/security_agent.py`：异步 Security Agent（意图研判、恶意判定、修复建议）；
- `desktop_app/backend/confirm_manager.py`：桌面确认请求；
- `desktop_app/backend/security_interrupt.py`：恶意判定后的会话熔断；
- `base/backup_manager.py`：文件备份与恢复。

### `SECURITY_AGENT_MODE`

| 模式 | 行为 |
|---|---|
| `off` | 关闭安全 Agent 研判 |
| `basic` | 本地高危规则预筛；命中后由 AI 风险评估与确认 |
| `full` | 每条命令异步进行语义 / 风险 / 恶意研判；恶意时熔断 |

### `SECURITY_GUARD_MODE`（仅在 `basic` 下生效）

| 模式 | 行为 |
|---|---|
| `strict` | 高危规则命中即确认 |
| `balanced` | 中高风险确认 |
| `permissive` | 仅高风险确认 |

配套能力包括白名单、评估缓存、审计日志（`.spore/security_audit.jsonl`）、回滚建议和恶意命令后的修复建议。

## 8. 备份与回滚

文件恢复系统独立于 Git，使用内容寻址与版本记录：写入前后比较内容哈希，仅真实变化才保存；支持版本查看、按版本恢复与按步回退；删除文件与目录中的文件可进入恢复链；增量版本使用 `bsdiff4` 降低存储成本；每隔若干版本保存完整锚点控制恢复链长度；恢复操作自身也会记录版本。每个会话拥有自己的备份版本链与 metadata，checkpoint 分为 `user_message` 和 `action` 两类。对话点回滚按该会话身份恢复文件、消息历史和 TODO。底层物理文件系统仍然共享，因此这种按会话组织的恢复记录不代表完整的文件系统隔离。

CLI 常用命令：

```text
rollback <文件> [--to 版本号 | --steps N]
filehistory [<文件>]
checkpoints
rewind [<checkpoint_id> | --turns N]
whitelist [list | add <命令>]
```

详见 [CLI 文档](docs/CLI.md)。

## 9. 桌面端技术栈

| 层 | 技术 |
|---|---|
| Desktop 容器 | Tauri 1.x |
| 前端 | React、TypeScript、Vite、Zustand |
| 后端 | Python 3.10+、FastAPI |
| 并发与隔离 | `threading`、`ThreadPoolExecutor`、`multiprocessing`、IPC |
| 实时推送 | 独立 WebSocket 进程 + 进程间队列 |
| 打包 | PyInstaller、NSIS、Tauri |
| 备份 | 内容寻址存储、SHA256、bsdiff4 |

桌面端通过 Tauri sidecar 启动和关闭本地 Python 后端，并用 Windows Job Object 保证主程序退出时后端进程树被连带回收。Windows 是主要支持平台。

## 10. 本地 HTTP / WebSocket 集成

后端可作为本地 Agent 服务使用，典型能力包括：

- `POST /api/task/submit`：提交后端自驱任务；
- `GET /api/task/status`：查询任务或会话运行状态；
- `POST /api/chat/send`：单轮会话调用；
- `POST /api/chat/interrupt`：中断当前主任务；
- 会话创建 / 切换 / 删除、历史读取、记忆管理、配置更新；
- WebSocket 推送 `task_started`、`round_reply`、`tool_call`、`tool_result`、`todo_update`、`task_finished` 等结构化事件。

REST 默认使用 `127.0.0.1:8765`，并读取 `DESKTOP_API_PORT`。前端 WebSocket 客户端当前仍固定为 `ws://127.0.0.1:8766`，因此修改 REST 端口不会同步移动这条前端连接。

接口默认绑定本机回环地址。如需暴露给局域网或公网，请自行评估认证、网络边界、权限和审计要求。

## 11. 目录结构

```text
base/                       Agent 核心、工具、会话、IPC、策略、备份
AutoAgent/                  Supervisor、ModeSelector、Security Agent
desktop_app/backend/        FastAPI 路由、任务层、通知、WebSocket、确认
desktop_app/frontend/       React/Tauri 桌面界面
prompt/                     主 Agent 与辅助 Agent 提示词
skills/                     可扩展技能包（docx / pdf / pptx / pcap-analyst 等）
docs/                       配置、构建、界面、CLI、架构文档
example/                    真实任务示例
```

## 12. 构建源码版

环境要求：Windows 10/11 x64、Python 3.10+、[uv](https://github.com/astral-sh/uv)、Node.js 18/20 LTS、Rust + Cargo、Visual Studio Build Tools（含 C++ 工具链）。

双击 `build_installer.bat` 可构建安装包。构建过程会准备前端产物、Python 后端 sidecar 和 NSIS 安装程序。详见 [构建指南](docs/BUILD.md)。

---

## 许可证

本项目采用 **AGPL-3.0 License**。如需商业使用，请联系 miunasu@foxmail.com。详见 [LICENSE](LICENSE)。

---

<div align="center">

**Spore AI Agent 4.0** · 让 Agent 有真实执行力，让用户始终保有控制权

[GitHub](https://github.com/miunasu/Spore) · [文档](docs/) · [Release](https://github.com/miunasu/Spore/releases)

</div>
