# 动态 HTML 语义意图与修改事务协议（已实施）

> 状态：已实施协议说明
> 适用范围：Spore HTML artifact 的用户行为采集、语义意图归纳、Frontend Agent 调度、领域知识供给、HTML mutation、冻结、校验、加载与解冻。
> 本文使用“必须 / MUST”描述协议不变量，不再作为候选设计或固定五秒采集方案。

## 1. 协议目标

动态 HTML 页面可能已经具备完整结构和本地交互，但缺少某些内容或能力。例如，PE 文件结构页面可以展示 `IMAGE_SECTION_HEADER.PointerToRawData` 及当前值，却没有解释字段定义和该值在当前文件中的意义。

系统不把鼠标和键盘流水直接排队交给 Agent，而是维护当前语义焦点，将相关信号归纳为一个可替换的 semantic intent episode。只有页面尚未满足且意图足够明确时，才调用 Frontend Agent。只有 Frontend Agent 决定持久修改 HTML 时，才进入 `interrupt` barrier、冻结、mutation 校验、CAS 持久化、重载、恢复、ready 后端确认与解冻流程。

协议保证：

1. 普通浏览不会持续触发 Agent。
2. 模糊选择先在本地消歧。
3. 复制、取消和新焦点可以在 barrier 前取消旧意图。
4. 网络延迟不会形成 FIFO 历史任务队列。
5. iframe 信号仅作为不可信候选证据。
6. 语义对象、展示位置和 mutation 目标使用不同引用。
7. 领域事实由主 Agent、专业 Agent 或批准的知识源提供。
8. `interrupt` 只负责 Freeze Signal，不代表 mutation 已被接受。
9. `@SPORE:STOP_REASON` 只结束 Agent 生命周期，不代表 HTML 事务成功。
10. 页面只有在提交、加载、状态恢复和后端 ready ACK 完成后才正常解冻。

---

## 2. 实施链路

一个完整交互按以下阶段处理：

```text
可信浏览器事件
→ iframe bridge 生成有界候选观察
→ Host 归一化、裁剪敏感值
→ 更新 artifact focus memory
→ 动态窗口合并或切分意图片段
→ 本地响应判断
→ 弱信号仅更新焦点 / 模糊信号显示本地候选工具条
→ 形成 semantic intent episode
→ Latest Wins 注册、替换或取消请求
→ 必要时通过主 Agent 知识链路取得 knowledge_packet
→ Frontend Agent 判断 no_change 或 mutate
→ mutate 的首个非空输出为独立 interrupt
→ 当前请求建立 barrier 并冻结整个预览
→ Spore 通用协议结束 Agent 输出
→ mutation schema、引用、语法与安全校验
→ 基础版本检查与 CAS 持久化
→ 加载新文档并恢复运行时状态
→ iframe init/restore ready
→ 后端匹配 operation 的 ready ACK
→ 解冻并执行唯一 latest pending intent
```

观察、意图、知识、页面表达和提交事务是五个不同职责层。任何一层都不得把自己的成功等同于下一层成功。

---

## 3. 信号等级与本地处理

### 3.1 弱信号

典型事件：

- 单次普通点击；
- 短暂停留；
- 无显式请求的键盘导航；
- 页面已完成预期响应的控件操作。

处理：

- 更新 focus memory；
- 不直接调用 Agent；
- 可以作为同一焦点后续强信号的上下文；
- 焦点转移到无关结构时关闭旧片段。

### 3.2 模糊信号

典型事件：

- 拖选文字；
- 选择技术内容但没有说明用途；
- 两个对象可能用于解释或对比。

处理：

- 保留为本地 candidate；
- 显示轻量候选工具条，例如“解释 / 对比 / 取消”；
- 未确认前不默认调用 Agent；
- 复制、选择折叠、取消或无关焦点转移会撤销候选；
- 用户点击工具条后，将显式请求写入新的高置信度 episode。

### 3.3 强信号

典型事件：

- 双击结构化技术字段；
- touch long press；
- 对同一未响应对象重复操作；
- 同一对象的字段名、字段值和结构上下文形成稳定组合。

处理：

- 进入短稳定窗口；
- 等待可能的相关补充信号；
- 若用户复制、取消或切换无关焦点，则取消；
- 页面没有本地满足时形成 Agent 候选。

### 3.4 明确信号

典型事件：

- 页面明确的“解释”“对比”“补充内容”按钮；
- `data-spore-request` 声明的请求；
- submit 或其他不可歧义动作。

处理：

- 立即关闭当前动态窗口；
- 形成高置信度 episode；
- 参与 Latest Wins 仲裁，不等待固定批次。

### 3.5 取消信号

以下操作不仅取消本地候选，也会在 `interrupt` 前使旧 Agent 请求失效：

- 选择后复制；
- 选择折叠或显式取消；
- 新语义焦点替代旧焦点；
- 页面本地响应已经满足请求；
- artifact 基础版本发生变化。

取消信号必须推进 intent epoch 或以等价取消身份通知调度层，不能只隐藏工具条。

---

## 4. 动态窗口协议

### 4.1 动态窗口不是固定采样周期

底层可信事件即时采集；动态窗口控制的是“何时提交意图”，不是每隔固定时间抽样。系统不使用固定五秒批次，也不累积无界事件流水。

动态窗口依据以下状态变化：

- 信号强度和显式程度；
- 当前语义焦点是否稳定；
- 新事件与当前片段是否相关；
- 页面是否可能仍在本地响应；
- 用户是否仍在输入、选择或补充上下文；
- 当前是否存在 Agent 请求；
- 当前请求是否已建立 `interrupt` barrier；
- 用户操作节奏；
- Agent、网络和页面加载状态；
- 最大存活边界。

### 4.2 已实施窗口类别

| 类别 | 适用信号 | 行为 |
|---|---|---|
| immediate | 显式请求、submit | 尽快提交当前意图 |
| short_stable | dblclick、long press、重复未响应操作 | 短暂等待同焦点补充证据 |
| input_silence | input、change | 用户停止输入后归纳 |
| ambiguous_selection | selection | 保持本地候选，不直接提交 |
| local_outcome_observation | 普通控件操作 | 先观察页面本地响应 |
| maximum_lifetime | 所有未决片段 | 到期后提交强意图、保留候选或取消，不保证调用 Agent |

具体毫秒数是策略配置，不是协议语义。代码和提示词不得再把 episode 描述为 `window_ms=5000` 的固定批次。

### 4.3 片段合并与切分

通常合并：

- 同一语义对象的 click、dblclick 和最终 selection；
- 字段名称与同一行当前值；
- 同一结构内明确相关的两个对象；
- 同一未响应对象的重复操作。

必须切分或替换：

- 新焦点位于无关章节；
- 对象跨越不同领域或语义结构；
- 用户给出新的显式动作；
- 页面导航或 artifact 版本变化；
- 前一 episode 已提交完成；
- 取消信号结束旧候选。

相同 DOM parent 或相同容器只能作为相关性证据，不能单独证明两个对象属于同一意图。

---

## 5. Focus Memory 与本地候选工具条

每个 artifact 维护短期、可替换的 focus memory：

```text
primary semantic focus
optional secondary focus
semantic path and container
current value / instance data
recent high-value evidence
local outcome
candidate intents
confidence
current intent epoch
base artifact version
```

focus memory 不是完整行为历史。普通点击即使不形成 Agent 请求，也必须更新 primary focus。第二焦点只有在对象关系足够明确时保留。

模糊 selection 形成的 candidate toolbar 属于 Host 本地 UI：

- `Explain`：把当前候选提升为显式解释请求；
- `Compare`：把 primary 和 secondary focus 提升为显式对比请求；
- `Dismiss`：结束候选并使其不能继续触发 Agent；
- copy、selection collapse 或无关焦点转移自动执行等价 dismiss。

---

## 6. Semantic Intent Episode

提交给调度层和 Frontend Agent 的不是原始事件队列，而是一个有界 episode。核心结构包括：

```json
{
  "episode_id": "episode-...",
  "intent_epoch": 12,
  "started_at_ms": 0,
  "ended_at_ms": 0,
  "semantic_focus_ref": "...",
  "presentation_target_ref": "...",
  "mutation_target_ref": "...",
  "focus": {},
  "secondary_focus": null,
  "evidence": [],
  "candidate_intents": [],
  "confidence": "low|medium|high",
  "local_outcome": "satisfied|not_satisfied|unknown"
}
```

### 6.1 语义上下文

primary 和 secondary focus 按可用性包含：

- object name；
- object type；
- domain；
- semantic path；
- container ref；
- selected text；
- current value；
- instance data；
- related refs；
- explanation present；
- inspector ref。

多个对象用于 compare 时，不能只传第二对象的字符串 ref；必须保留其对象类型、语义路径和实例上下文，以便 Agent 区分“浏览多个字段”和“比较两个同类对象”。

### 6.2 Local Outcome

Local Outcome 表示页面本地行为是否已经满足用户，而不只是 DOM 是否发生任意变化。至少区分：

- observed；
- relevant change；
- reveal succeeded；
- target visible；
- explanation present；
- satisfied / not satisfied / unknown。

任意 body 长度、无关动画或控件状态变化不能单独判定 satisfied。

---

## 7. 三类引用协议

三类引用必须保持职责分离：

### 7.1 `semantic_focus_ref`

标识用户所关注的领域对象，例如：

```text
PE.IMAGE_SECTION_HEADER.PointerToRawData
```

它用于意图理解，不自动具备 DOM mutation 权限。

### 7.2 `presentation_target_ref`

标识结果应该展示的位置，优先级通常为：

1. 已有稳定 inspector；
2. 当前结构的说明区域；
3. 与焦点对象稳定关联的展示容器；
4. 必要时创建的新 inspector。

它不能因为与 semantic focus 名称相同就自动视为 mutation target。

### 7.3 `mutation_target_ref`

标识 Host 已解析并授权给当前请求的结构目标。它必须来自后端 supplied references，例如当前元素、父容器、inspector、presentation target、`document-head` 或 `document-body`。

DOM path、element id、`data-spore-*` 和 iframe 声明只能用于 Host 解析候选节点。Frontend Agent 最终 mutation 必须使用 Host 提供并接受的 `target_ref`，不得直接使用任意选择器或自造引用。

---

## 8. 不可信 iframe 候选与隐私边界

iframe bridge 是观察源，不是认证边界。以下内容全部视为不可信 artifact data：

- 可见文本；
- 标签、ARIA、title；
- `data-spore-request`；
- `data-spore-semantic-ref`；
- domain、object type、semantic path；
- inspector ref；
- local outcome；
- iframe 发出的 ready 候选。

Host 必须执行：

- 事件类型白名单；
- 字符串、数组和嵌套深度裁剪；
- password、token、secret、支付信息等敏感值裁剪；
- 引用重新解析；
- 请求身份和 artifact 版本校验；
- 不把 artifact 文本当作系统指令。

`data-spore-*` 可以增强语义准确度，但不能绕过 Host mutation 引用和事务校验。

---

## 9. 主 Agent 领域知识责任链路

Frontend Agent 负责：

- 解析当前页面意图；
- 判断页面是否需要改变；
- 选择稳定展示位置；
- 将已经提供且有依据的知识忠实表达为 HTML。

Frontend Agent 不负责凭空生成权威领域事实。解释 PE、协议、AST、数据库 schema、反汇编、医学、法律或其他专业对象时，知识链路如下：

```text
semantic intent episode
→ Host 判断 knowledge_requirement
→ 主 Agent / 专业 Agent / 批准知识源处理语义知识请求
→ semantic knowledge prompt 约束严格 JSON
→ 校验 knowledge_packet
→ Frontend Agent 忠实页面表达
```

`knowledge_packet` 的顶层字段固定为：

```json
{
  "status": "grounded|uncertain|unavailable|error",
  "answer": "...",
  "facts": [],
  "uncertainties": [],
  "sources": []
}
```

责任规则：

- `grounded`：Frontend Agent 可以忠实表达 answer 和 facts；
- `uncertain`：必须在页面中明确展示 uncertainties，不能把推断写成确定事实；
- `unavailable`：不得补写领域解释，可返回 `no_change` 或仅建立明确的待补充知识区域；
- `error`：不得把错误、空响应或模型猜测当作知识；
- packet 缺失、结构非法或来源不合格时，按 unavailable 处理；
- Frontend Agent 不得扩写 packet 中没有依据的新事实。

知识内容来源和页面表达是两个不同提交物。Frontend Agent 的布局能力不能替代领域知识责任。

---

## 10. Latest Wins、取消与队列语义

每个 artifact 只允许：

```text
一个 active operation
一个 latest pending intent
```

不存在 FIFO 历史意图队列。

### 10.1 Barrier 前

在当前请求尚未建立有效 `interrupt` barrier 时：

- 新 intent epoch 替代旧请求；
- 新相关证据可以合并成更新 episode；
- copy、dismiss、selection collapse、本地满足和无关焦点转移可以取消旧请求；
- provider 请求应被取消；
- 无法立即取消时，旧结果仍因身份过期而不可执行；
- 旧请求迟到的输出和 `interrupt` 均无效。

### 10.2 Barrier 后

有效 `interrupt` 建立 barrier 后：

- 当前 mutation 事务不可被新意图替换；
- 新意图只覆盖 `latest pending intent`；
- 当前事务结束、失败恢复或 ready ACK 后，才启动最新 pending intent；
- 中间 pending intent 被更新版本直接替换。

---

## 11. 五类身份与版本

每次提交必须携带并校验五类身份/版本：

| 类别 | 字段 | 作用 |
|---|---|---|
| 意图片段身份 | `episode_id`、`intent_epoch` | 判断当前用户意图及新旧顺序 |
| Agent 请求身份 | `agent_request_id` | 绑定一次 provider/Frontend Agent 请求 |
| HTML 事务身份 | `operation_id` | 绑定 barrier、heartbeat、ready 和 recovery |
| Artifact 基础版本 | `base_html_revision`、`base_html_sha256` | 防止在过时 HTML 上应用 mutation |
| 交互状态版本 | `state_revision` | 丢弃乱序 WebSocket、polling 和 ACK 状态 |

任何迟到结果在 mutation 应用前都必须再次检查这五类身份。只要 intent、operation、artifact 或 state 已过期，结果不得冻结、持久化或解冻当前页面。

---

## 12. `interrupt` Barrier 协议

### 12.1 合法输出形式

`mutate` 响应的首个非空输出必须是独立一行：

```text
interrupt
```

之后才输出一个严格 JSON mutation object。`no_change` 禁止输出 `interrupt`。

```text
interrupt
{"decision":"mutate","intent":"...","mutations":[...]}
@SPORE:STOP_REASON=frontend operation finished
```

首个非空输出不是独立 `interrupt` 的 mutate 响应必须拒绝。正文、JSON 字符串或解释文字中偶然出现 `interrupt`，不能被视为合法 barrier。

### 12.2 Freeze Signal 与 Commit Acceptance

`interrupt` 的含义仅为：

```text
当前有效请求承诺尝试修改页面；Host 进入冻结事务。
```

它不是 Commit Acceptance。建立 barrier 后，Host 仍必须完成：

1. 当前 active/superseded 身份检查；
2. mutation JSON schema 校验；
3. allowed operation 校验；
4. supplied target ref 校验；
5. fragment 语法、安全与大小校验；
6. 完整 HTML 合成和文档校验；
7. artifact 基础 revision/SHA 校验；
8. CAS 持久化；
9. 新文档加载、恢复和 ready ACK。

只有当前未 supersede 的请求可以建立 barrier。过时请求的 `interrupt` 永远无效。

---

## 13. STOP_REASON 边界

`@SPORE:STOP_REASON=<natural language reason>` 属于 Spore 通用 Agent 生命周期协议，只表示 Frontend Agent 已结束本轮或多轮输出。

它不表示：

- mutation JSON 合法；
- target refs 有效；
- HTML 校验通过；
- artifact 已持久化；
- CAS 成功；
- iframe 已加载；
- 运行时状态已恢复；
- 页面已经解冻；
- 用户意图已经满足。

状态模型必须分别记录：

```text
agent_stop_reason
operation_outcome
validation_result
artifact_commit_result
document_load_result
```

mutation parser 不定义专用 `html_update_complete` stop reason。Agent 使用通用 STOP_REASON 自行结束，Host 独立判断事务结果。

---

## 14. Mutation、校验与 CAS

允许的 mutation operation：

- `append`
- `prepend`
- `before`
- `after`
- `replace_inner`
- `replace_outer`
- `set_attributes`
- `remove`

约束：

- 只能使用当前请求 supplied `target_ref`；
- HTML 字段必须是 fragment，不得返回完整文档；
- mutation 数量和总字节数有界；
- 禁止替换或删除核心 document structure；
- 整批 mutation 原子校验，任一失败则整批拒绝；
- 应用后对完整 HTML 执行语法、安全和完整性校验；
- 保存使用 `base_html_sha256` 的 compare-and-swap；
- CAS 冲突不得覆盖较新页面；
- STOP_REASON 或 Agent 成功返回不能绕过 CAS。

---

## 15. Freeze、ready、restore、init 与后端 ACK

### 15.1 冻结范围

有效 barrier 建立后，Host 冻结整个 HTML preview：

- overlay 拦截 pointer；
- iframe 失去焦点；
- `tabIndex=-1`；
- iframe body 进入 inert/frozen 状态；
- bridge 停止发布新的交互候选。

冻结持续覆盖协议重试、validation、persistence、reload、restore 和 ready ACK。

### 15.2 文档加载与状态恢复

CAS 成功后，Host 生成新的 document token 并加载新 `srcDoc`。恢复信息按可用性包括：

- scroll position；
- active element；
- selection；
- input/select/textarea state；
- details open state；
- expanded/selected/hidden toggles；
- semantic presentation target。

### 15.3 ready 候选

bridge 只有在以下阶段完成后才发送 ready 候选：

1. bridge 已安装；
2. 新 document token 已生效；
3. artifact 初始化已完成或明确报告状态；
4. runtime restore 已完成或明确报告失败；
5. 核心交互面已可使用。

ready 候选至少绑定 artifact、document token 和 restore/init 结果。它仍是不可信 iframe 消息，不能直接解冻。

### 15.4 后端 ready ACK

Host 收到 ready 候选后调用后端 ACK。后端必须匹配：

- `operation_id`；
- `agent_request_id`；
- committed HTML SHA-256；
- 允许的 `state_revision`；
- 当前 phase 必须处于 committed/reloading 且 frozen。

只有后端返回匹配 operation 的 `interaction_ready` 且 `frozen=false`，Host 才解除冻结。ready=false、restore/init 失败或超时进入失败恢复，不得伪装为正常完成。

---

## 16. Heartbeat、Lease 与 Recovery

冻结事务使用 lease 防止应用崩溃、WebSocket 丢失或浏览器加载异常造成永久冻结。

- barrier 建立后写入 `lease_expires_at`；
- Agent 继续输出、协议重试和冻结页面期间发送 heartbeat；
- heartbeat 必须绑定当前 `operation_id`，可同时校验 `agent_request_id`；
- heartbeat 只能延长当前 frozen operation；
- lease 过期进入 orphaned/recovering；
- recovery 将事务标记为失败并解除冻结；
- recovery 不把未知加载结果标记为成功；
- recovery 结束后释放 active operation，并启动唯一 latest pending intent；
- 强制 recovery 只用于明确的 ready 超时或人工恢复路径。

---

## 17. Frontend Agent 决策协议

Frontend Agent 按顺序判断：

1. 当前 episode 是否仍有效；
2. 用户真正希望获得什么结果；
3. 页面是否已本地满足；
4. 是否有现有 inspector 或本地交互可以满足；
5. 是否需要领域知识以及 `knowledge_packet` 是否可用；
6. uncertainty 是否需要可见表达；
7. 是否确实需要持久 HTML mutation；
8. mutation 范围是否与意图和置信度相称。

决策：

- `no_change`：页面已满足、证据不足、知识不可用或不应持久修改；
- `mutate`：使用最小、连贯、受限 mutation 更新稳定展示区域。

一次弱操作不得触发大范围重构。复杂技术页面优先复用 inspector，避免无限追加说明卡片。

---

## 18. 实施文件映射

| 协议职责 | 主要文件 |
|---|---|
| 产品与事务协议说明 | `docs/HTML_SEMANTIC_INTENT_STRATEGY.md` |
| iframe 事件、语义上下文、runtime state、freeze/ready bridge | `desktop_app/frontend/src/components/common/htmlBridge.ts` |
| 信号归一、动态窗口、焦点相关性、episode 与 refs | `desktop_app/frontend/src/components/common/htmlIntent.ts` |
| focus memory、候选工具条、Latest Wins 客户端、冻结与 ready | `desktop_app/frontend/src/components/common/HtmlPreview.tsx` |
| 前端 API 身份、interaction、heartbeat、ready、recovery | `desktop_app/frontend/src/services/api.ts` |
| 后端 HTTP 路由和 ready/recovery 请求模型 | `desktop_app/backend/routes/html.py` |
| 候选事件与 episode 的隐私归一化 | `base/html_semantic_intent.py` |
| 交互状态、revision、heartbeat、lease、ready ACK、recovery | `base/html_interaction_state.py` |
| Latest Wins coordinator、Agent 调用、interrupt barrier、mutation、CAS | `AutoAgent/frontend_agent.py` |
| Frontend Agent 页面表达和事务提示词 | `prompt/frontend_prompt.md` |
| 主/专业 Agent 语义知识包提示词 | `prompt/semantic_knowledge_prompt.md` |
| mutation 与事务后端测试 | `tests/test_frontend_agent.py`、`tests/test_frontend_agent_transactions.py` |
| iframe、候选工具条、Latest Wins、ready 前端测试 | `desktop_app/frontend/src/components/common/HtmlPreview.test.tsx` |

---

## 19. 协议不变量摘要

1. 不存在固定五秒事件批次。
2. 普通点击只更新 focus memory。
3. 模糊选择先显示本地工具条。
4. copy、取消和无关焦点在 barrier 前撤销旧意图。
5. 每个 artifact 只有 active 和 latest pending。
6. iframe 元数据和 ready 都是不可信候选。
7. semantic、presentation 和 mutation refs 不得混用。
8. 领域事实必须来自已校验 `knowledge_packet`。
9. `uncertain` 必须在页面中显示不确定性。
10. 缺失或失败的知识包不得由 Frontend Agent 补写事实。
11. mutate 的首个非空输出必须是独立 `interrupt`。
12. Freeze Signal 不等于 Commit Acceptance。
13. STOP_REASON 不等于 HTML 操作成功。
14. 所有 mutation 必须通过身份、版本、schema、语法、安全和 CAS 校验。
15. 正常解冻必须经过 load、restore/init、ready candidate 和后端 ACK。
16. heartbeat/lease/recovery 保证冻结事务最终可收敛。