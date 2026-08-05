# HTML Semantic Intent Implementation Audit

> 审阅类型：策略—实现只读联合审计  
> 审阅基线：`docs/HTML_SEMANTIC_INTENT_STRATEGY.md` 与当前前后端实现  
> 审阅日期：2026-08-02  
> 说明：本报告保留完整 Critical / High / Medium 1—21。文件行号可能随并行修改漂移，应以函数名和代码区域为准。

## 最终实施状态（2026-08-02）

> 下方原始 Critical / High / Medium 1—21 保留为修复前审计记录；本节是修复后的最终状态。当前 21 项均已落地并有自动化测试覆盖，不再以原始“结论摘要”中的未修复判断为准。

| # | 原审计项 | 最终状态 | 已落地的安全/行为边界 |
|---:|---|---|---|
| 1 | Latest Wins cancel/barrier 竞态 | **Resolved** | 客户端等待取消 ACK；后端只维护 `active + latest_pending`；barrier owner 不可被新 episode 抢占。 |
| 2 | iframe 伪造 ready/restored | **Resolved** | bridge capability 仅存于注入脚本闭包；artifact 无法从 DOM/freeze 消息读取；ready 需 capability、generation、restore attempt 和完整 report。 |
| 3 | 公共 force recovery | **Resolved** | 公共模型不再接受 `force`；仅允许 lease 已到期且 operation/request/state revision 全匹配的 CAS recovery。 |
| 4 | semantic/presentation ref 权限升级 | **Resolved** | semantic、presentation、mutation 三个 namespace 独立；mutation 只能使用 Host 明确签发的 mutation refs。 |
| 5 | 任意 `element_id` 劫持节点 | **Resolved** | ID 只作为候选约束，仍必须与 tag/text/aria/href/path 等归一化证据一致；冲突时不解析。 |
| 6 | `data-spore-request` 被视为可信强意图 | **Resolved** | iframe metadata 仅为不可信候选证据；后端重新归一化并由 semantic episode/evidence 决定意图。 |
| 7 | STOP_REASON 非终端 | **Resolved** | 通用 `ProtocolManager` 要求合法 STOP_REASON 后只能有空白；后续文本、JSON、REPLY/ACTION block 均报 `content_after_stop_reason`。 |
| 8 | barrier 后退化为普通 no_change | **Resolved** | barrier 后普通 `no_change` 被拒绝；仅允许显式受控 `abort_after_barrier`，且 STOP_REASON 不等于事务成功。 |
| 9 | interrupt 流式解析宽松 | **Resolved** | 第一个非空流式输出必须是严格独立、小写的 `interrupt`；前缀、大小写、附加字符和 stale stream 均不能冻结。 |
| 10 | 身份/版本交叉验证不完整 | **Resolved** | episode、epoch、agent request、operation、base revision/SHA、state revision、snapshot/event identity 全量校验。 |
| 11 | ready ACK revision/phase 偏弱 | **Resolved** | generation、restore attempt、capability、loaded SHA、phase、state revision 和 readiness report 在后端原子校验。 |
| 12 | ready=false 收敛慢/不明确 | **Resolved** | `ready=false` 立即进入 `failed_after_barrier` 终态并停止 heartbeat；late ready=true 被拒绝；最终仅可 lease-expired CAS recovery。 |
| 13 | 冻结期间普通 artifact 写入绕过 | **Resolved** | save、force generate、delete 都经过统一 unfrozen guard；冻结时返回 409，artifact SHA 保持不变。 |
| 14 | coordinator/lease 仅驻内存 | **Resolved** | interaction 与 barrier owner journal 持久化；重启恢复 frozen owner；pre-barrier/latest pending 不复活；损坏 journal fail-closed quarantine。 |
| 15 | 知识责任链仅为通用模型调用 | **Resolved** | 每次知识请求签发 request-scoped source registry；严格 JSON/完整 source metadata；Host 重签 fact ID，并用进程内 HMAC authority digest 证明 packet 未被篡改或跨请求复用。 |
| 16 | knowledge requirement 覆盖过窄 | **Resolved** | Explain/Compare、技术字段/结构含义等 semantic intent 会显式产生 knowledge requirement；无 grounded packet 时禁止权威领域 mutation。 |
| 17 | 弱点击无法跨窗口累计 | **Resolved** | 弱点击记忆按 artifact/focus 跨动态 settling window 累积；达到重复阈值后形成解释候选，不跨 artifact 混合。 |
| 18 | dismiss 不推进 epoch/取消 | **Resolved** | dismiss 清 candidate/focus memory、推进 epoch，并按精确 identity 取消相关 barrier 前请求。 |
| 19 | 外部 revision 切换不原子 | **Resolved** | barrier 前 content/artifact 变化执行统一 invalidation；barrier committed/awaiting ready/terminal failure 时禁止 reset、替换 owner 或解冻。 |
| 20 | restore 解析成功即视为成功 | **Resolved** | bridge 输出 requested/attempted/applied/failures 等严格 restore report；required ref/value/focus/selection 恢复失败即 `restored=false`。 |
| 21 | 控件值、PII、URL secret 采集过量 | **Resolved** | control value 默认不采集，仅显式 opt-in；URL 去 query/fragment；文本和字段在前后端执行有界裁剪与敏感信息最小化。 |

### 最终协议不变量

1. 原始浏览器事件不会作为无限队列直接交给 Frontend Agent；Host 使用信号类型相关的动态 settling window，输出有界 semantic episode/evidence。
2. Latest Wins 只在 barrier 前生效；barrier 一旦由严格 `interrupt` 建立，旧 operation 成为唯一页面 owner。
3. `@SPORE:STOP_REASON=...` 仅结束 Agent 生命周期；mutation 是否成功由 validate → CAS commit → reload → init/restore → ready/backend ACK 的完整事务链决定。
4. 页面从 barrier 建立起保持冻结，直到匹配 operation 的完整 ready ACK 成功；失败后保持受控冻结并由严格 lease recovery 收敛。
5. iframe 观测、artifact HTML、labels、`data-*` 和页面脚本都是不可信输入；ref authority、bridge capability、knowledge authority 和 commit identity 均由 Host/后端重新建立。
6. 知识 source/fact ID 只在当前 knowledge request 中有效；静态猜测、旧请求复用、source metadata 改写、fenced/附加 JSON 和 packet 篡改均不能取得 grounded mutation authority。

### 最终验证

- 后端/Python：`python -m pytest tests -q --disable-warnings --maxfail=20` → **141 passed**。
- 前端 TypeScript：`npx tsc --noEmit` → **passed**。
- 前端 Vitest：`npm test -- --run` → **12 files / 79 tests passed**。
- 关键测试覆盖：transaction Latest Wins/barrier/CAS/ready/recovery、journal restart/corruption/privacy、strict STOP_REASON、request-scoped knowledge authority、bridge capability/restore/privacy、dynamic intent window/weak-click memory/ref namespaces。

---

## 范围

重点审阅：

- `AutoAgent/frontend_agent.py`
- `base/html_interaction_state.py`
- `base/html_semantic_intent.py`
- `base/text_protocol/protocol_manager.py`
- `base/html_artifacts.py`
- `desktop_app/backend/routes/html.py`
- `desktop_app/frontend/src/components/common/HtmlPreview.tsx`
- `desktop_app/frontend/src/components/common/htmlBridge.ts`
- `desktop_app/frontend/src/components/common/htmlIntent.ts`
- `desktop_app/frontend/src/services/api.ts`
- `prompt/frontend_prompt.md`
- `prompt/semantic_knowledge_prompt.md`

## 结论摘要（修复前历史记录）

> 本段描述联合审计当时的缺口，已由上方“最终实施状态”取代。

审计当时的实现已经具备动态窗口、semantic intent episode、单 active + latest pending、`interrupt` 冻结信号、mutation 校验、CAS 保存、文档重载、runtime restore、ready ACK、heartbeat/lease/recovery 等主干能力，但协议仍存在三个会破坏事务安全边界的 Critical 问题：客户端 Latest Wins 与后端 barrier 状态竞态、iframe 可伪造 ready、公开的强制恢复可绕过 barrier。高风险差距主要集中在 refs 权限升级、interaction/interrupt/STOP_REASON 严格性、版本身份、ready 状态机、事务外写入和知识责任链。中风险差距主要集中在弱信号跨窗口记忆、候选取消、revision 切换、restore 真实性及隐私裁剪。

---

# Critical

## 1. Latest Wins 的客户端取消与服务端 barrier 提交存在竞态

- **位置**：
  - `desktop_app/frontend/src/components/common/HtmlPreview.tsx`：`supersedeActiveBeforeBarrier`、`startEpisode`、interaction 状态接收与 cancel 调用区域
  - `AutoAgent/frontend_agent.py`：请求协调、取消、barrier 提交及 pending promotion 区域
- **问题**：客户端在取消 ACK 返回前即可把旧 active 标记 superseded 或替换为新 active。若旧请求已在服务端提交 barrier、但对应状态尚未送达客户端，客户端可能因为 active 身份已变化而忽略旧 operation 的 frozen 状态。与此同时，cancel 返回的 `reason=barrier_committed` 没有被提升为不可替代事务状态处理。
- **违反策略**：Latest Wins 只允许替换 barrier 前请求；barrier 一旦提交必须不可替代，直到该 operation 完成 ready 或进入明确恢复终态。
- **风险**：后端认为页面已冻结，前端却继续接收交互或启动新请求；旧 operation 与新 operation 对页面所有权发生分裂。
- **建议**：引入 cancel-ACK 状态机。旧 active 在取消结果确定前不得被物理替换；若 ACK 表示 barrier 已提交，立即恢复旧 operation 为唯一 active、进入冻结并把新 episode 仅保留为 latest pending。所有异步响应按 operation/request/epoch 重新归属，而不是仅以当前 React ref 判断是否忽略。

## 2. iframe 内页面脚本可伪造 ready / restored 报告

- **位置**：
  - `desktop_app/frontend/src/components/common/htmlBridge.ts`：readiness report 构造与 `parent.postMessage`
  - `desktop_app/frontend/src/components/common/HtmlPreview.tsx`：`interaction_ready` message 接收和后端 ready ACK 区域
- **问题**：artifact 脚本可读取 DOM 中的 artifact ID、document token，并自行向 parent 发送形似 bridge 的 `interaction_ready`。Host 未要求 iframe 消息携带由可信 bridge 独占的 operation capability；Host 还会用自身 pending state 补齐 operation/SHA 后直接请求后端 ACK。
- **违反策略**：iframe 只能提供不可信候选观察；ready 必须证明当前 document generation 已完成 init、restore，并与当前 operation 精确绑定。
- **风险**：恶意或意外页面脚本可绕过 restore/init 检查，使未恢复或未初始化的文档被后端确认 ready 并解冻。
- **建议**：由 Host 为每次文档加载生成不可由 artifact DOM 读取的 bridge capability/nonce，通过受控初始化通道交给 bridge；ready 消息必须带 operation ID、document generation、restore attempt ID、capability，并由 Host 和后端共同校验。不要仅靠公开 dataset token。

## 3. 公共 `force=true` recovery 可破坏 barrier 不变量

- **位置**：
  - `desktop_app/backend/routes/html.py`：interaction recovery 请求模型与路由
  - `AutoAgent/frontend_agent.py`：interaction recovery 入口
  - `base/html_interaction_state.py`：`recover` / lease recovery 状态迁移
- **问题**：调用方可请求强制恢复，但该能力未绑定 operation、agent request、state revision、lease owner、超时证明或授权角色。
- **违反策略**：barrier 只能由匹配 operation 的正常完成、受约束的 abort，或可证明 lease 失效后的 recovery 解除。
- **风险**：任意可访问该接口的调用方可在 mutation/commit/load/restore 中途解除冻结，造成用户继续操作旧文档或半提交文档。
- **建议**：移除普通客户端可用的无条件 `force`；恢复请求必须携带并验证 operation ID、expected state revision、lease generation/owner，且只有超时、后端检测到 owner 失效或受认证管理路径才允许强制恢复。

---

# High

## 4. 三类 refs 仍存在 semantic/presentation 自动升级为 mutation authority

- **位置**：
  - `desktop_app/frontend/src/components/common/htmlIntent.ts`：`buildSemanticIntentEpisode` 中三类 ref 构造
  - `AutoAgent/frontend_agent.py`：reference target 解析、mutation target fallback 区域
- **问题**：前端 mutation target 会回退到 inspector、spore target、container、semantic ref、element ID 或 focus；后端也会把 presentation/semantic node 作为 mutation anchor，并在无 focus 时把同一 fallback ref 同时赋给三类引用。
- **违反策略**：semantic ref 只说明“用户在看什么”，presentation ref 只说明“内容适合展示在哪里”，mutation ref 才是明确授权的可写目标；三者不能自动互相升级。
- **风险**：模糊语义焦点可能被转化为 DOM 写权限，导致错误区域被替换或删除。
- **建议**：mutation ref 只能来自显式、独立声明并经 Host/后端解析验证的 mutation capability。缺失时允许解释/no_change，但必须拒绝 mutation；presentation 和 semantic ref 不得作为 fallback mutation target。

## 5. 伪造 interaction 可通过任意 `element_id` 解析到 DOM 节点

- **位置**：`AutoAgent/frontend_agent.py`：interaction observation 解析、click node / element reference resolution 区域
- **问题**：当请求提供 `element_id` 时，后端可直接解析对应节点，却未把该节点与同一事件中的 tag、text、DOM path、semantic context 做一致性核验。
- **违反策略**：iframe 观察是不可信候选，Host/后端必须重解析并交叉验证。
- **风险**：伪造事件可把用户焦点指向任意受保护或高价值节点，进而影响 supplied refs 和 mutation 目标。
- **建议**：对 ID、path、spore-view、tag、文本摘要和语义容器进行多信号匹配；冲突时降低置信度或拒绝该 ref，不允许单一 iframe ID 获得权威身份。

## 6. 不可信 `data-spore-request` 被当成显式强意图

- **位置**：
  - `desktop_app/frontend/src/components/common/htmlBridge.ts`：采集 `data-spore-request`
  - `desktop_app/frontend/src/components/common/htmlIntent.ts`：`isStrongIntentSignal`、candidate/confidence 推断
  - `desktop_app/frontend/src/components/common/HtmlPreview.tsx`：copy / selection-clear 取消判断
- **问题**：页面可自行写入 `data-spore-request`，当前实现把它直接视为强、显式请求，并允许它阻止复制或清除选择触发的取消逻辑。
- **违反策略**：iframe 候选不可信；显式用户意图必须来自可信用户动作或 Host 确认，而不是页面自声明。
- **风险**：artifact 可制造高置信请求、频繁调用 Agent，或让用户取消动作失效。
- **建议**：将其降级为 `iframe_request_hint`；必须与可信事件类型、Host UI 确认或签名 action descriptor 组合后才能成为 explicit intent。copy/selection-clear 的取消优先级不得被未认证 hint 覆盖。

## 7. STOP_REASON 未被要求处于输出终端边界

- **位置**：
  - `base/text_protocol/protocol_manager.py`：STOP_REASON 提取、协议文本清理
  - `AutoAgent/frontend_agent.py`：Frontend Agent 输出解析、mutation 决策处理
- **问题**：STOP_REASON 可从输出任意位置被提取并剥离，后续仍可出现 mutation JSON。例如 `interrupt`、STOP_REASON、mutation JSON 的顺序可能被接受。
- **违反策略**：STOP_REASON 只结束 Agent 生命周期，必须是终端协议边界；其后不得再有业务输出。
- **风险**：Agent 生命周期结束与 mutation payload 边界混乱，流式解析可能在已经“停止”后继续接受写操作。
- **建议**：要求 STOP_REASON 是最后一个非空协议单元；其后任何非空 token 都拒绝。解析器先验证完整顺序，再做 marker 剥离。

## 8. barrier 后重试可退化为普通 `no_change` 并直接解冻

- **位置**：`AutoAgent/frontend_agent.py`：barrier 后 validation retry、`no_change` 分支、异常/终态处理区域
- **问题**：Agent 已输出合法 interrupt 并建立 barrier 后，如果 mutation 校验失败进入重试，后续响应可返回普通 `no_change`，当前逻辑可能把它作为正常无变更结果并解除冻结。
- **违反策略**：barrier 建立后只能进入 commit→load→restore→ready，或显式 abort/recovery 事务；不能回到 barrier 前普通 no_change 语义。
- **风险**：已冻结事务缺少明确回滚证明便被释放，状态审计和恢复责任丢失。
- **建议**：把 barrier 后状态设为不可逆事务阶段。重试只允许修复 mutation 或返回明确 `abort_after_barrier`，后者必须记录 validation/artifact/document outcome 并经后端终态迁移后解冻。

## 9. `interrupt` 流式解析不够严格

- **位置**：`AutoAgent/frontend_agent.py`：interrupt 正则、stream prefix 累积、首个非空输出检查、JSON fence 处理
- **问题**：interrupt 匹配大小写不严格；流式 prefix 可能重置或只保留后段，导致更早的非法文本被遗忘；非流式 provider 只能等完整响应后冻结；解析仍接受 fenced JSON，和提示词中的严格 JSON 边界不一致。
- **违反策略**：mutate 的首个非空输出必须是大小写精确、独立一行的 `interrupt`；barrier 应在该合法信号一出现就建立。
- **风险**：非法前缀被容忍、冻结时机过晚、不同 provider 的协议语义不一致。
- **建议**：实现单调、不可重置的前缀状态机；只接受精确 `interrupt\n`，一旦发现首个非空 token 不是该独立单元立即永久拒绝 mutate。非流式 provider 若无法早期冻结，应明确不支持 mutation 或使用具备首 token 回调的适配层。严格禁止 code fence。

## 10. 五类身份/版本并非全部强制且缺少交叉验证

- **位置**：
  - `desktop_app/backend/routes/html.py`：interaction request schema
  - `AutoAgent/frontend_agent.py`：operation identity 创建、请求校验、coordinator epoch
  - `base/html_semantic_intent.py`：episode identity 归一化
- **问题**：episode ID 未被端到端追踪；top-level identity、snapshot identity 和 event identity 之间未全部核对；state revision 主要只拒绝未来值，过旧值仍可能接受；coordinator epoch 在进程重启后重置。
- **违反策略**：episode、intent epoch、agent request、operation、artifact revision/SHA、state revision 必须形成一致身份链。
- **风险**：旧 snapshot、新 top-level request 或重启前 operation 可能被错误拼接；审计无法证明哪次用户意图产生了哪次 mutation。
- **建议**：把 episode_id、intent_epoch、request_id、operation_id、artifact generation、base revision/SHA、state revision 全部设为必填并逐层等值校验；epoch/generation 需持久化或采用全局唯一、单调可比较标识。

## 11. ready ACK 的 revision 与 phase 语义仍偏弱

- **位置**：
  - `desktop_app/backend/routes/html.py`：ready 请求字段
  - `base/html_interaction_state.py`：ready validation 与状态迁移
- **问题**：HTTP 层字段目前已要求提供，ready 校验和迁移也已在同一个 `RLock` 下执行，早期 TOCTOU 已显著修复；但 stale revision 仍可被接受，`failed_after_barrier` 等失败阶段仍可能随后接受 `ready=true`，后端没有 document generation/token 或 restore attempt identity。
- **违反策略**：ready 必须只确认当前 operation 当前加载代次、当前 restore 尝试和允许 ready 的 phase。
- **风险**：旧文档或旧恢复尝试的 ACK 可能结束新事务；失败终态可能被后来的消息翻转。
- **建议**：ready 使用 expected-exact revision，而非仅非未来；增加 document generation、document token hash、restore attempt ID；限定只有 `awaiting_ready` 可接受成功 ACK，失败终态必须不可逆或只能通过显式 recovery 新代次迁移。

## 12. `ready=false` 后通常要等待完整 lease 到期才恢复

- **位置**：
  - `desktop_app/frontend/src/components/common/HtmlPreview.tsx`：terminal failure、heartbeat 停止、poll/recover 区域
  - `base/html_interaction_state.py`：ready failure 与 lease expiry recovery
- **问题**：当前实现不会必然永久冻结：Host 标记 terminal failure 后停止 heartbeat，轮询最终能触发 lease recovery；但失败后没有短路径进入受控 abort，常需等待较长 lease 到期。
- **违反策略**：明确的 init/restore/load 失败应快速进入可审计失败恢复，而不是把“已知失败”伪装成“owner 可能失联”。
- **风险**：用户长时间面对冻结页面；重复轮询与恢复请求增加状态竞争。
- **建议**：ready=false 应原子记录失败原因并进入 operation-bound recovery/rollback；由后端立即给出可恢复终态或短失败 lease，而不是沿用健康 operation 的长 lease。

## 13. 普通 artifact save 可在冻结事务中绕过 transaction CAS

- **位置**：
  - `desktop_app/backend/routes/html.py`：普通 save 路由
  - `base/html_artifacts.py`：save 与 `save_if_sha256`
- **问题**：Agent mutation 路径的 `save_if_sha256()` 在 store `RLock` 下是原子的；但普通 save 若未提供 `expected_sha256`，仍可在 committed→ready 的冻结期间覆盖 artifact。
- **违反策略**：当前 operation 持有 barrier 时，artifact 的所有持久写入必须受同一事务所有权和 CAS 约束。
- **风险**：已提交 mutation 被外部保存覆盖，随后 ready ACK 却对应不同内容；base SHA 与实际文档失配。
- **建议**：interaction state 为 frozen/committed/awaiting_ready 时阻止非 operation 写入，或要求所有保存都携带 expected SHA、operation capability，并在同一锁域验证。

## 14. transaction/coordinator/lease 状态仅驻留内存

- **位置**：
  - `base/html_interaction_state.py`：全局状态存储
  - `AutoAgent/frontend_agent.py`：coordinator active/pending 状态
- **问题**：后端重启会丢失 frozen operation、lease、pending intent、coordinator epoch 和部分恢复上下文。
- **违反策略**：heartbeat/lease/recovery 应保证重启后收敛，而不是清空事务历史。
- **风险**：页面可能仍显示冻结 overlay，但后端已不认识 operation；或后端视为可用而客户端仍等待旧事务。
- **建议**：持久化最小事务日志：artifact ID、operation/request/episode、phase、state revision、base/committed SHA、lease generation/deadline、pending latest。启动时执行恢复扫描并向客户端广播权威状态。

## 15. 领域知识责任链目前仍只是通用模型调用

- **位置**：
  - `AutoAgent/frontend_agent.py`：semantic knowledge provider 调用、packet 归一化及 prompt 组装
  - `base/html_semantic_intent.py`：候选意图与知识需求数据
  - `prompt/semantic_knowledge_prompt.md`
- **问题**：尚未真正接入主 Agent 上下文、专业 Agent 路由、工具或批准知识源注册表。模型可以自报 source ID/locator；解析虽已增加 source type allowlist、fact/evidence/source linkage，并会丢弃不完整 fact、降低 grounded 状态，但仍未验证来源真实性，也未严格拒绝 fence/额外字段。系统没有程序化证明 mutation 中的领域文本来自 knowledge packet，或 uncertain 状态被页面明确展示。
- **违反策略**：Frontend Agent 只负责忠实表达；领域事实必须由合适 Agent/知识源提供，缺失或失败时不得编造。
- **风险**：页面可持久化幻觉事实、虚构引用或把 uncertain 内容呈现成确定事实。
- **建议**：由主 Agent 持有知识请求编排，按 domain/object_type 路由专业 Agent 或批准工具；source ID 由系统签发并解析到可信 registry；严格 JSON schema、拒绝额外字段；mutation 校验阶段对知识型新增文本执行 packet provenance/uncertainty 展示检查。

---

# Medium

## 16. knowledge requirement 启发式覆盖面过窄

- **位置**：`AutoAgent/frontend_agent.py`：判断 episode 是否需要 knowledge packet 的 candidate prefix 逻辑
- **问题**：主要识别 `explain_`、`compare_`、`understand_` 前缀，遗漏定义、原因、风险、来源、校验、当前值意义、关系追踪等知识型意图。
- **风险**：Frontend Agent 在缺少知识包时仍被要求补全领域内容。
- **建议**：使用结构化 intent taxonomy 和 `requires_domain_knowledge` 明确字段，不依赖字符串前缀；默认对新增领域陈述采取 fail-closed。

## 17. 跨 settling window 的重复弱点击未形成累计证据

- **位置**：
  - `desktop_app/frontend/src/components/common/HtmlPreview.tsx`：focus memory 与 draft 生命周期
  - `desktop_app/frontend/src/components/common/htmlIntent.ts`：weak click compact、candidate/confidence 推断
- **问题**：同一窗口内重复未响应 click 可升级为高置信解释意图，但第一个低置信 episode 被丢弃后，后续独立窗口的普通 click 通常不会带回前一个普通 click；现有 focus memory 主要只在后续事件已经是强信号时补入弱上下文。
- **违反策略**：重复未响应操作应跨短窗口累计为 short-stable 证据。
- **风险**：用户连续尝试同一字段仍无法触发解释，感知为 Agent“看不懂”。
- **建议**：按 artifact + semantic focus 保存有界、带 TTL 的弱点击证据；第二次同焦点、未 satisfied 的可信点击在期限内升级 episode；copy、selection-clear、focus shift、revision change 必须清空对应记忆。

## 18. 本地候选 dismiss 未推进 epoch，也未通知取消

- **位置**：`desktop_app/frontend/src/components/common/HtmlPreview.tsx`：`dismissIntentCandidate`
- **问题**：用户关闭中置信候选工具条时，主要只是清 UI 状态，没有把该动作记录为意图取消、推进 epoch 或通知后端协调器。
- **风险**：旧候选的异步结果或后续相近信号可能再次激活同一意图；审计无法区分“自然过期”和“用户明确拒绝”。
- **建议**：dismiss 生成可信 cancellation event，推进 intent epoch，清 focus/draft memory；若已有 barrier 前 active，发送匹配 identity 的 cancel。

## 19. 外部内容/revision 变化未原子清理旧意图状态

- **位置**：`desktop_app/frontend/src/components/common/HtmlPreview.tsx`：content/artifact revision 更新、draft/focus/candidate/active 状态管理
- **问题**：页面内容由外部编辑、保存或加载改变时，旧 focus memory、draft episode、candidate、latest pending 与新 revision 的切换并非一个原子动作。
- **风险**：旧 DOM ref 和旧语义上下文被应用到新文档；后续请求虽可能在 CAS 被拒绝，但仍浪费调用并产生错误候选。
- **建议**：文档 revision/generation 变化时执行统一 invalidation transaction：推进 epoch、清 draft/focus/candidate/pending、取消 barrier 前 active，并重建 refs。

## 20. runtime `restore()` 只要解析成功就可能报告成功

- **位置**：`desktop_app/frontend/src/components/common/htmlBridge.ts`：runtime state `restore()` 与 readiness report
- **问题**：当前逻辑对找不到的 ref、类型不匹配、属性未应用、focus/selection 恢复失败大多静默跳过，最后仍返回 true；因此 `restored=true` 并不证明状态真正恢复。
- **违反策略**：ready 前必须确认 restore 完成，而不是只确认 JSON 可解析。
- **风险**：页面在丢失用户滚动、焦点、选择或控件状态后解冻，且后端记录错误成功结果。
- **建议**：返回严格、结构化 restore report，包含 requested/parsed/attempted/applied/failures；任何要求恢复的条目无法解析、定位、应用或验证时 `restored=false`，并把有界失败摘要传给 Host/backend。

## 21. 隐私裁剪不足：普通控件值、PII 与 URL secret 仍可能外泄

- **位置**：
  - `desktop_app/frontend/src/components/common/htmlBridge.ts`：`controlState`、`runtimeState`、href/semantic context 采集
  - `base/html_semantic_intent.py`：文本裁剪与敏感值归一化
- **问题**：除 password/email/tel 等启发式敏感输入外，普通 input/select/textarea value 默认会进入 interaction/runtime state；自由文本中的 PII 和 URL query/fragment 中 token 也可能被发送给 Agent。
- **违反策略**：只收集完成意图判断所需的最小数据，敏感值默认不观察。
- **风险**：搜索词、内部标识、访问 token、用户输入或业务数据进入模型上下文和日志。
- **建议**：控件 value 默认不采集，仅显式 `data-spore-observe-value` 且通过敏感检查时允许；URL 只保留 scheme/host/path 或相对 path，删除 query/fragment；后端增加 PII/credential patterns、长度和字段级 allowlist，并避免把 runtime restore 私有值传给知识/Frontend Agent。

---

# 已确认正确或已显著改进的部分

1. `base/html_artifacts.py` 的 `save_if_sha256()` 在 store `RLock` 下执行原子 CAS。
2. 服务端协调器是“一个 active + 一个 latest pending”，不是 FIFO 队列。
3. 正常服务端路径中，barrier 提交后新 operation 不会直接替换旧 operation。
4. `interrupt` 与 STOP_REASON 均不等价于 commit 成功。
5. mutation 仍需通过 schema、ref、fragment/full HTML、安全、大小与 CAS 校验。
6. `no_change` 不允许携带 interrupt；mutate 要求 interrupt。
7. interaction state 已区分 `agent_stop_reason`、`operation_outcome`、`validation_result`、`artifact_commit_result`、`document_load_result`。
8. ready 请求字段当前已在 HTTP route 中要求提供；ready validation 与 transition 已在同一个 `RLock` 内完成，早期 ready ACK TOCTOU 已显著修复。
9. ready failure 后 Host 会进入 terminal failure、停止 heartbeat，轮询最终可触发 lease recovery；剩余问题是恢复延迟过长，而非必然永久冻结。
10. knowledge packet 归一化已具备 source type allowlist、fact 对象要求、evidence/source linkage、无支持 fact 丢弃和 grounded 降级，但来源真实性与责任链仍未闭环。
11. Host 已具有冻结 overlay、pointer interception、blur、`tabIndex=-1`、inert/frozen bridge 控制。

# 修复优先级建议

1. Latest Wins cancel/barrier 竞态。
2. trusted bridge capability + document-generation-bound ready。
3. 移除或授权化 force recovery。
4. 三类 refs 独立授权，禁止 semantic/presentation→mutation fallback。
5. terminal STOP_REASON 与 barrier 后不可逆事务状态。
6. 五类身份/version 必填并交叉验证。
7. frozen 期间阻止事务外写入。
8. 主 Agent / 专业 Agent / 批准来源知识链路。
9. transaction/lease/recovery 持久化与重启收敛。
