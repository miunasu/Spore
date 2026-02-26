---
name: pcap-analyst
description: 专门用于网络流量深度分析、恶意行为检测和Payload取证的专业技能模块。通过时序分析、编码还原和行为特征提取，识别隐藏在加密和混淆流量中的攻击行为模式（心跳检测、Beacon识别、C2通信分析），并生成Snort/YARA检测规则。
---

# PCAP流量分析工具包 (PCAP Analysis Toolkit)

## 概述

PCAP流量分析工具包是一个专门用于网络流量深度分析、恶意行为检测和Payload取证的专业技能模块。该工具包帮助安全分析师识别隐藏在加密和混淆流量中的攻击行为模式，通过时序分析、编码还原和行为特征提取，发现传统特征检测无法识别的威胁。

核心理念：攻击者可以加密流量、混淆指令，但无法隐藏**行为模式（Behavior Patterns）**。

## 功能特性

### 1. 时序行为分析
- **心跳检测（Heartbeat Detection）**：识别僵尸网络和C2客户端的定期通信
- **Beacon识别**：发现规律性的回连行为
- **时间间隔分析**：检测机械式的规律性通信模式
- **抖动检测（Jitter Detection）**：识别带有时间扰动的高级隐蔽通信

### 2. 上线行为识别
- **系统信息回传检测**：识别恶意软件的初次上线包
- **MachineID/GUID提取**：发现受害者唯一标识符
- **系统信息枚举**：检测包含OS版本、用户名、杀软列表的流量

### 3. 攻击指令分析
- **下行流量分析**：识别C2服务器下发的命令
- **请求/响应不对称检测**：发现异常的流量模式
- **关键字特征匹配**：检测WebShell和远程执行指令
- **编码识别**：识别Base64编码的PE文件和Shellcode

### 4. Payload深度取证
- **十六进制解码**：还原混淆的载荷内容
- **熵值计算**：识别加密内容和Shellcode
- **协议头识别**：发现自定义C2协议
- **多层编码解析**：支持Base64、ROT13、XOR等常见编码

### 5. 规则生成
- **Snort规则自动生成**：基于发现的特征生成IDS规则
- **YARA规则生成**：针对提取的Payload创建检测规则
- **高精度特征提取**：生成可复用的检测签名


## 详细使用指南

### 深度场景分析：如何识别"隐形"的恶意流量

#### 场景 A: 识别"心跳"与"Beacon" (Heartbeat & Beaconing)
**特征原理**: 僵尸网络或 C2 客户端为了保持存活，会定期发送数据包。这种**“机械式的规律性”**是识别的关键。

**1. 怎么分析思路 (Analysis Logic)**
* **时序规律**: 攻击者设置的 `sleep(60)` 会导致数据包间隔（Delta Time）呈现某种正态分布（例如都在 60s 左右波动）。
* **载荷大小一致性**: 心跳包通常只包含这就“我还在”，所以 Payload 长度通常固定，或者变化极小。

**2. Tshark 筛选与验证技巧 (Tshark Tactics)**

**第一步：计算数据包间隔 (Delta Time)**

你需要提取同一个源 IP 发出的数据包与上一个包的时间差。

```bash
# 重点关注 frame.time_delta_displayed
tshark -r target.pcap -Y "ip.src == 192.168.1.100 && tcp.dstport == 443" -T fields -e frame.time_epoch -e frame.len -e frame.time_delta_displayed
```

**Agent 判定逻辑**:
- 如果 `frame.time_delta_displayed` 的数值高度集中（例如连续出现 5.0s, 5.1s, 4.9s），且 `frame.len` 几乎不变，判定为机器心跳。

**第二步：发散性筛选 (Jitter 检测)**

高级攻击者会加入"抖动"（Jitter）来规避检测（例如 sleep 60s ± 10s）。

策略：即使时间有抖动，长连接的会话指纹通常不变。筛选 TCP 会话时长极长的流。

```bash
# 筛选持续时间超过 1小时的 TCP 会话
tshark -r target.pcap -q -z conv,tcp -Y "tcp.time_relative > 3600"
```

#### 场景 B: 识别"上线"与"系统信息回传" (Check-in & System Info)

**特征原理**: 恶意软件运行后的第一件事是告诉服务器“我感染成功了”，并附带受害者信息（用户名、OS版本、杀软列表）。

**1. 怎么分析思路**

- **独特标识符 (UID)**: 第一次请求中通常包含生成的 MachineID 或 GUID。
- **信息枚举**: 关注包含 Win10, x64, Admin, AV name 等关键词的各种编码形式。

**2. Tshark 筛选与载荷提取**

**策略一：寻找"异常长"的第一个请求**

上线包通常比心跳包大，因为它携带了系统信息。

```bash
# 筛选 HTTP POST 请求，且 Content-Length 较大，提取 Body 前 100 字节
tshark -r target.pcap -Y "http.request.method == POST && http.content_length > 200" -T fields -e ip.dst -e text
```

**策略二：十六进制解码与模式匹配**

有些上线包是自定义二进制协议。

```bash
# 提取 Payload 的 Hex
tshark -r target.pcap -Y "udp.dstport == 53" -T fields -e data
```

**Agent 发散操作**:
- 如果 Payload 开头是固定的（例如 `0x11223344`），这是协议头
- 如果 Payload 后半部分看似乱码但可见字符较多，尝试 Base64 解码或单字节 XOR 爆破
- 很多上线包只是简单的异或加密

#### 场景 C: 识别"攻击者指令" (Attacker Instructions)

**特征原理**: 这是 C2 服务器发给受害者的命令（Downstream Traffic）。通常混在 HTTP Response 或 TCP PUSH 标志位的数据中。

**1. 怎么分析思路**

- **请求/响应不对称**: 受害者发了一个很小的心跳，服务器却回了一个很大的包（可能包含了下载新木马的指令或 Shellcode）
- **关键字特征**: 攻击指令通过 WebShell 传输时，常包含 `cmd`, `whoami`, `powershell`, `wget`, `curl`
- **编码特征**: 看到 `TVqQAAMAAAAEAAAA`（Base64 编码的 PE 文件头 MZ）出现在流量中，意味着在下发恶意文件

**2. Tshark 深度提取指令**

**技巧一：追踪流并提取响应体**

不要只看请求，指令在响应里！

```bash
# 查找服务器响应包中包含特定二进制头或脚本特征的流
tshark -r target.pcap -Y "ip.src == <C2_IP> && (data contains 'whoami' || data contains 'exec')" -T fields -e data
```

**技巧二：基于 Payload 熵值 (Entropy) 的筛选**

加密指令或 Shellcode 的信息熵很高（看起来非常随机），而普通文本熵值较低。

虽然 Tshark 原生不算熵，但你可以让 Agent 提取 data 字段后，自己计算熵值。

**Agent 逻辑**:
1. 使用 `-e data` 提取 Hex
2. 计算字符串的随机性
3. 如果某段流量即使没有明显关键字，但熵值极高且去往高危端口 → 加密指令下发

---

## Agent 自我训练提示 (Self-Correction Prompt)

在处理每一个 PCAP 时，问自己：

1. **"这是谁发起的？"**
   - 是受害者主动去连 C2（上线/心跳），还是 C2 主动连受害者（Bind Shell）？

2. **"为什么是这个频率？"**
   - 间隔是随机的还是固定的？
   - 如果是固定的，一定是机器行为

3. **"这串乱码能解开吗？"**
   - 尝试 Base64
   - 尝试 ROT13
   - 尝试 XOR 0xFF
   - 攻击者也是懒惰的，很多指令只是简单的 Base64

---

## 高级实战：已知恶意 IP 的特征提取与规则固化
如果已知其他恶意特征，分析流程同下文，不变！

### 任务背景 (Mission Context)
**现状**: 你已经锁定了一个恶意 IP（例如 C2 服务器 IP `10.10.10.10`）。
**痛点**: 攻击者随时可能更换 IP。单纯封锁 IP 是短视的。
**目标**: 从该 IP 的通信中提取**“流量指纹”**（Traffic Fingerprint），编写出无论 IP 如何变化都能生效的 Snort/Suricata 规则。

### 标准化作业流程 (SOP)

#### 第一阶段：提纯流量 (Isolation)
首先，必须剔除背景噪声，只看受害者与该恶意 IP 的所有交互。

* **Tshark 核心指令**:
    ```bash
    # 提取双向流量，按时间排序
    tshark -r input.pcap -Y "ip.addr == 10.10.10.10" -w malicious_only.pcap
    ```
* **Agent 思考点**:
    * 流量是单向的还是双向的？（双向意味着连接成功，风险极高）。
    * 主要涉及什么协议？(TCP? UDP? HTTP?)

#### 第二阶段：寻找"不变的特征" (Invariant Hunting)
这是最核心的一步。你要找的不是“变量”（如随机生成的 Session ID），而是“常量”（硬编码在恶意软件里的特征）。

**路径 A: 如果是 HTTP 流量**
攻击者通常会重用 Web 框架或特定的 URI 结构。

1.  **分析 User-Agent 和 URI**:
    ```bash
    tshark -r malicious_only.pcap -Y "http.request" -T fields -e http.user_agent -e http.request.uri -e http.host
    ```
2.  **特征提取逻辑**:
    * **URI 特征**: 所有的请求是否都指向 `/api/v1/update.php`？或者 URI 是否总是由 16 位随机字符组成但后缀固定？
    * **Header 特征**: 是否包含拼写错误的 Header？例如 `Reffer: google.com` (Referer 拼错了)。
    * **Host 特征**: 如果是直接用 IP 访问 (`Host: 10.10.10.10`) 而不是域名，这在现代网络中非常可疑。

**路径 B: 如果是 TCP/UDP 私有协议 (Raw Payloads)**
恶意软件常用自定义的二进制协议，头部通常有 Magic Bytes。

1.  **提取 Payload Hex**:
    ```bash
    # 提取 TCP 数据段的前 8 个字节 (通常是协议头)
    tshark -r malicious_only.pcap -Y "tcp.len > 0" -T fields -e data | cut -c 1-16
    ```
2.  **寻找重复模式**:
    * 如果发现所有包都以 `48 45 4c 4f` (HELO) 或 `00 00 00 01` 开头，这就是**协议头指纹**。

#### 第三阶段：规则固化 (Rule Crystallization)
将 Tshark 看到的特征翻译成检测规则。

**场景演示 1：HTTP 特征提取**
* **Tshark 发现**:
    * URI: `/admin/login.php`
    * User-Agent: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)` (极其古老的 UA，常见于老旧扫描器或特定木马)
* **Agent 生成规则 (Suricata)**:
    ```yaml
    # 重点：不要写死 IP，要匹配特征
    alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Malware Known User-Agent Pattern"; flow:established,to_server; content:"/admin/login.php"; http_uri; content:"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"; http_user_agent; classtype:trojan-activity; sid:300001;)
    ```

**场景演示 2：TCP 二进制特征提取**
* **Tshark 发现**:
    * 恶意 IP `10.10.10.10` 的 TCP 流量，Payload 前 4 字节总是 `deadbeef` (Hex)。
* **Agent 生成规则 (Snort)**:
    ```snort
    # 提取 Hex 特征，offset 0 depth 4 表示只匹配开头4字节，提高性能
    alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Malware Binary Protocol - Magic Bytes Detected"; flow:established,to_server; content:"|de ad be ef|"; offset:0; depth:4; classtype:command-and-control; sid:300002;)
    ```

#### 第四阶段：验证与误报排除 (Validation)
在提交规则前，Agent 必须进行自我验证。

* **验证命令**: 使用生成的特征反向过滤 PCAP，看是否只命中了恶意流量。
    ```bash
    # 验证 Hex 特征是否过于宽泛
    tshark -r input.pcap -Y "data contains de:ad:be:ef"
    ```
* **Agent 检查清单**:
    1.  特征是否太短？（如 `00 00` 会匹配到无数正常流量，**禁止**作为单一特征）。
    2.  特征是否常见？（如 `GET / HTTP/1.1` 是无效特征）。
    3.  是否结合了端口？（如果该协议只跑在 443 端口，加上 `port 443` 条件更精准）。

### Agent 快捷指令模板 (Prompt Template)

当用户给你一个恶意 IP 时，按照以下步骤输出：

1.  **流量隔离**: "我已将 IP `[IP]` 的相关流量提取完毕，共发现 `[数字]` 个数据包。"
2.  **特征识别**:
    * "通信协议分析：主要是 `[协议]`。"
    * "发现固定特征：所有请求的 Payload 开头均为 `[Hex/String]`。"
    * "异常行为：心跳间隔固定为 `[秒]`。"
3.  **规则产出**:
    * "基于上述特征，我构建了以下 Suricata 规则，即使攻击者更换 IP 也能检测："
    * `[规则代码]`
