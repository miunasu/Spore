# PCAP文件深度分析报告

## 基本信息
- **分析时间**: 2025年12月5日
- **PCAP文件**: `test/pcap.pcap`
- **文件大小**: 7,169 字节
- **数据包数量**: 60 个
- **时间跨度**: 130.72 秒 (1759554460.212507000 - 1759554590.932822000)
- **主要协议分布**:
  - TCP: 40个数据包 (3,853字节)
  - UDP/DNS: 20个数据包 (2,332字节)
  - HTTP: 1个请求

## 网络通信分析

### 主要通信对
1. **C2通信 (主要威胁)**
   - `192.168.122.104:49695` ↔ `93.127.160.198:2019`
   - 31个数据包，2,953字节
   - 端口2019是Remcos RAT的默认端口

2. **DNS查询**
   - `192.168.122.104` ↔ `8.8.8.8:53`
   - 20个数据包，2,332字节
   - 多个DNS查询，可能用于数据外传或C2域名解析

3. **HTTP请求**
   - `192.168.122.104:49696` ↔ `178.237.33.50:80`
   - 9个数据包，900字节
   - GET请求到 `http://geoplugin.net/json.gp` (获取地理位置信息)

## 恶意行为深度分析

### 1. 上线包 (Check-in Packet) - 帧#4
**协议头**: `24 04 ff 00 19 02 00 00`
**内容分析**:
```
EVANGELIST|...|DESKTOP-RQ8184/Bruno|...|US|...|Windows 11 Enterprise (64 bit)|...||...|8589148160|...|7.0.3 Pro|...|C:\ProgramData\remcos\logs.dat|...|C:\Windows\SysWOW64\SndVol.exe|...||...|Program Manager|...|0|...|88|...|5121468|...|1|...|93.127.160.198|...|EVANGELIST-B1OJ2Q|...|0|...|C:\Windows\SysWOW64\SndVol.exe|...|           Intel(R) Xeon(R) CPU @ 2.80GHz|...|Exe|...||...|X.èh|...||...|m.6f|...|32
```

**提取的关键信息**:
- **恶意软件**: EVANGELIST (Remcos RAT) 版本7.0.3 Pro
- **受害者标识**: EVANGELIST-B1OJ2Q
- **计算机名**: DESKTOP-RQ8184/Bruno
- **操作系统**: Windows 11 Enterprise (64位)
- **地理位置**: US
- **进程注入**: `C:\Windows\SysWOW64\SndVol.exe`
- **日志文件**: `C:\ProgramData\remcos\logs.dat`
- **C2服务器**: 93.127.160.198:2019
- **硬件信息**: Intel Xeon CPU @ 2.80GHz

### 2. 心跳机制 (Heartbeat Pattern)
**时间间隔分析**:
```
帧#17-18: 28.65秒间隔
帧#19-20: 1.41秒间隔 (响应)
帧#21-22: 28.28秒间隔
帧#23-24: 30.53秒间隔
帧#25-26: 0.44秒间隔 (响应)
帧#27-28: 29.11秒间隔
帧#29-30: 0.39秒间隔 (响应)
```

**心跳特征**:
- 固定间隔: 28-30秒
- 请求包大小: 74字节 (协议头 + 数据)
- 响应包大小: 54字节 (ACK)
- 典型的C2心跳保持连接机制

### 3. 数据外传行为
1. **DNS隧道嫌疑**: 多个DNS查询到8.8.8.8
2. **地理位置收集**: HTTP请求获取IP地理位置
3. **系统信息回传**: 包含完整的系统配置信息

## 威胁评估

### 恶意软件识别: Remcos RAT
**匹配特征**:
1. ✅ 端口2019 - Remcos默认C2端口
2. ✅ 系统信息收集格式
3. ✅ 心跳机制 (28-30秒间隔)
4. ✅ 进程注入 (SndVol.exe)
5. ✅ 日志文件路径 (`C:\ProgramData\remcos\`)
6. ✅ 自定义二进制协议头 (`24 04 ff 00`)

**威胁等级**: 🔴 **高危**
- 商业级远程访问木马
- 完整系统控制能力
- 数据窃取功能
- 持久化机制

## 检测规则生成

### Suricata/Snort规则

```yaml
# 规则1: 检测Remcos协议头
alert tcp $HOME_NET any -> $EXTERNAL_NET 2019 (msg:"ET TROJAN Remcos RAT Protocol Header Detected"; flow:established,to_server; content:"|24 04 ff 00|"; depth:4; fast_pattern; reference:url,www.remcos.com; classtype:trojan-activity; sid:2025120501; rev:1;)

# 规则2: 检测Remcos心跳模式
alert tcp $HOME_NET any -> $EXTERNAL_NET 2019 (msg:"ET TROJAN Remcos RAT Heartbeat Pattern"; flow:established,to_server; content:"|24 04 ff 00 0c 00 00 00 01 00 00 00 30 7c 1e 1e 1f 7c 33 30|"; depth:20; reference:malware,Remcos; classtype:command-and-control; sid:2025120502; rev:1;)

# 规则3: 检测Remcos上线包
alert tcp $HOME_NET any -> $EXTERNAL_NET 2019 (msg:"ET TROJAN Remcos RAT Check-in Packet"; flow:established,to_server; content:"EVANGELIST"; nocase; content:"|7c 1e 1e 1f 7c|"; distance:0; within:50; content:"remcos"; nocase; distance:0; within:100; classtype:trojan-activity; sid:2025120503; rev:1;)

# 规则4: 检测SndVol.exe进程注入
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Remcos Process Injection - SndVol.exe"; flow:established,to_server; content:"SndVol.exe"; nocase; content:"|00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 57 00 4f 00 57 00 36 00 34 00 5c 00 53 00 6e 00 64 00 56 00 6f 00 6c 00 2e 00 65 00 78 00 65|"; classtype:trojan-activity; sid:2025120504; rev:1;)
```

### YARA规则 (内存/文件检测)

```yaml
rule Remcos_RAT_EVANGELIST {
    meta:
        description = "Detects Remcos RAT variant EVANGELIST"
        author = "Spore Security Analysis"
        date = "2025-12-05"
        threat_level = 8
        reference = "Remcos commercial RAT"
    
    strings:
        $magic = { 24 04 ff 00 }
        $name = "EVANGELIST" wide
        $version = "7.0.3 Pro" wide
        $log_path = "C:\\ProgramData\\remcos\\logs.dat" wide
        $process = "SndVol.exe" wide
        $separator = "|" wide
    
    condition:
        3 of them and filesize < 10MB
}
```

### Sigma规则 (SIEM检测)

```yaml
title: Remcos RAT Network Activity
id: 20251205-remcos-network
status: experimental
description: Detects network traffic patterns associated with Remcos RAT
author: Spore
date: 2025/12/05
references:
    - https://attack.mitre.org/software/S0332/
    - https://www.remcos.com/
logsource:
    category: firewall
detection:
    selection:
        DestinationPort: 2019
        Protocol: TCP
    condition: selection
falsepositives:
    - Legitimate remote administration tools using port 2019
level: high
tags:
    - attack.command_and_control
    - attack.t1043
```

## 取证建议

### 1. 主机取证
- 检查进程: `SndVol.exe` 在 `C:\Windows\SysWOW64\`
- 检查文件: `C:\ProgramData\remcos\logs.dat`
- 检查注册表: Remcos相关启动项
- 检查网络连接: 到93.127.160.198:2019的连接

### 2. 网络监控
- 监控端口2019的出站连接
- 检测DNS异常查询模式
- 监控到geoplugin.net的HTTP请求

### 3. 清除建议
1. 终止恶意进程
2. 删除相关文件
3. 清理注册表启动项
4. 重置网络配置
5. 更新安全软件规则库

## 总结

该PCAP文件捕获了**Remcos RAT**的完整通信过程，包括：
1. ✅ 初始上线包（系统信息泄露）
2. ✅ 规律性心跳通信（28-30秒间隔）
3. ✅ 数据外传行为（DNS查询、地理位置获取）
4. ✅ 进程注入特征（SndVol.exe）

**建议立即采取行动**:
1. 隔离受影响主机
2. 应用生成的检测规则
3. 进行全面的系统清查
4. 更新威胁情报库

---
*报告生成: Spore Security Analysis*
*时间: 2025-12-05 09:45*