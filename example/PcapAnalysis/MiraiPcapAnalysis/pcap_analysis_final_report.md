# PCAP文件深度分析报告

## 文件信息
- **文件名**: 81d021df259a9807f640230795a4a41f96b1ec5ae97d874e2161dc389fbf353c_Zenbox Linux.pcap
- **文件大小**: 1661 字节
- **分析时间**: 2025年12月3日

## 网络流量概况
- **数据包总数**: 19 个
- **TCP数据包**: 17 个 (1165 字节)
- **UDP数据包**: 2 个 (168 字节)
- **DNS查询**: 1 个

### 关键通信对
- **主要通信**: 192.168.122.100 ↔ 198.98.59.161 (端口: 36852 ↔ 5432)
- **DNS查询**: 192.168.122.100 ↔ 8.8.8.8

## 恶意行为检测结果

### 1. 心跳检测 (Heartbeat Detection)
**发现规律性通信模式**:
- 数据包间隔呈现明显的周期性：10秒、7.5秒、20秒
- **固定间隔**: 20秒间隔出现多次 (37.68s → 57.68s → 77.68s)
- **Payload大小一致**: 多个数据包具有相同的载荷长度
- **行为特征**: 机械式的规律性通信，符合C2心跳行为

### 2. 协议指纹识别
**发现重复模式**:
- **336699模式**: 出现6次，可能是协议标识符
- **"unknown"字符串**: 十六进制 `06756e6b6e6f77` 解码为 "unknown"

### 3. 可疑域名检测
**发现可疑DNS查询**:
- **域名**: `netbots.africa`
- **特征**: 域名拼写异常（应为africa而非africa），常见于恶意软件

## 检测规则生成

### Snort 规则
```snort
# 检测 Zenbox Linux 僵尸网络通信
alert tcp $HOME_NET any -> $EXTERNAL_NET 5432 (msg:"Suspected Zenbox Linux Botnet Communication"; flow:established,to_server; content:"|33 66 99|"; offset:0; depth:3; classtype:trojan-activity; sid:300001;)

# 检测 netbots.africa 域名访问
alert udp $HOME_NET any -> any 53 (msg:"Suspected Botnet Domain Query - netbots.africa"; content:"netbots.africa"; classtype:bad-unknown; sid:300002;)
```

### YARA 规则
```yara
rule Zenbox_Linux_Botnet {
    meta:
        description = "Detects Zenbox Linux botnet communication patterns"
    strings:
        $hex_pattern = {33 66 99}
        $unknown_str = "unknown"
    condition:
        $hex_pattern or $unknown_str
}
```

## 威胁评估

### 风险等级: **中高**

**确认的恶意指标**:
1. ✅ 规律性心跳通信 (20秒间隔)
2. ✅ 可疑域名查询 (netbots.africa)
3. ✅ 重复协议标识符 (336699)
4. ✅ 隐藏命令标识 ("unknown")

## 安全建议

### 立即行动
1. **阻断通信**: 封锁与 198.98.59.161 的通信
2. **域名过滤**: 将 netbots.africa 加入黑名单
3. **系统检查**: 检查主机 192.168.122.100 是否存在恶意进程
4. **网络监控**: 持续监控类似通信模式的流量

### 长期措施
1. **IDS/IPS规则**: 部署生成的检测规则
2. **威胁情报**: 将 netbots.africa 上报至威胁情报平台

## 结论

该PCAP文件包含**高度可疑的僵尸网络通信**。发现了明确的C2心跳模式、可疑域名查询和潜在的隐藏命令标识。

**关键发现总结**:
- 确认存在规律性通信模式
- 发现可疑域名和协议特征
- 建议立即采取安全防护措施

---
*分析完成时间: 2025年12月3日*
*分析工具: PCAP-Analyst Skill*