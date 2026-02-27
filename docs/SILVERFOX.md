# 🦊 SilverFox 恶意软件分析指南

## 📋 准备工作

### 1. 安装软件

从 [Release 页面](https://github.com/miunasu/Spore/releases) 下载安装包并完成安装。

### 2. 准备分析材料

准备分析银狐所需的[样本文件](../example/MalwareAnalysis/SliverFox/SliverFox1/malware/)。

### 3. 配置 LLM

在 `.env` 文件中填写以下配置：

```env
# LLM API 配置
LLM_API_KEY=your_api_key_here
LLM_API_URL=your_api_url_here

# Token 限制配置（根据使用的模型调整）
MAX_OUTPUT_TOKENS=8000       # LLM 单次输出的最大 token 数
CONTEXT_MAX_TOKENS=128000     # 上下文最大 token 数
```

### 4. 配置 IDA-Skill

编辑 [IDA-Skill 配置文件](../skills/IDA-Skill/config.json)，填写 IDA 目录中的 `idat.exe` 绝对路径。

示例：
```json
{
  "ida_path": "C:\\Program Files\\IDA Pro\\idat.exe"
}
```

---

## 🚀 开始分析

### 启动 Spore

双击 `Spore.exe` 启动程序。

### 发送分析指令

向 Spore 发送以下分析指令（根据实际路径调整）：

```
我在 path\to\malware 为你准备了样本，帮我分析。

样本目录包含以下文件：
- 主样本 i64 文件：libexpat.dll.i64（经过 REAI 处理）
- 样本本体：libexpat.dll
- 持久化记录文件夹：persistence_report_b0c27ebf2b0814f7150864d505a8f478_byovd_drv_20260202_200131
- 恶意软件配置文件：box.ini
- 后续通信内容：data 子文件夹

请分析样本并生成完整的样本分析报告。
```
---

## 📝 注意事项

- 确保样本文件路径正确且可访问
- 分析过程可能需要较长时间，请耐心等待
- 若IDA目录同时存在idat.exe与idat64.exe，请填写idat.exe，因为该样本为32位