# 🦊 银狐（SilverFox）恶意软件分析指南

> [English](en/SILVERFOX.md)

> 适用于 Spore 4.1。请使用桌面或 CLI 启动后按下列提示复现；样本与输出见 `example/MalwareAnalysis/SliverFox/`。

## 📋 准备工作

### 1. 安装软件

从 [Release 页面](https://github.com/miunasu/Spore/releases) 下载安装包并完成安装。

### 2. 准备分析材料

准备分析银狐所需的[样本文件](../example/MalwareAnalysis/SliverFox/SliverFox1/malware/)。

### 3. 配置 LLM

在安装目录的 `.env` 文件中填写以下配置（变量说明见 [配置文档](CONFIGURATION.md)）：

```env
# 以 OpenAI 兼容接口为例
LLM_SDK=openai
OPENAI_API_KEY=your_api_key_here
OPENAI_API_URL=your_api_url_here
OPENAI_MODEL=your_model_name

# Token 限制（根据使用的模型调整）
MAX_OUTPUT_TOKENS=8000        # LLM 单次输出的最大 token 数
CONTEXT_MAX_TOKENS=128000     # 上下文最大 token 数
```

Anthropic 接口则改用 `LLM_SDK=anthropic` + `ANTHROPIC_API_KEY` / `ANTHROPIC_API_URL` / `ANTHROPIC_MODEL`。

### 4. 配置 IDA-Skill

下载 [最新版 IDA-Skill](https://github.com/miunasu/IDA-Skill)，并放入安装目录的 `skills/` 文件夹。

编辑 `skills/IDA-Skill/config.json`，填写 IDA 目录中 `idat.exe` 的绝对路径。

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
```

分析过程中可通过左栏日志、右栏 Agent 监控与 TODO 栏观察进度；报告默认产出在 `output/` 目录。

---

## 📝 注意事项

- 确保样本文件路径正确且可访问
- **不要运行样本本体**：分析基于静态逆向与已有记录文件；安全 Agent（`SECURITY_AGENT_MODE=full`，默认）会对可疑执行命令熔断
- 分析过程可能需要较长时间，请耐心等待
- 若 IDA 目录同时存在 `idat.exe` 与 `idat64.exe`，请填写 `idat.exe`，因为该样本为 32 位
- 建议配合角色 `characters/Malware analyst.md`（`char select` 或桌面设置中选择）
