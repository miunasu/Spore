# 配置说明

## 主要配置项（`.env`）

### LLM 配置

```env
# LLM SDK 选择
LLM_SDK=openai                          # openai / anthropic

# OpenAI / DeepSeek 配置
OPENAI_API_KEY=your_key
OPENAI_BASE_URL=https://api.deepseek.com  # 可选，用于兼容 DeepSeek 等
MODEL_MAIN=deepseek-chat                # 主 Agent 模型
MODEL_SUPERVISOR=deepseek-chat          # 监督 Agent 模型

# Anthropic Claude 配置
ANTHROPIC_API_KEY=your_key
MODEL_MAIN=claude-3-5-sonnet-20241022   # 主 Agent 模型

# 温度和 Token 限制
TEMPERATURE_MAIN=0.0                    # 主 Agent 温度
MAX_TOKENS_MAIN=8000                    # 主 Agent 最大输出 Token
```

### 启动模式

```env
LAUNCH_MODE=desktop                     # cli / desktop
```

### 上下文管理

```env
CONTEXT_MODE=auto                       # auto / strong_context / long_context
MAX_CONTEXT_TOKENS=120000               # 最大上下文 Token
RULE_REMINDER_INTERVAL=10               # 规则提醒间隔（LLM 回复次数）
```

**模式说明：**
- `strong_context`：强上下文关联模式，适合需要精确推理的任务
- `long_context`：长上下文处理模式，适合大文本处理、大项目编程
- `auto`：根据任务自动判断使用哪种模式

### 角色系统

```env
CHARACTER_RECOMMEND_INTERVAL=5          # 角色推荐间隔（用户消息次数）
```

### 桌面模式

```env
DESKTOP_API_HOST=127.0.0.1
DESKTOP_API_PORT=8765
DESKTOP_CONFIRM_ENABLED=true            # 文件修改确认
```

## 配置方式

### 方式 1：配置文件

1. 编辑 `.env` 文件，填写配置项
2. 重启应用

### 方式 2：GUI 设置

1. 启动应用
2. 点击右侧"设置"按钮
3. 在"环境配置"页面填写配置
4. 保存后自动生效

## 常见问题

### Q: 如何切换 LLM 提供商？

修改 `LLM_SDK` 和对应的 API Key：

```env
# 使用 OpenAI
LLM_SDK=openai
OPENAI_API_KEY=sk-...

# 使用 Anthropic Claude
LLM_SDK=anthropic
ANTHROPIC_API_KEY=sk-ant-...

# 使用 DeepSeek
LLM_SDK=openai
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.deepseek.com
MODEL_MAIN=deepseek-chat
```

### Q: 如何禁用文件修改确认？

设置 `DESKTOP_CONFIRM_ENABLED=false`

### Q: 如何调整上下文长度？

修改 `MAX_CONTEXT_TOKENS`，建议值：
- GPT-4：120000
- Claude：180000
- DeepSeek：120000
