# 技能开发指南（v4.0）

> [English](en/SKILLS.md)

Spore 的扩展技能遵循 Claude Skills 风格目录规范：每个技能一个文件夹，核心是 `SKILL.md`。  
主 Agent / 子 Agent 通过工具 **`skill_query`** 按需读取文档，避免把全部技能正文塞进 system prompt。

---

## 技能包结构

```text
skills/your-skill/
├── SKILL.md              # 必需：技能说明（Agent 查询入口）
├── scripts/              # 可选：可执行脚本
│   └── tool.py
├── references/           # 可选：参考资料
│   └── notes.md
└── requirements.txt      # 可选：额外 Python 依赖
```

规范详见 `skills/agent_skills_spec.md`。

当前仓库内置示例：

| 技能目录 | 用途 |
|----------|------|
| `skills/docx` | Word 创建 / 模板填充 / 分析 |
| `skills/pdf` | PDF 提取、生成、合并拆分、表单等 |
| `skills/pptx` | PowerPoint 生成与处理 |
| `skills/pcap-analyst` | PCAP 流量分析、C2/Beacon 检测、Snort/YARA 规则产出 |
| `skills/skill-creator` | 帮助创建新技能包（含脚手架脚本） |

逆向（IDA 等）能力通常通过 **主机命令工具 + 外部工具链 + 案例目录** 完成，不强制内置在 `skills/`。案例见 `example/MalwareAnalysis/`，配套技能见 [IDA-Skill](https://github.com/miunasu/IDA-Skill)（用法见 [银狐案例](SILVERFOX.md)）。

---

## SKILL.md 建议格式

```markdown
---
name: your-skill
description: "一句话说明何时应使用该技能"
---

# 技能名称

## 功能概述

...

## 使用场景

- ...

## 工具 / 脚本

### xxx

**功能**：...

**用法**：

```bash
python scripts/xxx.py --input a --output b
```

**参数**：

- `input`：...

## 注意事项

...
```

frontmatter 支持 `name` / `description`（必需），以及可选的 `license` / `metadata` / `allowed-tools`。

Agent 侧调用形态（文本协议）：

```text
@SPORE:ACTION_SINGLE_START
skill_query skill_name="your-skill"
@SPORE:ACTION_SINGLE_END
```

实现见 `base/tools.py` → `handle_skill_query`，内容检索见 `base/utils/skills.py`。

系统提示中的技能目录摘要由 `prompt_loader.collect_skills_md_features()` 扫描装配到 `prompt/prompt.md` 的 `{skills}` 占位符（仅 name + description，正文按需查询）。

---

## 开发步骤

1. 创建目录：`skills/your-skill/`
2. 编写 `SKILL.md`（name/description + 可操作说明）
3. 如需脚本：放 `scripts/`，参数化并支持 `--help`
4. 额外依赖写入 `requirements.txt`，并在运行环境中自行安装；Spore 只发现和读取技能，不会自动安装技能声明的外部依赖
5. 启动 Spore，对话中要求「查询 your-skill 技能」验证 `skill_query`

CLI 自检：

```text
User> skills
```

会打印已发现技能的功能摘要。桌面端右栏「skills」页也可直接浏览技能目录。

> 提示：桌面安装版的技能目录位于资源根下的 `skills/`（通常由 `SPORE_RESOURCE_DIR` 定位）；源码运行时则通常是仓库根的 `skills/`。若部署环境另行提供 `SKILLS_DIR`，技能和脚本应以该目录为准。

### 路径与依赖约定

- `SKILL.md` 内的脚本和资源路径应相对当前技能目录书写，例如 `scripts/tool.py`、`references/notes.md`
- 从仓库根给出可直接运行的示例时，使用 `skills/<技能名>/...`；运行时定位可使用 `SKILLS_DIR`，桌面安装版资源可使用 `SPORE_RESOURCE_DIR` 下的 `skills/`
- 禁止把开发机专用绝对路径（如盘符路径或个人 home 目录）写入技能文档或脚本默认值
- 示例输入/输出可使用清晰的占位相对路径，例如 `examples/input.docx`、`output/result.docx`
- `requirements.txt` 只是依赖声明；Spore 不会自动执行 `pip`、`npm` 或系统包安装

---

## 最佳实践

1. **写清决策表**：什么任务用哪条命令/脚本  
2. **脚本可独立运行**：不依赖 Spore 内部 import  
3. **错误信息可读**：非 0 退出码 + stderr 说明  
4. **少占上下文**：细节放 references，SKILL.md 保持可检索的精炼结构  
5. **路径相对技能目录或已声明资源根**：优先使用技能目录相对路径；需要跨技能定位时明确使用 `SKILLS_DIR` / `SPORE_RESOURCE_DIR`，不要依赖开发机绝对路径

---

## 与工具系统的关系

技能 **不是** 新的工具名称；技能教 Agent 如何组合已有工具：

- `execute_command`：跑脚本 / PowerShell（受安全守卫管控）
- `file` / `edit` / `Grep`：读写改搜
- `web_browser`：在线资料
- `multi_agent_dispatch`（long_context）：并行调研与编辑

注意：若在工具策略中禁用了某工具（见 [ARCHITECTURE.md](ARCHITECTURE.md)「工具策略」），依赖该工具的技能步骤将无法执行。

协议说明见 [ARCHITECTURE.md](ARCHITECTURE.md)「文本协议」一节。

---

## 贡献

1. Fork 仓库  
2. 在 `skills/` 添加技能包  
3. 更新本页索引（如有）  
4. 提交 PR  

相关：

- [配置说明](CONFIGURATION.md)
- [架构设计](ARCHITECTURE.md)
- [银狐案例](SILVERFOX.md)
