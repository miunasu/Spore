# 技能开发指南

## 技能包结构

一个标准的技能包目录结构：

```
skills/your-skill/
├── SKILL.md              # 技能说明文档（必需）
├── scripts/              # 辅助脚本（可选）
│   ├── script1.py
│   └── script2.py
├── references/           # 参考文档（可选）
│   └── reference.md
└── requirements.txt      # Python 依赖（可选）
```

## SKILL.md 格式

`SKILL.md` 是技能包的核心文档，Agent 会通过 `skill_query` 工具查询这个文档。

### 基本模板

```markdown
# 技能名称

## 功能概述

简要描述这个技能包的功能和用途。

## 使用场景

- 场景 1
- 场景 2
- 场景 3

## 工具列表

### 工具 1

**功能**：工具的功能描述

**使用方法**：
\```bash
python scripts/tool1.py --arg1 value1 --arg2 value2
\```

**参数说明**：
- `arg1`：参数 1 的说明
- `arg2`：参数 2 的说明

**示例**：
\```bash
python scripts/tool1.py --input file.txt --output result.txt
\```

### 工具 2

...

## 注意事项

使用这个技能包时需要注意的事项。
```

## 已集成技能包示例

### IDA-Skill

```
skills/IDA-Skill/
├── SKILL.md              # IDA Pro 逆向工程说明
├── API.md                # IDA Python API 参考
├── TOOLS.md              # 工具使用说明
├── docs/                 # IDA API 详细文档
│   ├── 01_core/
│   ├── 02_disasm/
│   └── ...
├── tools/                # 辅助工具脚本
│   ├── exec_ida.py
│   ├── findcrypt.py
│   └── ...
├── analysis/             # 分析技术文档
│   ├── malware-analysis.md
│   ├── deobfuscation.md
│   └── ...
└── requirements.txt
```

## 开发步骤

### 1. 创建技能包目录

```bash
mkdir skills/your-skill
cd skills/your-skill
```

### 2. 编写 SKILL.md

参考上面的模板，编写技能说明文档。

### 3. 添加辅助脚本（可选）

```bash
mkdir scripts
# 添加你的 Python 脚本
```

### 4. 添加依赖（可选）

```bash
# 创建 requirements.txt
echo "your-dependency>=1.0.0" > requirements.txt
```

### 5. 测试技能包

```bash
# 启动 Spore
python main.py

# 在对话中测试
User> 查询 your-skill 技能的使用方法
```

Agent 会自动调用 `skill_query` 工具查询你的 `SKILL.md` 文档。

## 技能包最佳实践

### 1. 文档清晰

- 使用清晰的标题和分段
- 提供具体的使用示例
- 说明参数的含义和类型

### 2. 脚本独立

- 每个脚本应该可以独立运行
- 使用命令行参数而不是硬编码
- 提供 `--help` 参数

### 3. 错误处理

- 脚本应该有良好的错误处理
- 输出清晰的错误信息
- 返回合适的退出码

### 4. 依赖管理

- 在 `requirements.txt` 中列出所有依赖
- 使用版本号固定依赖版本
- 避免使用过多的依赖

## 技能查询

Agent 可以通过 `skill_query` 工具查询技能文档：

```
@SPORE:ACTION
tool_name: skill_query
parameters:
  skill_name: your-skill
  query: 如何使用工具1
```

工具会搜索 `SKILL.md` 中包含"工具1"的相关内容并返回。

## 技能包示例

参考已有的技能包：

- [skill-creator](../skills/skill-creator/SKILL.md) - 技能包创建工具
- [IDA-Skill](../skills/IDA-Skill/SKILL.md) - IDA Pro 逆向工程

## 贡献技能包

欢迎贡献你的技能包！

1. Fork 项目
2. 在 `skills/` 目录创建你的技能包
3. 提交 Pull Request

我们会审核并合并有价值的技能包。
