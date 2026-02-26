---
name: docx
description: "Word文档(.docx)的创建、编辑和分析。支持：基于模板生成文档、修改现有文档、格式保留等"
---

# DOCX 文档操作技能

## 快速决策

| 任务 | 方法 |
|------|------|
| 读取文档内容 | `pandoc file.docx -o output.md` |
| **基于模板生成新文档（保持格式）** | **`template_editor.py`（推荐）** |
| 从零创建新文档 | docx-js（见下方） |

---

## 基于模板生成文档（推荐方法）

**适用场景**: 需要生成与参考文档格式完全一致的新文档（如CNCERT报告、公司模板等）

### 使用 template_editor.py

**脚本位置**: `E:\SoulRain\Project\AI\Spore\skills\docx\scripts\template_editor.py`

```bash
# 基本用法（使用绝对路径）
python E:\SoulRain\Project\AI\Spore\skills\docx\scripts\template_editor.py 模板.docx 输出.docx --replacements data.json

# 清空所有图片
python E:\SoulRain\Project\AI\Spore\skills\docx\scripts\template_editor.py 模板.docx 输出.docx --replacements data.json --clear-images
```

**注意**：
- 脚本可以直接运行，不需要先解压 docx
- 模板.docx 和 输出.docx 都使用绝对路径
- data.json 也使用绝对路径

### data.json 格式

```json
{
    "clear_images": true,
    "replacements": [
        {"find": "恶意代码名称", "replace": "恶意代码名称：NewMalware", "scope": "cell"},
        {"find": "MD5", "replace": "MD5：abc123def456", "scope": "cell"},
        {"find": "特征说明", "replace": "新的特征说明内容...", "scope": "cell_clear"},
        {"find": "逆向分析及功能描述", "replace": "新的分析内容...", "scope": "paragraph"}
    ]
}
```

### scope 选项

| scope | 用途 | 行为 |
|-------|------|------|
| `"cell"` | 表格单元格 | **部分替换**：只替换 find 的部分，保留其他内容 |
| `"cell_clear"` | 表格单元格 | **完全替换**：清空整个单元格（含图片），填入 replace 内容 |
| `"paragraph"` | 正文段落 | **部分替换**：只替换 find 的部分 |

**重要**：
- 脚本会先合并单元格内所有文本再匹配，所以即使 Word 把文本分割成多个 XML 元素也能正确匹配
- **模糊匹配**：自动处理空白字符差异（空格、换行、制表符、不间断空格等），不要求完全精确匹配

### 清空图片

两种方式：
1. 命令行参数：`--clear-images` 或 `-c`
2. JSON配置：`"clear_images": true`

**注意**：对于包含图片的单元格（如"特征说明"），使用 `"scope": "cell_clear"` 可以清空图片并替换文本。

### 工作原理

Word文档会把文本分割成多个XML元素（如"2025年"可能被拆成"202"+"5"+"年"），简单字符串替换会失败。

`template_editor.py` 在单元格/段落级别替换，绕过这个问题。

### 保留的格式

✅ 字体（宋体、Arial等）  
✅ 字号和样式  
✅ 表格列宽和单元格格式  
✅ 页边距和布局  
✅ 页眉页脚  
✅ 图片

### 完整示例

假设要基于 `参考报告.docx` 生成新的 `SpeedMaster报告.docx`：

1. 创建 `replacements.json`:
```json
{
    "replacements": [
        {"find": "SearchHijack", "replace": "SpeedMaster", "scope": "cell"},
        {"find": "e35dbe7c516b131a8578e94ad4fb7d1a", "replace": "新的MD5值", "scope": "cell"},
        {"find": "2025年12月10日", "replace": "2025年12月15日", "scope": "cell"},
        {"find": "该样本为crx格式", "replace": "该样本为恶意浏览器插件...", "scope": "cell"}
    ]
}
```

2. 运行:
```bash
python E:\SoulRain\Project\AI\Spore\skills\docx\scripts\template_editor.py E:\工作目录\参考报告.docx E:\工作目录\SpeedMaster报告.docx -r E:\工作目录\replacements.json
```

---

## 从零创建文档 (docx-js)

**适用场景**: 没有参考模板，需要从头创建

1. **必须先阅读**: [`docx-js.md`](docx-js.md)
2. 编写 JavaScript 创建文档
3. 中文文档必须设置字体为"宋体"

---

## 读取文档内容

```bash
# 转为Markdown
pandoc document.docx -o output.md

# 查看原始XML结构
python ooxml/scripts/unpack.py document.docx unpacked_dir
# 然后查看 unpacked_dir/word/document.xml
```

---

## 高级：直接编辑XML

如果 `template_editor.py` 无法满足需求，可以直接操作XML：

```bash
# 1. 解压
python ooxml/scripts/unpack.py 模板.docx unpacked

# 2. 编辑（见 ooxml.md）

# 3. 打包
python ooxml/scripts/pack.py unpacked 输出.docx
```

详见 [`ooxml.md`](ooxml.md)

---

## 常用命令

```bash
# 模板生成（推荐）- 使用绝对路径
python E:\SoulRain\Project\AI\Spore\skills\docx\scripts\template_editor.py 模板.docx 输出.docx -r data.json

# 解压/打包
python E:\SoulRain\Project\AI\Spore\skills\docx\ooxml\scripts\unpack.py input.docx output_dir
python E:\SoulRain\Project\AI\Spore\skills\docx\ooxml\scripts\pack.py input_dir output.docx

# 转Markdown
pandoc input.docx -o output.md
```
