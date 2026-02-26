"""
基于模板编辑文档的高级工具

解决 Word 文档中文本被分割成多个 XML 元素的问题。
支持清空图片、在单元格/段落级别替换内容。

用法:
    python template_editor.py <template.docx> <output.docx> --replacements <data.json>
    python template_editor.py <template.docx> <output.docx> --replacements <data.json> --clear-images

data.json 格式:
{
    "clear_images": true,  // 可选：清空所有图片
    "replacements": [
        {"find": "文本片段", "replace": "新文本", "scope": "cell"},
        {"find": "特征说明", "replace": "新内容", "scope": "cell_clear"}  // cell_clear会清空整个单元格包括图片
    ]
}

scope 选项:
- "cell": 替换单元格中的文本，保留图片
- "cell_clear": 清空整个单元格（包括图片），然后填入新文本
- "paragraph": 替换段落文本

模糊匹配:
- 自动处理空白字符差异（空格、换行、制表符等）
- 自动处理 Unicode 特殊字符（如不间断空格 \\xa0）
- 支持子串匹配，不要求完全匹配
"""

import sys
import os
import json
import shutil
import argparse
import re
from pathlib import Path

# Windows 控制台 UTF-8 输出
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# 使用标准 minidom 而不是 defusedxml，因为 defusedxml 的 SAX 解析器
# 在处理某些 XML 实体时有问题（如 &amp;&amp; 会被截断）
from xml.dom import minidom


def clear_all_images(temp_dir, dom=None):
    """删除文档中的所有图片（文件+XML引用）"""
    count = 0
    
    # 1. 删除 media 文件夹里的图片文件
    media_dir = temp_dir / 'word' / 'media'
    if media_dir.exists():
        for img_file in media_dir.iterdir():
            if img_file.is_file():
                img_file.unlink()
                count += 1
    
    # 2. 删除 XML 里的图片引用（避免"无法显示该图片"）
    if dom is not None:
        # 删除 w:drawing 元素
        for drawing in list(dom.getElementsByTagName("w:drawing")):
            drawing.parentNode.removeChild(drawing)
        # 删除 w:pict 元素（旧版格式）
        for pict in list(dom.getElementsByTagName("w:pict")):
            pict.parentNode.removeChild(pict)
    
    print(f"  已清除 {count} 个图片")
    return count


def remove_drawings_from_node(node):
    """从节点中移除所有图片/绘图元素"""
    # 查找并移除 w:drawing 元素
    drawings = node.getElementsByTagName("w:drawing")
    for drawing in list(drawings):
        drawing.parentNode.removeChild(drawing)
    
    # 查找并移除 w:pict 元素（旧版图片格式）
    picts = node.getElementsByTagName("w:pict")
    for pict in list(picts):
        pict.parentNode.removeChild(pict)


def normalize_text(text):
    """标准化文本，处理空白字符和特殊字符差异
    
    - 将所有空白字符（空格、制表符、换行、不间断空格等）统一为单个空格
    - 移除首尾空白
    - 处理 Unicode 特殊字符
    """
    if not text:
        return ""
    # 将各种空白字符替换为普通空格
    # \xa0 是不间断空格，\u00a0 也是
    text = re.sub(r'[\s\xa0\u00a0\u200b]+', ' ', text)
    return text.strip()


def fuzzy_find(cell_text, find_text):
    """模糊查找文本，忽略空白字符差异
    
    Returns:
        bool: 是否找到匹配
    """
    norm_cell = normalize_text(cell_text)
    norm_find = normalize_text(find_text)
    return norm_find in norm_cell


def fuzzy_replace(cell_text, find_text, replace_text):
    """模糊替换文本
    
    由于原始文本可能有不同的空白字符，我们需要找到实际匹配的位置
    """
    norm_cell = normalize_text(cell_text)
    norm_find = normalize_text(find_text)
    
    if norm_find not in norm_cell:
        return cell_text
    
    # 简单情况：直接替换标准化后的文本              
    # 这会丢失原始格式，但对于大多数情况是可接受的
    return norm_cell.replace(norm_find, replace_text, 1)


def clear_cell_content(cell, dom):
    """清空单元格的所有内容，只保留一个空段落"""
    # 移除所有图片
    remove_drawings_from_node(cell)
    
    # 获取所有段落
    paras = list(cell.getElementsByTagName("w:p"))
    
    if not paras:
        return None
    
    # 保留第一个段落，清空其内容
    first_para = paras[0]
    
    # 清空第一个段落中的所有 w:r 元素（保留 w:pPr 段落属性）
    for r in list(first_para.getElementsByTagName("w:r")):
        first_para.removeChild(r)
    
    # 删除其他段落
    for para in paras[1:]:
        para.parentNode.removeChild(para)
    
    return first_para


def create_text_run(dom, text):
    """创建一个包含文本的 w:r 元素"""
    r = dom.createElement("w:r")
    t = dom.createElement("w:t")
    # 如果文本包含前导/尾随空格，需要设置 xml:space="preserve"
    if text and (text[0].isspace() or text[-1].isspace()):
        t.setAttribute("xml:space", "preserve")
    t.appendChild(dom.createTextNode(text))
    r.appendChild(t)
    return r


def find_and_replace_in_cell(dom, find_text, replace_text, clear_cell=False, replace_all=False):
    """在表格单元格中查找并替换文本
    
    Args:
        dom: minidom.Document 对象
        find_text: 要查找的文本（会在合并后的单元格文本中搜索，支持模糊匹配）
        replace_text: 替换后的完整文本
        clear_cell: 是否清空整个单元格（包括图片）
        replace_all: 是否替换所有匹配的单元格（默认只替换第一个）
    """
    cells = dom.getElementsByTagName("w:tc")
    found_count = 0
    
    for cell in cells:
        # 获取单元格的所有文本节点
        t_nodes = list(cell.getElementsByTagName("w:t"))
        if not t_nodes:
            continue
            
        # 合并所有文本（处理 Word 分割问题）
        cell_text = ''.join(t.firstChild.nodeValue if t.firstChild else '' for t in t_nodes)
        
        # 检查是否包含目标文本（使用模糊匹配）
        if fuzzy_find(cell_text, find_text):
            if clear_cell:
                # cell_clear 模式：清空整个单元格，然后添加新内容
                first_para = clear_cell_content(cell, dom)
                if first_para:
                    # 按换行符分割文本，每行创建一个段落
                    lines = replace_text.split('\n')
                    # 第一行添加到第一个段落
                    if lines:
                        r = create_text_run(dom, lines[0])
                        first_para.appendChild(r)
                    # 后续行创建新段落
                    for line in lines[1:]:
                        new_para = dom.createElement("w:p")
                        r = create_text_run(dom, line)
                        new_para.appendChild(r)
                        cell.appendChild(new_para)
            else:
                # cell 模式：只替换匹配的部分（使用模糊替换）
                new_text = fuzzy_replace(cell_text, find_text, replace_text)
                
                # 设置第一个文本节点的内容
                if t_nodes[0].firstChild:
                    t_nodes[0].firstChild.nodeValue = new_text
                else:
                    t_nodes[0].appendChild(dom.createTextNode(new_text))
                
                # 清空其他文本节点
                for t in t_nodes[1:]:
                    if t.firstChild:
                        t.firstChild.nodeValue = ""
            
            found_count += 1
            if not replace_all:
                return True
    
    return found_count > 0


def find_and_replace_row_content(dom, find_text, replace_text):
    """找到包含 find_text 的单元格所在行，替换该行下一个单元格的内容
    
    适用于表格中"标题|内容"的布局，通过标题找到对应的内容单元格并替换
    同时会清空后续行中第一个单元格为空的行（处理跨行内容）
    
    Args:
        dom: minidom.Document 对象
        find_text: 要在标题单元格中查找的文本
        replace_text: 替换内容单元格的新文本
    """
    rows = list(dom.getElementsByTagName("w:tr"))
    
    for row_idx, row in enumerate(rows):
        cells = list(row.getElementsByTagName("w:tc"))
        if len(cells) < 2:
            continue
        
        # 检查每个单元格
        for i, cell in enumerate(cells[:-1]):  # 不检查最后一个单元格
            t_nodes = list(cell.getElementsByTagName("w:t"))
            cell_text = ''.join(t.firstChild.nodeValue if t.firstChild else '' for t in t_nodes)
            
            if fuzzy_find(cell_text, find_text):
                # 找到了标题单元格，替换下一个单元格的内容
                import sys
                print(f"    找到 '{find_text}' 在 Row {row_idx}, Cell {i}", flush=True)
                sys.stdout.flush()
                content_cell = cells[i + 1]
                
                # 清空内容单元格
                first_para = clear_cell_content(content_cell, dom)
                if first_para:
                    # 按换行符分割文本，每行创建一个段落
                    lines = replace_text.split('\n')
                    if lines:
                        r = create_text_run(dom, lines[0])
                        first_para.appendChild(r)
                    for line in lines[1:]:
                        new_para = dom.createElement("w:p")
                        r = create_text_run(dom, line)
                        new_para.appendChild(r)
                        content_cell.appendChild(new_para)
                
                # 清空后续行中第一个单元格为空的行（跨行内容）
                for next_row in rows[row_idx + 1:]:
                    next_cells = list(next_row.getElementsByTagName("w:tc"))
                    if len(next_cells) < 2:
                        break
                    # 检查第一个单元格是否为空
                    first_cell_t = next_cells[0].getElementsByTagName("w:t")
                    first_cell_text = ''.join(t.firstChild.nodeValue if t.firstChild else '' for t in first_cell_t)
                    if normalize_text(first_cell_text) == '':
                        # 第一个单元格为空，清空第二个单元格
                        print(f"    清空跨行内容单元格")
                        clear_cell_content(next_cells[1], dom)
                    else:
                        # 遇到非空标题单元格，停止
                        break
                
                return True
    
    return False


def find_and_replace_in_paragraph(dom, find_text, replace_text, replace_all=False):
    """在段落中查找并替换文本
    
    Args:
        dom: minidom.Document 对象
        find_text: 要查找的文本（支持模糊匹配）
        replace_text: 替换后的文本
        replace_all: 是否替换所有匹配的段落
    """
    paras = dom.getElementsByTagName("w:p")
    found_count = 0
    
    for para in paras:
        # 跳过表格内的段落（已由 cell 处理）
        if para.parentNode and para.parentNode.nodeName == "w:tc":
            continue
            
        t_nodes = list(para.getElementsByTagName("w:t"))
        if not t_nodes:
            continue
            
        para_text = ''.join(t.firstChild.nodeValue if t.firstChild else '' for t in t_nodes)
        
        if fuzzy_find(para_text, find_text):
            # 替换文本（使用模糊替换）
            new_text = fuzzy_replace(para_text, find_text, replace_text)
            
            if t_nodes[0].firstChild:
                t_nodes[0].firstChild.nodeValue = new_text
            else:
                t_nodes[0].appendChild(dom.createTextNode(new_text))
                
            for t in t_nodes[1:]:
                if t.firstChild:
                    t.firstChild.nodeValue = ""
            
            found_count += 1
            if not replace_all:
                return True
    
    return found_count > 0


def apply_replacements(dom, replacements):
    """应用所有替换"""
    results = {"success": [], "failed": []}
    
    for item in replacements:
        find_text = item["find"]
        replace_text = item["replace"]
        scope = item.get("scope", "cell")
        
        display_find = find_text[:25] + '...' if len(find_text) > 25 else find_text
        display_replace = replace_text[:25] + '...' if len(replace_text) > 25 else replace_text
        print(f"  [{scope}] '{display_find}' -> '{display_replace}'")
        
        success = False
        if scope == "cell":
            success = find_and_replace_in_cell(dom, find_text, replace_text, clear_cell=False)
        elif scope == "cell_clear":
            success = find_and_replace_in_cell(dom, find_text, replace_text, clear_cell=True)
        elif scope == "row_content":
            # 新增：找到标题单元格，替换同行的内容单元格
            success = find_and_replace_row_content(dom, find_text, replace_text)
        elif scope == "paragraph":
            success = find_and_replace_in_paragraph(dom, find_text, replace_text)
        
        if success:
            results["success"].append(find_text)
        else:
            results["failed"].append(find_text)
            print(f"    [WARN] 未找到匹配")
    
    return results


def edit_template(template_path, output_path, replacements_data, clear_images=False):
    """基于模板编辑文档"""
    template_path = Path(template_path)
    output_path = Path(output_path)
    
    if not template_path.exists():
        raise FileNotFoundError(f"模板文件不存在: {template_path}")
    
    temp_dir = output_path.parent / f'_temp_edit_{output_path.stem}_{os.getpid()}'
    
    try:
        import zipfile
        with zipfile.ZipFile(template_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # 使用标准 minidom 解析 document.xml（避免 defusedxml 的实体解析问题）
        doc_xml_path = temp_dir / 'word' / 'document.xml'
        with open(doc_xml_path, 'r', encoding='utf-8') as f:
            dom = minidom.parse(f)
        
        # 清空图片（如果指定）
        if clear_images or replacements_data.get("clear_images", False):
            print("清空图片...")
            clear_all_images(temp_dir, dom)
        
        # 应用替换
        print("应用替换...")
        results = apply_replacements(dom, replacements_data.get("replacements", []))
        
        # 保存 document.xml
        with open(doc_xml_path, 'wb') as f:
            f.write(dom.toxml(encoding='utf-8'))
        
        # 打包
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(temp_dir)
                    zipf.write(file_path, arcname)
        
        print(f"\n[OK] 成功创建: {output_path}")
        print(f"  成功: {len(results['success'])} 项")
        if results['failed']:
            print(f"  失败: {len(results['failed'])} 项")
            for f in results['failed']:
                print(f"    - {f[:50]}")
        
        return results
        
    finally:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)


def main():
    parser = argparse.ArgumentParser(description='基于模板编辑文档')
    parser.add_argument('template', help='模板文档 (.docx)')
    parser.add_argument('output', help='输出文档 (.docx)')
    parser.add_argument('--replacements', '-r', required=True, help='替换规则 JSON 文件')
    parser.add_argument('--clear-images', '-c', action='store_true', help='清空所有图片')
    
    args = parser.parse_args()
    
    with open(args.replacements, 'r', encoding='utf-8') as f:
        replacements_data = json.load(f)
    
    try:
        edit_template(args.template, args.output, replacements_data, args.clear_images)
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
