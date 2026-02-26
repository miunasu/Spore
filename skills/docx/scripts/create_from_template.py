"""
基于模板文档创建新文档的工具

这个脚本提供了基于现有 Word 文档模板创建新文档的功能，
完整保留原文档的所有格式（字体、样式、表格布局等）。

用法:
    # 方式1: 使用 JSON 数据文件进行占位符替换
    python create_from_template.py <template.docx> <output.docx> --data <data.json>
    
    # 方式2: 仅复制模板（后续手动编辑）
    python create_from_template.py <template.docx> <output.docx> --unpack-to <dir>

JSON 数据格式示例 (用于占位符替换):
{
    "{{报告编号}}": "SP-20251215-001",
    "{{提交时间}}": "2025年12月15日",
    "{{分析人员}}": "李豪俊"
}

支持的占位符格式:
- {{key}} - 双花括号
- 【key】 - 中文方括号
- [key] - 英文方括号
- 直接文本匹配

示例:
    # 基于参考文档创建新报告
    python create_from_template.py reference.docx new_report.docx --data report_data.json
    
    # 解压模板以便手动编辑
    python create_from_template.py reference.docx new_report.docx --unpack-to unpacked_dir
"""

import sys
import os
import json
import shutil
import zipfile
import argparse
import re
from pathlib import Path


def unpack_docx(docx_path, output_dir):
    """解压 docx 文件到指定目录"""
    output_dir = Path(output_dir)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)
    
    with zipfile.ZipFile(docx_path, 'r') as zip_ref:
        zip_ref.extractall(output_dir)
    
    return output_dir


def pack_docx(input_dir, docx_path):
    """将目录打包为 docx 文件"""
    input_dir = Path(input_dir)
    docx_path = Path(docx_path)
    
    docx_path.parent.mkdir(parents=True, exist_ok=True)
    
    with zipfile.ZipFile(docx_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(input_dir):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(input_dir)
                zipf.write(file_path, arcname)


def replace_text_in_xml(xml_content, replacements):
    """在 XML 内容中替换文本，保持格式"""
    for key, value in replacements.items():
        # 转义 XML 特殊字符
        safe_value = (value
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&apos;'))
        
        # 直接替换 key
        xml_content = xml_content.replace(key, safe_value)
        
        # 如果 key 不包含占位符标记，也尝试带标记的版本
        if not any(marker in key for marker in ['{{', '【', '[']):
            xml_content = xml_content.replace(f'{{{{{key}}}}}', safe_value)
            xml_content = xml_content.replace(f'【{key}】', safe_value)
            xml_content = xml_content.replace(f'[{key}]', safe_value)
    
    return xml_content


def create_from_template(template_path, output_path, data=None, unpack_to=None):
    """基于模板创建新文档"""
    template_path = Path(template_path)
    output_path = Path(output_path)
    
    if not template_path.exists():
        raise FileNotFoundError(f"模板文件不存在: {template_path}")
    
    # 如果只需要解压
    if unpack_to:
        unpack_dir = Path(unpack_to)
        unpack_docx(template_path, unpack_dir)
        print(f"模板已解压到: {unpack_dir}")
        print(f"编辑完成后运行: python pack.py {unpack_dir} {output_path}")
        return str(unpack_dir)
    
    # 创建临时目录
    temp_dir = output_path.parent / f'_temp_{output_path.stem}_{os.getpid()}'
    
    try:
        unpack_docx(template_path, temp_dir)
        
        if data:
            # 处理 document.xml
            doc_xml_path = temp_dir / 'word' / 'document.xml'
            if doc_xml_path.exists():
                with open(doc_xml_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                content = replace_text_in_xml(content, data)
                with open(doc_xml_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            # 处理页眉页脚
            for xml_file in (temp_dir / 'word').glob('header*.xml'):
                with open(xml_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                content = replace_text_in_xml(content, data)
                with open(xml_file, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            for xml_file in (temp_dir / 'word').glob('footer*.xml'):
                with open(xml_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                content = replace_text_in_xml(content, data)
                with open(xml_file, 'w', encoding='utf-8') as f:
                    f.write(content)
        
        pack_docx(temp_dir, output_path)
        print(f"成功创建文档: {output_path}")
        return str(output_path)
        
    finally:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)


def main():
    parser = argparse.ArgumentParser(
        description='基于模板文档创建新文档，保留所有格式',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('template', help='模板文档路径 (.docx)')
    parser.add_argument('output', help='输出文档路径 (.docx)')
    parser.add_argument('--data', '-d', help='JSON 数据文件路径')
    parser.add_argument('--unpack-to', '-u', help='解压目录路径')
    
    args = parser.parse_args()
    
    data = None
    if args.data:
        with open(args.data, 'r', encoding='utf-8') as f:
            data = json.load(f)
    
    try:
        create_from_template(args.template, args.output, data, args.unpack_to)
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
