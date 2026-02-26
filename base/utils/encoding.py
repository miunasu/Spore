"""
编码检测和转换工具

提供智能编码检测功能，自动尝试多种编码以避免乱码
"""
from typing import Optional


def smart_decode(data: bytes, prefer_encoding: str = None) -> str:
    """
    智能解码：自动尝试多种编码，避免乱码
    
    解码策略：
    1. 首先尝试首选编码（Windows默认GBK，Linux默认UTF-8）
    2. 失败则尝试UTF-8
    3. 再失败则尝试其他常见编码（CP936, GB2312, Latin-1）
    4. 最后使用replace策略强制解码
    
    参数:
        data: 原始字节数据
        prefer_encoding: 首选编码，None时根据系统自动选择
                        Windows: gbk
                        Linux/Mac: utf-8
    
    返回:
        解码后的字符串
    
    示例:
        >>> data = b'\xd5\xd2\xb2\xbb\xb5\xbd\xce\xc4\xbc\xfe'
        >>> text = smart_decode(data)  # Windows上自动使用GBK
        >>> print(text)
        '找不到文件'
    """
    if not data:
        return ""
    
    # 确定首选编码
    if prefer_encoding is None:
        import os
        prefer_encoding = 'gbk' if os.name == 'nt' else 'utf-8'
    
    # Step 1: 尝试首选编码
    try:
        return data.decode(prefer_encoding)
    except (UnicodeDecodeError, LookupError):
        pass
    
    # Step 2: 尝试 UTF-8
    if prefer_encoding != 'utf-8':
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            pass
    
    # Step 3: 尝试其他常见编码
    fallback_encodings = ['cp936', 'gb2312', 'gbk', 'latin-1', 'iso-8859-1']
    for enc in fallback_encodings:
        if enc == prefer_encoding:  # 跳过已尝试的编码
            continue
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    
    # Step 4: 使用replace策略强制解码（保证不会失败）
    return data.decode(prefer_encoding, errors='replace')


def detect_encoding(data: bytes, max_bytes: int = 10000) -> str:
    """
    检测字节数据的编码格式
    
    参数:
        data: 原始字节数据
        max_bytes: 用于检测的最大字节数
    
    返回:
        最可能的编码名称
    
    示例:
        >>> data = "中文测试".encode('gbk')
        >>> encoding = detect_encoding(data)
        >>> print(encoding)
        'gbk'
    """
    if not data:
        return 'utf-8'
    
    # 限制检测数据量
    sample = data[:max_bytes]
    
    # 尝试各种编码，记录成功率
    encodings_to_try = [
        'utf-8',
        'gbk',
        'gb2312',
        'cp936',
        'utf-16',
        'utf-16le',
        'utf-16be',
        'latin-1',
        'iso-8859-1',
    ]
    
    for encoding in encodings_to_try:
        try:
            decoded = sample.decode(encoding)
            # 检查解码后的文本质量（简单启发式）
            # 如果包含大量不可打印字符，可能不是正确的编码
            printable_ratio = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t') / len(decoded) if decoded else 0
            if printable_ratio > 0.8:  # 80%以上是可打印字符
                return encoding
        except (UnicodeDecodeError, LookupError):
            continue
    
    # 默认返回系统编码
    import os
    return 'gbk' if os.name == 'nt' else 'utf-8'


def safe_encode(text: str, encoding: str = None, errors: str = 'replace') -> bytes:
    """
    安全编码：将字符串编码为字节，保证不会失败
    
    参数:
        text: 要编码的字符串
        encoding: 目标编码，None时根据系统自动选择
        errors: 错误处理策略 ('strict', 'ignore', 'replace')
    
    返回:
        编码后的字节数据
    """
    if encoding is None:
        import os
        encoding = 'gbk' if os.name == 'nt' else 'utf-8'
    
    try:
        return text.encode(encoding, errors=errors)
    except (UnicodeEncodeError, LookupError):
        # 回退到UTF-8
        return text.encode('utf-8', errors=errors)
