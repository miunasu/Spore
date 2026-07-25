"""
仅测试数据库功能，不调用 OpenAI API
"""
import sys
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
import json

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_database_creation():
    """测试数据库创建"""
    print("=== 测试数据库创建 ===\n")
    
    db_path = "F:/friend/spore/memory/episodic.db"
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    
    # 执行 schema
    schema_path = Path(__file__).parent / "schema.sql"
    with open(schema_path, 'r', encoding='utf-8') as f:
        schema_sql = f.read()
    
    with sqlite3.connect(db_path) as conn:
        conn.executescript(schema_sql)
        conn.commit()
    
    print(f"数据库创建成功: {db_path}\n")
    
    # 检查表
    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' 
            ORDER BY name
        """)
        tables = [row[0] for row in cursor.fetchall()]
    
    print("已创建的表:")
    for table in tables:
        print(f"  - {table}")
    print()


def test_insert_without_embedding():
    """测试不使用 embedding 的插入"""
    print("=== 测试插入记录（无 embedding） ===\n")
    
    db_path = "F:/friend/spore/memory/episodic.db"
    
    # 准备数据
    timestamp = datetime.now(timezone.utc)
    episode_id = f"ep_test_{timestamp.strftime('%Y%m%d_%H%M%S')}"
    
    input_data = {
        "user_query": "测试查询：分析这个样本",
        "context": {"sample_hash": "test123"}
    }
    
    output_data = {
        "result": "分析完成",
        "yara_rule": "rule test { ... }"
    }
    
    # 插入记录
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            INSERT INTO episodes (
                episode_id, timestamp, source, trust_zone, task_type,
                input_json, reasoning_trace, tool_calls, output_json,
                outcome, salience, evidence, half_life_days
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            episode_id,
            timestamp.isoformat(),
            "user",
            "verified",
            "malware_analysis",
            json.dumps(input_data, ensure_ascii=False),
            json.dumps(["步骤1", "步骤2"], ensure_ascii=False),
            json.dumps([], ensure_ascii=False),
            json.dumps(output_data, ensure_ascii=False),
            "success",
            0.8,
            json.dumps({}, ensure_ascii=False),
            90
        ))
        conn.commit()
    
    print(f"插入成功: {episode_id}\n")
    
    # 读取验证
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("""
            SELECT * FROM episodes WHERE episode_id = ?
        """, (episode_id,))
        row = cursor.fetchone()
    
    if row:
        print("读取验证:")
        print(f"  Episode ID: {row['episode_id']}")
        print(f"  Task Type: {row['task_type']}")
        print(f"  Outcome: {row['outcome']}")
        print(f"  Salience: {row['salience']}")
        
        input_obj = json.loads(row['input_json'])
        print(f"  Query: {input_obj['user_query']}")
        print()
    
    return episode_id


def test_query_episodes():
    """测试查询 episodes"""
    print("=== 测试查询记录 ===\n")
    
    db_path = "F:/friend/spore/memory/episodic.db"
    
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("""
            SELECT episode_id, timestamp, task_type, outcome, salience
            FROM episodes
            ORDER BY timestamp DESC
            LIMIT 5
        """)
        rows = cursor.fetchall()
    
    print(f"找到 {len(rows)} 条记录:\n")
    for row in rows:
        print(f"[{row['episode_id']}]")
        print(f"  时间: {row['timestamp']}")
        print(f"  任务: {row['task_type']}")
        print(f"  结果: {row['outcome']}, 显著性: {row['salience']}")
        print()


def test_fts_search():
    """测试全文搜索"""
    print("=== 测试全文搜索 ===\n")
    
    db_path = "F:/friend/spore/memory/episodic.db"
    
    search_term = "分析"
    
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("""
            SELECT episode_id, task_type
            FROM episodes_fts
            WHERE episodes_fts MATCH ?
            LIMIT 5
        """, (search_term,))
        rows = cursor.fetchall()
    
    print(f"搜索关键词 '{search_term}'，找到 {len(rows)} 条记录:\n")
    for row in rows:
        print(f"  - [{row['episode_id']}] {row['task_type']}")
    print()


def main():
    """运行所有测试"""
    print("开始测试 Episodic Memory Store（数据库功能）\n")
    print("=" * 60)
    print()
    
    try:
        # 1. 创建数据库
        test_database_creation()
        
        print("=" * 60)
        print()
        
        # 2. 插入测试数据
        episode_id = test_insert_without_embedding()
        
        print("=" * 60)
        print()
        
        # 3. 查询记录
        test_query_episodes()
        
        print("=" * 60)
        print()
        
        # 4. 全文搜索
        test_fts_search()
        
        print("=" * 60)
        print("\n数据库测试完成!")
        
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()