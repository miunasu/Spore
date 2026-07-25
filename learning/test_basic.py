"""
基础功能测试脚本
测试 EpisodeStore 的写入和检索功能
"""
import sys
from pathlib import Path

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from learning.episode_store import EpisodeStore


def test_add_episodes():
    """测试添加 episodes"""
    print("=== 测试添加 episodes ===\n")
    
    store = EpisodeStore("F:/friend/spore/memory/episodic.db")
    
    # 添加几条测试记录
    test_cases = [
        {
            "task_type": "malware_analysis",
            "input_data": {
                "user_query": "分析这个样本，生成 YARA 规则",
                "context": {"sample_hash": "abc123"}
            },
            "output_data": {
                "yara_rule": "rule sample_abc123 { ... }",
                "xml_rule": "<rule>...</rule>"
            },
            "outcome": "success",
            "salience": 0.8,
            "reasoning_trace": [
                "检查 CAPE 报告的 cape_yara 字段",
                "发现 VID_0x 命中",
                "从 XML 原规则提取 mem_offset"
            ]
        },
        {
            "task_type": "code_review",
            "input_data": {
                "user_query": "检查这段代码有没有安全问题",
                "context": {"file": "auth.py"}
            },
            "output_data": {
                "issues": ["SQL injection risk", "Missing input validation"]
            },
            "outcome": "success",
            "salience": 0.6
        },
        {
            "task_type": "malware_analysis",
            "input_data": {
                "user_query": "提取恶意样本的 C2 地址",
                "context": {"sample_hash": "def456"}
            },
            "output_data": {
                "c2_addresses": ["192.168.1.100:8080", "example.com"]
            },
            "outcome": "partial",
            "salience": 0.7
        }
    ]
    
    episode_ids = []
    for i, case in enumerate(test_cases, 1):
        episode_id = store.add_episode(**case)
        episode_ids.append(episode_id)
        print(f"{i}. 添加成功: {episode_id}")
        print(f"   任务: {case['task_type']}")
        print(f"   查询: {case['input_data']['user_query']}")
        print()
    
    return episode_ids


def test_get_episode(episode_id):
    """测试获取单条 episode"""
    print(f"=== 测试获取 episode: {episode_id} ===\n")
    
    store = EpisodeStore("F:/friend/spore/memory/episodic.db")
    episode = store.get_episode(episode_id)
    
    if episode:
        print(f"Episode ID: {episode['episode_id']}")
        print(f"Timestamp: {episode['timestamp']}")
        print(f"Task Type: {episode['task_type']}")
        print(f"Query: {episode['input'].get('user_query', 'N/A')}")
        print(f"Outcome: {episode['outcome']}")
        print(f"Salience: {episode['salience']}")
        print()
    else:
        print("Episode not found")


def test_list_episodes():
    """测试列出 episodes"""
    print("=== 测试列出所有 episodes ===\n")
    
    store = EpisodeStore("F:/friend/spore/memory/episodic.db")
    episodes = store.list_episodes(limit=10)
    
    print(f"找到 {len(episodes)} 条记录:\n")
    for ep in episodes:
        print(f"[{ep['episode_id']}]")
        print(f"  时间: {ep['timestamp']}")
        print(f"  任务: {ep['task_type']}")
        print(f"  查询: {ep['input'].get('user_query', 'N/A')}")
        print(f"  结果: {ep['outcome']}, 显著性: {ep['salience']}")
        print()


def test_search_similar():
    """测试语义检索"""
    print("=== 测试语义检索 ===\n")
    
    store = EpisodeStore("F:/friend/spore/memory/episodic.db")
    
    query = "分析恶意软件并生成检测规则"
    print(f"查询: {query}\n")
    
    results = store.search_similar(query, top_k=3)
    
    print(f"找到 {len(results)} 条相似记录:\n")
    for episode, score in results:
        print(f"[相似度: {score:.3f}] {episode['episode_id']}")
        print(f"  任务: {episode['task_type']}")
        print(f"  查询: {episode['input'].get('user_query', 'N/A')}")
        print(f"  结果: {episode['outcome']}")
        print()


def main():
    """运行所有测试"""
    print("开始测试 Episodic Memory Store\n")
    print("=" * 60)
    print()
    
    # 1. 添加测试数据
    episode_ids = test_add_episodes()
    
    print("=" * 60)
    print()
    
    # 2. 获取单条记录
    if episode_ids:
        test_get_episode(episode_ids[0])
    
    print("=" * 60)
    print()
    
    # 3. 列出所有记录
    test_list_episodes()
    
    print("=" * 60)
    print()
    
    # 4. 语义检索
    test_search_similar()
    
    print("=" * 60)
    print("\n测试完成!")


if __name__ == '__main__':
    main()