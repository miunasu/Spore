"""
Mock 测试 - 使用假的 embedding 测试完整流程
"""
import sys
from pathlib import Path
from unittest.mock import patch
import random

sys.path.insert(0, str(Path(__file__).parent.parent))

from learning.episode_store import EpisodeStore


def mock_generate(self, text):
    """生成假的 embedding（随机向量）"""
    random.seed(hash(text) % (2**32))
    return [random.random() for _ in range(1536)]


def test_full_workflow():
    """测试完整工作流"""
    print("=== Mock 测试：完整工作流 ===\n")
    
    # Patch embedding 生成方法
    with patch('learning.embedding.EmbeddingGenerator.generate', mock_generate):
        store = EpisodeStore("F:/friend/spore/memory/episodic.db")
        
        # 1. 添加多条记录
        print("1. 添加测试记录\n")
        
        test_cases = [
            {
                "task_type": "malware_analysis",
                "query": "分析恶意样本并生成 YARA 规则",
                "output": "rule malware_1 { ... }",
                "salience": 0.9
            },
            {
                "task_type": "malware_analysis",
                "query": "提取恶意软件的 C2 地址",
                "output": "C2: 192.168.1.100",
                "salience": 0.7
            },
            {
                "task_type": "code_review",
                "query": "检查代码安全漏洞",
                "output": "发现 SQL 注入风险",
                "salience": 0.6
            },
            {
                "task_type": "malware_analysis",
                "query": "分析样本的行为特征",
                "output": "发现注册表修改和网络通信",
                "salience": 0.8
            }
        ]
        
        episode_ids = []
        for case in test_cases:
            episode_id = store.add_episode(
                task_type=case["task_type"],
                input_data={"user_query": case["query"]},
                output_data={"result": case["output"]},
                outcome="success",
                salience=case["salience"]
            )
            episode_ids.append(episode_id)
            print(f"  添加: {episode_id}")
            print(f"    查询: {case['query']}")
        
        print()
        
        # 2. 获取单条记录
        print(f"2. 获取记录: {episode_ids[0]}\n")
        
        episode = store.get_episode(episode_ids[0])
        if episode:
            print(f"  任务类型: {episode['task_type']}")
            print(f"  查询: {episode['input']['user_query']}")
            print(f"  结果: {episode['outcome']}")
            print(f"  显著性: {episode['salience']}")
        
        print()
        
        # 3. 列出记录
        print("3. 列出所有 malware_analysis 记录\n")
        
        episodes = store.list_episodes(task_type="malware_analysis", limit=10)
        print(f"  找到 {len(episodes)} 条记录")
        for ep in episodes:
            print(f"    - {ep['episode_id']}: {ep['input']['user_query'][:30]}...")
        
        print()
        
        # 4. 语义检索
        print("4. 语义检索：'如何检测恶意软件'\n")
        
        results = store.search_similar(
            query="如何检测恶意软件",
            top_k=3,
            task_type="malware_analysis"
        )
        
        print(f"  找到 {len(results)} 条相似记录:\n")
        for episode, score in results:
            print(f"  [相似度: {score:.4f}] {episode['episode_id']}")
            print(f"    查询: {episode['input']['user_query']}")
            print(f"    显著性: {episode['salience']}")
            print()
        
        # 5. 测试更新 salience
        print(f"5. 更新 salience: {episode_ids[0]}\n")
        
        store.update_salience(episode_ids[0], 0.95)
        updated = store.get_episode(episode_ids[0])
        print(f"  新的 salience: {updated['salience']}")
        
        print()
        
        # 6. 测试 supersede
        print(f"6. 标记记录被修正: {episode_ids[1]} -> {episode_ids[0]}\n")
        
        store.mark_superseded(episode_ids[1], episode_ids[0])
        superseded = store.get_episode(episode_ids[1])
        print(f"  superseded_by: {superseded['superseded_by']}")
        
        print()
        print("=" * 60)
        print("\nMock 测试完成！所有功能正常工作。")


if __name__ == '__main__':
    test_full_workflow()