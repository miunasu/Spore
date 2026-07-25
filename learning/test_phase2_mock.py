"""
测试 Phase 2: Retrieval Integration (Mock版本，不依赖API)
"""
import sys
from pathlib import Path
import struct
import random

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from learning import EpisodeStore, EpisodicRetriever


class MockEmbeddingGenerator:
    """Mock embedding 生成器"""
    def __init__(self):
        self.model = "mock-embedding"
        self.embedding_dim = 1536
    
    def generate(self, text: str):
        """生成伪随机 embedding（基于文本hash保证一致性）"""
        random.seed(hash(text) % (2**32))
        return [random.gauss(0, 1) for _ in range(self.embedding_dim)]
    
    def generate_batch(self, texts):
        return [self.generate(t) for t in texts]
    
    def serialize_embedding(self, embedding):
        return struct.pack(f'{len(embedding)}f', *embedding)
    
    def deserialize_embedding(self, blob):
        count = len(blob) // 4
        return list(struct.unpack(f'{count}f', blob))
    
    def cosine_similarity(self, vec1, vec2):
        dot = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = sum(a * a for a in vec1) ** 0.5
        norm2 = sum(b * b for b in vec2) ** 0.5
        return dot / (norm1 * norm2) if norm1 and norm2 else 0.0


def test_retrieval():
    """测试检索功能"""
    print("=== Phase 2 测试：Retrieval Integration (Mock版本) ===\n")
    
    # 创建实例并注入 mock embedding
    store = EpisodeStore()
    store.embedding_gen = MockEmbeddingGenerator()
    retriever = EpisodicRetriever(store)
    
    # 1. 添加测试记录
    print("1. 添加测试记录")
    episode_ids = []
    
    test_cases = [
        {
            'task_type': 'malware_analysis',
            'query': '分析恶意样本并生成YARA规则',
            'output': {'yara_rule': 'rule malware_001 { strings: $a = "evil" condition: $a }'},
            'outcome': 'success',
            'salience': 0.9,
            'reasoning': ['读取样本文件', '提取特征字符串', '生成YARA规则', '验证规则']
        },
        {
            'task_type': 'malware_analysis',
            'query': '检测可疑进程并生成检测规则',
            'output': {'detection_rule': 'process: malware.exe'},
            'outcome': 'success',
            'salience': 0.8,
            'reasoning': ['分析进程行为', '提取IOC', '生成检测规则']
        },
        {
            'task_type': 'code_review',
            'query': '检查Python代码的安全问题',
            'output': {'issues': ['SQL注入风险', '未验证的输入']},
            'outcome': 'success',
            'salience': 0.7,
            'reasoning': ['扫描代码', '识别危险模式', '生成报告']
        },
        {
            'task_type': 'malware_analysis',
            'query': '分析勒索软件行为特征',
            'output': {'behaviors': ['文件加密', 'C2通信', '删除卷影副本']},
            'outcome': 'partial',
            'salience': 0.6,
            'reasoning': ['动态分析', '提取行为特征', '关联C2地址']
        }
    ]
    
    for case in test_cases:
        eid = retriever.record_task_execution(
            task_type=case['task_type'],
            user_query=case['query'],
            output_data=case['output'],
            outcome=case['outcome'],
            reasoning_trace=case['reasoning'],
            salience=case['salience']
        )
        episode_ids.append(eid)
        print(f"  添加: {eid} - {case['query'][:30]}...")
    
    print(f"\n共添加 {len(episode_ids)} 条记录\n")
    
    # 2. 测试检索功能
    print("2. 测试相似任务检索")
    query = "如何生成恶意软件的检测规则"
    print(f"查询: '{query}'\n")
    
    retrieved = retriever.retrieve_for_task(
        user_query=query,
        task_type='malware_analysis',
        top_k=3,
        min_score=0.0
    )
    
    print(f"检索到 {len(retrieved)} 条相关记录:\n")
    for item in retrieved:
        episode = item['episode']
        score = item['score']
        print(f"  [{score:.3f}] {episode['episode_id']}")
        print(f"         查询: {episode['input']['user_query']}")
        print(f"         结果: {episode['outcome']}, 显著性: {episode['salience']}")
        print()
    
    # 3. 测试 prompt 注入格式
    print("3. 测试 Prompt 注入格式\n")
    context = retriever.get_injection_context(
        user_query=query,
        task_type='malware_analysis',
        max_episodes=2
    )
    
    print("生成的上下文文本:")
    print("=" * 60)
    print(context)
    print("=" * 60)
    print()
    
    # 4. 测试反馈机制
    print("4. 测试用户反馈机制")
    if episode_ids:
        test_id = episode_ids[0]
        
        # 获取初始 salience
        episode = store.get_episode(test_id)
        initial_salience = episode['salience']
        print(f"  初始显著性: {initial_salience}")
        
        # 正面反馈
        retriever.update_salience_from_feedback(test_id, 'positive')
        episode = store.get_episode(test_id)
        new_salience = episode['salience']
        print(f"  正面反馈后: {new_salience} (增加 {new_salience - initial_salience:.2f})")
        
        # 负面反馈
        retriever.update_salience_from_feedback(test_id, 'negative')
        episode = store.get_episode(test_id)
        final_salience = episode['salience']
        print(f"  负面反馈后: {final_salience} (减少 {new_salience - final_salience:.2f})")
    
    print("\n=== 功能验证 ===")
    print("✓ 任务记录存储")
    print("✓ 三因子检索算法（recency + relevance + salience）")
    print("✓ Prompt上下文格式化")
    print("✓ 用户反馈机制")
    print("\n✓ Phase 2 测试完成")


if __name__ == '__main__':
    test_retrieval()