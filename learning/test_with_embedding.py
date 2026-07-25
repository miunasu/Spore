"""
测试带 embedding 的完整功能
"""
import sys
import os
from pathlib import Path

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from learning.episode_store import EpisodeStore


def test_add_single_episode():
    """测试添加单条带 embedding 的记录"""
    print("=== 测试添加单条记录（含 embedding） ===\n")
    
    # 确认 API key
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("错误: 未找到 OPENAI_API_KEY 环境变量")
        return None
    
    print(f"API Key: {api_key[:10]}...{api_key[-4:]}")
    print()
    
    try:
        store = EpisodeStore("F:/friend/spore/memory/episodic.db")
        
        episode_id = store.add_episode(
            task_type="malware_analysis",
            input_data={
                "user_query": "分析这个恶意样本并生成 YARA 检测规则",
                "context": {"sample_hash": "abc123", "file_type": "PE"}
            },
            output_data={
                "yara_rule": "rule malware_abc123 { strings: $s1 = { 4D 5A } condition: $s1 }",
                "detection_rate": "95%"
            },
            outcome="success",
            salience=0.9,
            reasoning_trace=[
                "读取样本的 CAPE 报告",
                "提取特征码",
                "生成 YARA 规则",
                "VT 验证通过"
            ],
            tool_calls=[
                {"tool": "file", "action": "read", "path": "report.json"},
                {"tool": "execute_command", "command": "yara scan"}
            ]
        )
        
        print(f"添加成功: {episode_id}\n")
        return episode_id
        
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_get_episode(episode_id):
    """测试获取记录"""
    print(f"\n=== 测试获取记录: {episode_id} ===\n")
    
    try:
        store = EpisodeStore("F:/friend/spore/memory/episodic.db")
        episode = store.get_episode(episode_id)
        
        if episode:
            print(f"Episode ID: {episode['episode_id']}")
            print(f"时间: {episode['timestamp']}")
            print(f"任务类型: {episode['task_type']}")
            print(f"查询: {episode['input']['user_query']}")
            print(f"结果: {episode['outcome']}")
            print(f"显著性: {episode['salience']}")
            
            if episode.get('reasoning_trace'):
                print(f"\n推理步骤:")
                for i, step in enumerate(episode['reasoning_trace'], 1):
                    print(f"  {i}. {step}")
            
            print()
            return True
        else:
            print("未找到记录")
            return False
            
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_search_similar():
    """测试语义检索"""
    print("\n=== 测试语义检索 ===\n")
    
    try:
        store = EpisodeStore("F:/friend/spore/memory/episodic.db")
        
        query = "如何检测恶意软件"
        print(f"查询: {query}\n")
        
        results = store.search_similar(query, top_k=3)
        
        print(f"找到 {len(results)} 条相似记录:\n")
        for episode, score in results:
            print(f"[相似度: {score:.4f}] {episode['episode_id']}")
            print(f"  任务: {episode['task_type']}")
            print(f"  查询: {episode['input'].get('user_query', 'N/A')}")
            print(f"  结果: {episode['outcome']}")
            print()
        
        return len(results) > 0
        
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """运行测试"""
    print("开始测试 Episodic Memory Store（完整功能）\n")
    print("=" * 60)
    print()
    
    # 测试 1: 添加记录
    episode_id = test_add_single_episode()
    
    if not episode_id:
        print("\n添加记录失败，停止测试")
        return
    
    print("=" * 60)
    
    # 测试 2: 获取记录
    success = test_get_episode(episode_id)
    
    if not success:
        print("\n获取记录失败")
    
    print("=" * 60)
    
    # 测试 3: 语义检索
    success = test_search_similar()
    
    if not success:
        print("\n语义检索失败")
    
    print("=" * 60)
    print("\n测试完成!")


if __name__ == '__main__':
    main()