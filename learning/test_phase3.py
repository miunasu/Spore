"""
测试 Phase 3: Consolidation
"""
import sys
from pathlib import Path

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from learning import EpisodeStore, ConsolidationEngine


def test_consolidation():
    """测试 consolidation 功能"""
    print("=== Phase 3 测试：Consolidation ===\n")
    
    # 创建实例
    store = EpisodeStore()
    consolidator = ConsolidationEngine(store)
    
    # 1. 添加足够的测试记录
    print("1. 准备测试数据（添加多条同类型记录）")
    
    test_cases = [
        {
            'task_type': 'yara_generation',
            'query': '为恶意样本生成YARA规则',
            'output': {'rule': 'rule mal1 {...}'},
            'outcome': 'success',
            'salience': 0.9,
            'tools': [{'tool': 'file', 'action': 'read'}, {'tool': 'Grep', 'pattern': 'MZ'}]
        },
        {
            'task_type': 'yara_generation',
            'query': '提取样本特征生成YARA规则',
            'output': {'rule': 'rule mal2 {...}'},
            'outcome': 'success',
            'salience': 0.85,
            'tools': [{'tool': 'file', 'action': 'read'}, {'tool': 'execute_command'}]
        },
        {
            'task_type': 'yara_generation',
            'query': '分析可疑文件生成检测规则',
            'output': {'rule': 'rule mal3 {...}'},
            'outcome': 'success',
            'salience': 0.8,
            'tools': [{'tool': 'file', 'action': 'read'}, {'tool': 'Grep'}]
        },
        {
            'task_type': 'yara_generation',
            'query': '基于CAPE报告生成YARA规则',
            'output': {'rule': 'rule mal4 {...}'},
            'outcome': 'success',
            'salience': 0.95,
            'tools': [{'tool': 'file', 'action': 'read'}, {'tool': 'skill_query'}]
        },
        {
            'task_type': 'yara_generation',
            'query': '从内存dump提取特征',
            'output': {'rule': 'rule mal5 {...}'},
            'outcome': 'partial',
            'salience': 0.7,
            'tools': [{'tool': 'file', 'action': 'read'}]
        }
    ]
    
    episode_ids = []
    for case in test_cases:
        eid = store.add_episode(
            task_type=case['task_type'],
            input_data={'user_query': case['query']},
            output_data=case['output'],
            outcome=case['outcome'],
            salience=case['salience'],
            tool_calls=case['tools'],
            reasoning_trace=['步骤1', '步骤2', '步骤3']
        )
        episode_ids.append(eid)
        print(f"  添加: {eid}")
    
    print(f"\n共添加 {len(episode_ids)} 条记录\n")
    
    # 2. 查找 consolidation 候选
    print("2. 查找 consolidation 候选记录")
    candidates = consolidator.find_consolidation_candidates(
        task_type='yara_generation',
        min_episodes=3,
        min_success_rate=0.6
    )
    
    print(f"找到 {len(candidates)} 条候选记录:")
    for cid in candidates[:5]:
        print(f"  - {cid}")
    print()
    
    # 3. 提取模式
    print("3. 提取执行模式")
    patterns = consolidator.extract_patterns(candidates)
    
    print(f"  任务类型: {patterns['task_types']}")
    print(f"  成功率: {patterns['success_rate']:.1%}")
    print(f"  记录总数: {patterns['total_episodes']}")
    print(f"  常用工具:")
    for tool, count in patterns['common_tools']:
        print(f"    - {tool}: {count} 次")
    print()
    
    # 4. 创建 semantic knowledge（简单模式）
    print("4. 创建 semantic knowledge（不使用LLM）")
    semantic_id = consolidator.consolidate_task_type('yara_generation')
    
    if semantic_id:
        print(f"  ✓ 创建成功: {semantic_id}\n")
        
        # 查看生成的知识
        knowledge_list = consolidator.get_semantic_knowledge(
            task_type='yara_generation',
            min_confidence=0.0
        )
        
        print("5. 查看生成的 semantic knowledge")
        for knowledge in knowledge_list[:1]:
            print(f"  ID: {knowledge['semantic_id']}")
            print(f"  任务类型: {knowledge['task_type']}")
            print(f"  置信度: {knowledge['confidence']:.2f}")
            print(f"  来源: {len(knowledge['source_episodes'])} 条 episodes")
            print(f"  知识描述:")
            for line in knowledge['knowledge'].split('\n'):
                print(f"    {line}")
            print()
    else:
        print("  未生成 semantic knowledge（记录数不足）\n")
    
    # 6. 测试冲突解决
    if semantic_id:
        print("6. 测试冲突解决机制")
        new_knowledge = """任务类型 'yara_generation' 的执行模式（修订版）:
- 成功率: 90%
- 基于 5 条历史记录
- 常用工具:
  - file (读取样本)
  - Grep (特征提取)
  - skill_query (调用专业模块)
- 最佳实践: 优先使用 memory-based 特征"""
        
        new_semantic_id = consolidator.resolve_conflict(
            old_semantic_id=semantic_id,
            new_knowledge_text=new_knowledge,
            confidence=0.9,
            actor='manual_review'
        )
        
        print(f"  ✓ 创建修正记录: {new_semantic_id}")
        print(f"  修正关系: {new_semantic_id} supersedes {semantic_id}\n")
    
    # 7. 测试定期 consolidation
    print("7. 测试定期 consolidation（自动发现任务类型）")
    results = consolidator.run_periodic_consolidation()
    
    if results:
        print(f"  处理了 {len(results)} 个任务类型:")
        for task_type, sem_id in results.items():
            print(f"    - {task_type}: {sem_id}")
    else:
        print("  没有符合条件的任务类型")
    
    print("\n✓ Phase 3 测试完成")


if __name__ == '__main__':
    test_consolidation()