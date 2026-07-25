# Spore Learning System - Phase 1: Episodic Store

基于认知科学的情景记忆（Episodic Memory）理论实现的任务学习系统。

## 已实现功能

### 1. 数据库 Schema

位置：`learning/schema.sql`

包含以下表结构：

- **episodes**: 存储完整的任务执行记录
- **episodes_fts**: 全文搜索索引
- **episodes_embeddings**: 向量 embedding 存储
- **semantic_knowledge**: 语义知识存储（Phase 3 使用）
- **semantic_fts**: 语义知识全文搜索索引

数据库文件默认位置：`F:/friend/spore/memory/episodic.db`

### 2. EpisodeStore 类

位置：`learning/episode_store.py`

核心功能：

#### 添加记录

```python
from learning import EpisodeStore

store = EpisodeStore()

episode_id = store.add_episode(
    task_type="malware_analysis",
    input_data={
        "user_query": "分析这个恶意样本并生成 YARA 规则",
        "context": {"sample_hash": "abc123"}
    },
    output_data={
        "yara_rule": "rule malware_abc123 { ... }",
        "detection_rate": "95%"
    },
    outcome="success",  # success / partial / failed
    source="user",  # user / tool / spore-self
    trust_zone="verified",  # verified / inferred / speculative
    salience=0.9,  # 显著性评分 0-1
    reasoning_trace=["步骤1", "步骤2", "步骤3"],
    tool_calls=[{"tool": "file", "action": "read"}],
    evidence={"cape_report": "path/to/report.json"}
)
```

#### 检索记录

```python
# 按 ID 获取
episode = store.get_episode(episode_id)

# 列出所有记录
episodes = store.list_episodes(
    task_type="malware_analysis",
    outcome="success",
    limit=20
)

# 语义检索（基于三因子评分）
results = store.search_similar(
    query="如何检测恶意软件",
    top_k=5,
    task_type="malware_analysis"
)

for episode, score in results:
    print(f"相似度: {score:.3f}")
    print(f"查询: {episode['input']['user_query']}")
```

#### 三因子检索算法

基于 Generative Agents 论文的检索机制：

1. **Recency（时间近度）**: 时间衰减权重
   ```
   score_recency = exp(-days_ago / half_life)
   ```

2. **Relevance（语义相似度）**: embedding cosine 相似度
   ```
   score_relevance = cosine_similarity(query_emb, episode_emb)
   ```

3. **Salience（显著性）**: 任务重要性评分

综合评分：
```
final_score = 0.3 * recency + 0.5 * relevance + 0.2 * salience
```

### 3. Embedding Generator

位置：`learning/embedding.py`

功能：

- 调用 OpenAI embedding API（text-embedding-3-small）
- 支持自定义 API URL（通过 `OPENAI_API_URL` 环境变量）
- 向量序列化/反序列化（存储为二进制 BLOB）
- Cosine 相似度计算

使用方式：

```python
from learning import EmbeddingGenerator

gen = EmbeddingGenerator()

# 单个文本
embedding = gen.generate("分析恶意样本")

# 批量生成
embeddings = gen.generate_batch(["文本1", "文本2", "文本3"])

# 计算相似度
similarity = gen.cosine_similarity(embedding1, embedding2)
```

### 4. CLI 测试命令

位置：`learning/cli_test.py`

使用方式：

```bash
# 添加测试记录
python cli_test.py add \
  --task-type malware_analysis \
  --query "分析样本生成 YARA 规则" \
  --output "rule malware { ... }" \
  --outcome success \
  --salience 0.8

# 获取记录
python cli_test.py get ep_20260723_215830_a3f2

# 列出记录
python cli_test.py list --task-type malware_analysis --limit 10

# 语义检索
python cli_test.py search "如何检测恶意软件" --top-k 5
```

## 测试

### 数据库功能测试（无需网络）

```bash
cd learning
python test_db_only.py
```

测试内容：
- 数据库创建
- 插入记录（不生成 embedding）
- 查询记录
- 全文搜索

### 完整功能测试（需要 OpenAI API）

```bash
cd learning
python test_with_embedding.py
```

测试内容：
- 添加记录（含 embedding 生成）
- 获取记录
- 语义检索

**注意**：需要在 `.env` 文件中配置：
```
OPENAI_API_KEY=sk-xxx
OPENAI_API_URL=https://api.openai.com/v1  # 可选，默认官方地址
```

## 架构设计

```
learning/
├── schema.sql          # 数据库 schema
├── embedding.py        # Embedding 生成器
├── episode_store.py    # Episodic memory 存储
├── cli_test.py         # CLI 测试工具
├── test_db_only.py     # 数据库功能测试
├── test_with_embedding.py  # 完整功能测试
└── __init__.py         # 模块导出
```

## 下一步（Phase 2 & 3）

### Phase 2: Retrieval Integration
- [ ] Spore 任务开始时自动检索相似历史记录
- [ ] 在 reasoning 时参考历史经验
- [ ] 用户反馈机制（更新 salience）

### Phase 3: Consolidation
- [ ] 定期后台任务合并 episodic 记录
- [ ] 用 LLM 生成 semantic 知识
- [ ] Conflict resolution 和 forgetting 机制

## 参考文献

- Tulving, E. (1972). Episodic and Semantic Memory
- Park et al. (2023). Generative Agents: Interactive Simulacra of Human Behavior
- Moltstream (2026). Memory is mostly write policy