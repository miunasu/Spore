-- Episodic Memory Store Schema
-- 存储完整的任务执行记录

CREATE TABLE IF NOT EXISTS episodes (
    episode_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('user', 'tool', 'spore-self')),
    trust_zone TEXT NOT NULL CHECK(trust_zone IN ('verified', 'inferred', 'speculative')),
    task_type TEXT NOT NULL,
    
    -- 任务输入（JSON）
    input_json TEXT NOT NULL,
    
    -- 推理痕迹（JSON 数组）
    reasoning_trace TEXT,
    
    -- 工具调用记录（JSON 数组）
    tool_calls TEXT,
    
    -- 输出结果（JSON）
    output_json TEXT,
    
    -- 任务结果
    outcome TEXT NOT NULL CHECK(outcome IN ('success', 'partial', 'failed')),
    
    -- 显著性评分（0-1）
    salience REAL NOT NULL DEFAULT 0.5 CHECK(salience >= 0 AND salience <= 1),
    
    -- 证据链（JSON）
    evidence TEXT,
    
    -- 半衰期（天）
    half_life_days INTEGER NOT NULL DEFAULT 90,
    
    -- 是否被后续记录修正
    superseded_by TEXT,
    
    -- 创建时间戳
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    
    FOREIGN KEY (superseded_by) REFERENCES episodes(episode_id)
);

-- 全文搜索索引
CREATE VIRTUAL TABLE IF NOT EXISTS episodes_fts USING fts5(
    episode_id UNINDEXED,
    task_type,
    input_text,
    reasoning_text,
    output_text,
    content=episodes,
    content_rowid=rowid
);

-- 自动同步 FTS 索引
CREATE TRIGGER IF NOT EXISTS episodes_fts_insert AFTER INSERT ON episodes BEGIN
    INSERT INTO episodes_fts(episode_id, task_type, input_text, reasoning_text, output_text)
    VALUES (
        new.episode_id,
        new.task_type,
        json_extract(new.input_json, '$.user_query'),
        new.reasoning_trace,
        new.output_json
    );
END;

CREATE TRIGGER IF NOT EXISTS episodes_fts_delete AFTER DELETE ON episodes BEGIN
    DELETE FROM episodes_fts WHERE episode_id = old.episode_id;
END;

-- 向量 embedding 存储
CREATE TABLE IF NOT EXISTS episodes_embeddings (
    episode_id TEXT PRIMARY KEY,
    embedding BLOB NOT NULL,
    embedding_model TEXT NOT NULL,
    embedding_dim INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (episode_id) REFERENCES episodes(episode_id) ON DELETE CASCADE
);

-- Semantic Knowledge Store Schema
-- 存储从 episodic 记录提炼出的语义知识

CREATE TABLE IF NOT EXISTS semantic_knowledge (
    semantic_id TEXT PRIMARY KEY,
    task_type TEXT NOT NULL,
    knowledge TEXT NOT NULL,
    
    -- 来源的 episode_id 列表（JSON 数组）
    source_episodes TEXT NOT NULL,
    
    -- 置信度（0-1）
    confidence REAL NOT NULL DEFAULT 0.5 CHECK(confidence >= 0 AND confidence <= 1),
    
    -- 创建者标识
    actor TEXT NOT NULL,
    
    -- 修正的旧知识 ID
    supersedes TEXT,
    
    -- 创建时间
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    
    FOREIGN KEY (supersedes) REFERENCES semantic_knowledge(semantic_id)
);

-- Semantic knowledge 全文搜索
CREATE VIRTUAL TABLE IF NOT EXISTS semantic_fts USING fts5(
    semantic_id UNINDEXED,
    task_type,
    knowledge,
    content=semantic_knowledge,
    content_rowid=rowid
);

CREATE TRIGGER IF NOT EXISTS semantic_fts_insert AFTER INSERT ON semantic_knowledge BEGIN
    INSERT INTO semantic_fts(semantic_id, task_type, knowledge)
    VALUES (new.semantic_id, new.task_type, new.knowledge);
END;

CREATE TRIGGER IF NOT EXISTS semantic_fts_delete AFTER DELETE ON semantic_knowledge BEGIN
    DELETE FROM semantic_fts WHERE semantic_id = old.semantic_id;
END;

-- 索引优化
CREATE INDEX IF NOT EXISTS idx_episodes_timestamp ON episodes(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_episodes_task_type ON episodes(task_type);
CREATE INDEX IF NOT EXISTS idx_episodes_outcome ON episodes(outcome);
CREATE INDEX IF NOT EXISTS idx_episodes_trust_zone ON episodes(trust_zone);
CREATE INDEX IF NOT EXISTS idx_semantic_task_type ON semantic_knowledge(task_type);
CREATE INDEX IF NOT EXISTS idx_semantic_confidence ON semantic_knowledge(confidence DESC);