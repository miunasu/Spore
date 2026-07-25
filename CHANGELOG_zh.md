# 更新日志

Spore AI Agent 的所有重要变更都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)。

---

## [未发布] - 2026-07-25

### 新增功能

#### 1. 请求重试进度显示
- **功能**：API 请求重试时在 Desktop error 日志中显示进度
- **实现细节**：
  - 修改了 `chat_process.py` 的重试机制，在每次重试前显示进度信息
  - 用户现在可以看到类似"请求失败，5秒后进行第 2 次重试..."的提示
  - 提升了网络问题或 API 失败时的用户感知
- **代码位置**：`base/chat_process.py` - `_do_llm_call()` 方法

#### 2. Learning 系统集成（情景记忆学习）
- **功能**：集成 Learning 模块，实现情景记忆和知识巩固能力
- **核心能力**：
  - **自动历史检索**：任务开始时，系统自动检索最多 3 条相关历史记录，并注入到 system prompt
  - **任务执行记录**：任务成功完成时，系统自动记录：
    - 用户查询
    - 任务类型（当前为 "general_task"）
    - 输出数据（最终回复）
    - 使用的工具调用
    - 执行结果
  - **未来支持**：用户反馈机制用于显著性调整（基础设施已就绪）
- **实现方式**：
  - 在 `conversation_loop.py` 中初始化 `EpisodicRetriever`
  - 在 `send_chat_request()` 中集成检索 - 发送 LLM 请求前注入相关历史
  - 在任务完成流程中集成记录（检测到 `STOP_REASON` 时）
  - 优雅降级：learning 模块不可用时，系统继续正常工作
- **代码位置**：`base/conversation_loop.py`，`learning/` 模块
- **参考文档**：详细文档见 `learning/PHASE2_PHASE3_SUMMARY.md`

#### 3. 文件备份系统改为会话级
- **功能**：文件备份系统从全局改为会话级隔离
- **解决的问题**：之前所有会话共享一个备份存储，导致：
  - 不同会话的版本链混在一起
  - 会话 A 的恢复操作可能影响会话 B 的文件状态
  - 无法独立管理各会话的备份
- **新架构**：
  - **会话隔离存储**：每个会话有独立的备份目录 `.spore/backups/<session_id>/`
  - **会话隔离元数据**：每个会话有独立的元数据文件 `.spore/metadata/<session_id>_file_history.json`
  - **后向兼容**：无 `session_id` 的会话使用 `__global__` 作为默认值
- **实现细节**：
  - 添加了 `_get_session_backup_dir(session_id)` 和 `_get_session_metadata_path(session_id)` 辅助方法
  - 将 `_metadata` 从单个字典改为 `_metadata_cache: Dict[str, Dict]` 实现按会话缓存
  - 更新了 13 个方法以接受和使用 `session_id` 参数：
    - 核心方法：`_load_metadata()`、`_save_metadata()`、`_record_version()`、`_reconstruct()`
    - API 方法：`restore_file()`、`get_history()`、`list_tracked_files()`
    - 快照方法：`create_checkpoint()`、`begin_round()`、`rewind()`
- **代码位置**：`base/backup_manager.py`
- **优势**：
  - 不同会话的备份和恢复操作完全隔离
  - 支持安全的多会话并发操作
  - 每个会话的备份历史更清晰

### 技术细节

**修改的文件**：
- `base/chat_process.py` - 重试进度日志
- `base/conversation_loop.py` - Learning 系统集成
- `base/backup_manager.py` - 会话级备份重构

**依赖项**：
- Learning 模块需要 `requests` 库用于 embedding API（已有）
- 未添加新的外部依赖

---

## 说明

详细的架构和配置信息，请参阅：
- [配置指南](docs/en/CONFIGURATION.md)
- [架构概览](docs/en/ARCHITECTURE.md)
- [Learning 模块文档](learning/PHASE2_PHASE3_SUMMARY.md)