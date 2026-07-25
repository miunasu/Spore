# Changelog

All notable changes to Spore AI Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased] - 2026-07-25

### Added

#### 1. Request Retry Progress Display
- **Feature**: API request retry progress is now displayed in Desktop error logs
- **Implementation**: 
  - Modified `chat_process.py` retry mechanism to show progress before each retry attempt
  - Users now see messages like "Request failed, retrying in 5 seconds (attempt 2/4)..." in the Desktop UI
  - Improves user awareness during network issues or API failures
- **Location**: `base/chat_process.py` - `_do_llm_call()` method

#### 2. Learning System Integration (Episodic Memory)
- **Feature**: Integrated the Learning module to enable episodic memory and knowledge consolidation
- **Capabilities**:
  - **Automatic History Retrieval**: When starting a task, the system retrieves up to 3 relevant historical episodes and injects them into the system prompt
  - **Task Execution Recording**: When a task completes successfully, the system automatically records:
    - User query
    - Task type (currently "general_task")
    - Output data (final reply)
    - Tool calls used
    - Execution outcome
  - **Future Support**: User feedback mechanism for salience adjustment (infrastructure ready)
- **Implementation**:
  - Added `EpisodicRetriever` initialization in `conversation_loop.py`
  - Integrated retrieval in `send_chat_request()` - injects relevant history before sending LLM requests
  - Integrated recording in task completion flow (when `STOP_REASON` is detected)
  - Graceful degradation: if the learning module is unavailable, the system continues to work without it
- **Location**: `base/conversation_loop.py`, `learning/` module
- **Reference**: See `learning/PHASE2_PHASE3_SUMMARY.md` for detailed documentation

#### 3. Session-Level File Backup System
- **Feature**: File backup system refactored from global to session-level isolation
- **Problem Solved**: Previously, all sessions shared a single backup storage, causing:
  - Version chains from different sessions mixed together
  - Session A's restore operations could affect Session B's file state
  - No independent backup management per session
- **New Architecture**:
  - **Session-isolated storage**: Each session has its own backup directory `.spore/backups/<session_id>/`
  - **Session-isolated metadata**: Each session has its own metadata file `.spore/metadata/<session_id>_file_history.json`
  - **Backward compatibility**: Sessions without `session_id` use `__global__` as default
- **Implementation**:
  - Added `_get_session_backup_dir(session_id)` and `_get_session_metadata_path(session_id)` helper methods
  - Changed `_metadata` from single dict to `_metadata_cache: Dict[str, Dict]` for per-session caching
  - Updated 13 methods to accept and use `session_id` parameter:
    - Core: `_load_metadata()`, `_save_metadata()`, `_record_version()`, `_reconstruct()`
    - API: `restore_file()`, `get_history()`, `list_tracked_files()`
    - Checkpoint: `create_checkpoint()`, `begin_round()`, `rewind()`
- **Location**: `base/backup_manager.py`
- **Benefits**:
  - Complete isolation between sessions' backup and restore operations
  - Safe concurrent multi-session operation
  - Cleaner backup history per session

### Technical Details

**Files Modified**:
- `base/chat_process.py` - Retry progress logging
- `base/conversation_loop.py` - Learning system integration
- `base/backup_manager.py` - Session-level backup refactoring

**Dependencies**:
- Learning module requires `requests` library for embedding API (already present)
- No new external dependencies added

---

## Notes

For detailed architecture and configuration, see:
- [Configuration Guide](docs/en/CONFIGURATION.md)
- [Architecture Overview](docs/en/ARCHITECTURE.md)
- [Learning Module Documentation](learning/PHASE2_PHASE3_SUMMARY.md)