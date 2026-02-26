/**
 * Note 编辑器组件 - 编辑根目录的 note.txt
 */
import React, { useState, useEffect, useCallback } from 'react';
import { filesApi } from '../../services/api';

const NOTE_PATH = 'note.txt';

export const NoteEditor: React.FC = () => {
  const [content, setContent] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 加载 note.txt
  const loadNote = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await filesApi.read(NOTE_PATH);
      setContent(response.content);
      setHasChanges(false);
    } catch (err) {
      // 文件不存在时创建空文件
      if ((err as any)?.status === 404) {
        setContent('');
        setHasChanges(false);
      } else {
        setError('加载失败');
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadNote();
  }, [loadNote]);

  // 保存 note.txt
  const saveNote = async () => {
    setIsSaving(true);
    setError(null);
    try {
      await filesApi.write(NOTE_PATH, content);
      setHasChanges(false);
    } catch (err) {
      setError('保存失败');
    } finally {
      setIsSaving(false);
    }
  };

  // Ctrl+S 保存
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        if (hasChanges) {
          saveNote();
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [hasChanges, content]);

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setContent(e.target.value);
    setHasChanges(true);
  };

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="flex items-center gap-2 text-spore-muted text-sm">
          <svg className="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          加载中...
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* 工具栏 */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-spore-border/30">
        <div className="flex items-center gap-2 text-xs text-spore-muted">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
          </svg>
          <span>note.txt</span>
          {hasChanges && <span className="text-spore-warning">●</span>}
        </div>
        <div className="flex items-center gap-2">
          {error && <span className="text-xs text-spore-error">{error}</span>}
          <button
            onClick={saveNote}
            disabled={!hasChanges || isSaving}
            className={`px-3 py-1 text-xs rounded-lg transition-colors ${
              hasChanges && !isSaving
                ? 'bg-spore-highlight hover:bg-spore-highlight-hover text-white'
                : 'bg-spore-accent/30 text-spore-muted cursor-not-allowed'
            }`}
          >
            {isSaving ? '保存中...' : '保存'}
          </button>
          <button
            onClick={loadNote}
            className="p-1.5 hover:bg-spore-accent rounded-lg transition-colors"
            title="刷新"
          >
            <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
        </div>
      </div>

      {/* 编辑区域 */}
      <div className="flex-1 overflow-hidden p-2">
        <textarea
          value={content}
          onChange={handleChange}
          placeholder="在这里记录笔记..."
          className="w-full h-full bg-spore-bg/50 border border-spore-border/30 rounded-lg p-3 text-sm text-spore-text resize-none focus:outline-none focus:border-spore-highlight/50 font-mono"
          spellCheck={false}
        />
      </div>
    </div>
  );
};
