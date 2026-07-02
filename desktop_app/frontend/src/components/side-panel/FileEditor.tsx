/**
 * 文件编辑器组件
 */
import React, { useRef, useEffect, useCallback } from 'react';
import { LineNumberedTextarea } from '../common/LineNumberedTextarea';
import { useFileStore } from '../../stores/fileStore';

export const FileEditor: React.FC = () => {
  const {
    editingFile,
    editingContent,
    editingScrollTop,
    setEditingContent,
    setEditingScrollTop,
    saveFile,
    closeEditor,
    isDirty,
  } = useFileStore();

  const editorRef = useRef<HTMLDivElement>(null);
  const dirty = isDirty();

  // Ctrl+S 保存快捷键
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
      e.preventDefault();
      saveFile();
    }
  }, [saveFile]);

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  // 恢复滚动位置
  useEffect(() => {
    const textarea = editorRef.current?.querySelector('textarea');
    if (textarea && editingScrollTop > 0) {
      textarea.scrollTop = editingScrollTop;
    }
  }, [editingFile]); // 只在文件切换时恢复

  // 保存滚动位置
  const handleScroll = (e: React.UIEvent<HTMLTextAreaElement>) => {
    setEditingScrollTop(e.currentTarget.scrollTop);
  };

  if (!editingFile) return null;

  return (
    <div className="h-full flex flex-col">
      {/* 工具栏 */}
      <div className="flex items-center justify-between p-2 border-b border-spore-accent">
        <div className="flex items-center gap-2 text-xs">
          <button
            onClick={closeEditor}
            className="p-1 hover:bg-spore-accent rounded"
            title="返回"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </button>
          <span className="text-spore-muted truncate">
            {editingFile.name}
            {dirty && <span className="text-spore-warning ml-1">●</span>}
          </span>
        </div>
        <button
          onClick={saveFile}
          disabled={!dirty}
          className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
            dirty 
              ? 'bg-spore-highlight text-white hover:bg-spore-highlight/80' 
              : 'bg-spore-accent text-spore-muted cursor-not-allowed'
          }`}
          title="Ctrl+S"
        >
          保存
        </button>
      </div>

      {/* 编辑区域 */}
      <div ref={editorRef} className="flex-1 overflow-hidden p-2">
        <LineNumberedTextarea
          value={editingContent}
          onChange={(e) => setEditingContent(e.target.value)}
          onScroll={handleScroll}
          spellCheck={false}
        />
      </div>
    </div>
  );
};
