/**
 * 文件编辑内容组件 - 显示在标签页内容区域
 */
import React, { useEffect } from 'react';
import { useEditorStore } from '../../stores/editorStore';

export const FileEditorContent: React.FC = () => {
  const {
    openFiles,
    activeFilePath,
    isLoading,
    isSaving,
    error,
    updateContent,
    saveFile,
  } = useEditorStore();

  const activeFile = openFiles.find((f) => f.path === activeFilePath);

  // Ctrl+S 保存
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 's' && activeFile?.hasChanges) {
        e.preventDefault();
        saveFile();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [activeFile?.hasChanges, saveFile]);

  if (!activeFile) {
    return (
      <div className="flex-1 flex items-center justify-center text-spore-muted">
        选择一个文件进行编辑
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* 工具栏 */}
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-spore-border/20 bg-spore-card/50">
        <div className="flex items-center gap-2 text-xs text-spore-muted truncate">
          <span className="truncate">{activeFile.path}</span>
        </div>
        <div className="flex items-center gap-2">
          {error && <span className="text-xs text-spore-error">{error}</span>}
          <button
            onClick={() => saveFile()}
            disabled={!activeFile.hasChanges || isSaving}
            className={`px-2.5 py-1 text-xs rounded transition-colors ${
              activeFile.hasChanges && !isSaving
                ? 'bg-spore-highlight hover:bg-spore-highlight-hover text-white'
                : 'bg-spore-accent/30 text-spore-muted cursor-not-allowed'
            }`}
            title="保存 (Ctrl+S)"
          >
            {isSaving ? '保存中...' : '保存'}
          </button>
        </div>
      </div>

      {/* 编辑区域 */}
      <div className="flex-1 overflow-hidden p-2">
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <span className="text-spore-muted">加载中...</span>
          </div>
        ) : (
          <textarea
            value={activeFile.content}
            onChange={(e) => updateContent(e.target.value)}
            className="w-full h-full bg-spore-bg/50 border border-spore-border/30 rounded-lg p-4 text-sm text-spore-text resize-none focus:outline-none focus:border-spore-highlight/50 font-mono"
            spellCheck={false}
          />
        )}
      </div>
    </div>
  );
};
