import React, { useEffect, useMemo, useState } from 'react';
import { LineNumberedTextarea } from '../common/LineNumberedTextarea';
import { SyntaxHighlighter, getSyntaxLanguage } from '../common/SyntaxHighlighter';
import { useEditorStore } from '../../stores/editorStore';

type ViewMode = 'preview' | 'edit';

class SyntaxPreviewBoundary extends React.Component<
  { children: React.ReactNode; resetKey: string },
  { hasError: boolean }
> {
  state = { hasError: false };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error: Error) {
    console.error('File preview failed:', error);
  }

  componentDidUpdate(previousProps: { resetKey: string }) {
    if (previousProps.resetKey !== this.props.resetKey && this.state.hasError) {
      this.setState({ hasError: false });
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex h-full items-center justify-center rounded-lg border border-spore-border/30 bg-spore-bg/50 p-4 text-sm text-spore-muted">
          预览失败，请切换到编辑模式查看原始内容
        </div>
      );
    }

    return this.props.children;
  }
}

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

  const [viewMode, setViewMode] = useState<ViewMode>('preview');
  const activeFile = openFiles.find((file) => file.path === activeFilePath);
  const language = useMemo(
    () => getSyntaxLanguage(activeFile?.path || activeFile?.name || '', activeFile?.content ?? ''),
    [activeFile?.content, activeFile?.name, activeFile?.path]
  );

  useEffect(() => {
    setViewMode('preview');
  }, [activeFilePath]);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 's' && activeFile?.hasChanges) {
        event.preventDefault();
        saveFile();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [activeFile?.hasChanges, saveFile]);

  if (!activeFile) {
    return (
      <div className="flex-1 flex items-center justify-center text-spore-muted">
        {isLoading ? '加载中...' : '选择一个文件进行查看'}
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <div className="flex items-center justify-between gap-3 px-3 py-1.5 border-b border-spore-border/20 bg-spore-card/50">
        <div className="flex items-center gap-2 min-w-0 text-xs text-spore-muted">
          <span className="truncate">{activeFile.path}</span>
          <span className="flex-shrink-0 rounded border border-spore-border/30 bg-spore-bg/50 px-1.5 py-0.5">
            {language.label}
          </span>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          <div className="flex overflow-hidden rounded-md border border-spore-border/30 bg-spore-bg/40">
            <button
              onClick={() => setViewMode('preview')}
              className={`px-2.5 py-1 text-xs transition-colors ${
                viewMode === 'preview'
                  ? 'bg-spore-highlight text-white'
                  : 'text-spore-muted hover:bg-spore-accent/50 hover:text-spore-text'
              }`}
              title="语法高亮预览"
            >
              预览
            </button>
            <button
              onClick={() => setViewMode('edit')}
              className={`px-2.5 py-1 text-xs transition-colors ${
                viewMode === 'edit'
                  ? 'bg-spore-highlight text-white'
                  : 'text-spore-muted hover:bg-spore-accent/50 hover:text-spore-text'
              }`}
              title="编辑文件内容"
            >
              编辑
            </button>
          </div>

          {error && <span className="max-w-48 truncate text-xs text-spore-error">{error}</span>}
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

      <div className="flex-1 overflow-hidden p-2">
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <span className="text-spore-muted">加载中...</span>
          </div>
        ) : viewMode === 'preview' ? (
          <SyntaxPreviewBoundary
            key={activeFile.path}
            resetKey={`${activeFile.path}:${activeFile.content.length}:${language.id}`}
          >
            <SyntaxHighlighter
              content={activeFile.content}
              fileName={activeFile.path || activeFile.name}
            />
          </SyntaxPreviewBoundary>
        ) : (
          <LineNumberedTextarea
            value={activeFile.content}
            onChange={(event) => updateContent(event.target.value)}
            spellCheck={false}
          />
        )}
      </div>
    </div>
  );
};
