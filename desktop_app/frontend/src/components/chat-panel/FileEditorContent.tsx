import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { LineNumberedTextarea } from '../common/LineNumberedTextarea';
import { SafeMarkdownRenderer } from '../common/SafeMarkdownRenderer';
import {
  MAX_HIGHLIGHT_CHARS,
  SyntaxHighlighter,
  getSyntaxLanguage,
} from '../common/SyntaxHighlighter';
import { isSemanticMarkdownFile } from '../common/codeLanguages';
import { HtmlPreview, isHtmlFile } from '../common/HtmlPreview';
import { useEditorStore } from '../../stores/editorStore';
import { useSettingsStore } from '../../stores/settingsStore';
import { useT } from '../../i18n';

type ViewMode = 'preview' | 'edit';

type ScrollPosition = {
  top: number;
  left: number;
};

class FilePreviewBoundary extends React.Component<
  { children: React.ReactNode; resetKey: string; fallbackText: string },
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
          {this.props.fallbackText}
        </div>
      );
    }

    return this.props.children;
  }
}

export function shouldUseMarkdownFilePreview(fileName: string, content: string) {
  return isSemanticMarkdownFile(fileName) && content.length <= MAX_HIGHLIGHT_CHARS;
}

export function getHtmlArtifactIdFromPath(filePath: string): string | undefined {
  const normalized = filePath.replace(/\\/g, '/');
  const match = /^html\/([a-z0-9][a-z0-9._-]{0,79})\.html$/i.exec(normalized);
  return match?.[1].toLowerCase();
}

export const FileEditorContent: React.FC = () => {
  const t = useT();
  const htmlRenderingEnabled = useSettingsStore((state) => state.htmlRenderingEnabled);
  const frontendAgentEnabled = useSettingsStore((state) => state.frontendAgentEnabled);
  const toggleFrontendAgent = useSettingsStore((state) => state.toggleFrontendAgent);
  const {
    openFiles,
    activeFilePath,
    isLoading,
    isSaving,
    error,
    updateContent,
    replacePersistedContent,
    saveFile,
  } = useEditorStore();

  const [viewMode, setViewMode] = useState<ViewMode>('preview');
  const previewRef = useRef<HTMLDivElement>(null);
  const editRef = useRef<HTMLTextAreaElement>(null);
  const scrollPositionsRef = useRef(new Map<string, ScrollPosition>());
  const activeFile = openFiles.find((file) => file.path === activeFilePath);
  const fileName = activeFile?.path || activeFile?.name || '';
  const language = useMemo(
    () => getSyntaxLanguage(fileName, activeFile?.content ?? ''),
    [activeFile?.content, fileName]
  );
  const useMarkdownPreview = Boolean(
    activeFile && shouldUseMarkdownFilePreview(fileName, activeFile.content)
  );
  const useHtmlPreview = Boolean(activeFile && htmlRenderingEnabled && isHtmlFile(fileName));

  const getScrollKey = useCallback(
    (mode: ViewMode) => activeFilePath ? `${activeFilePath}:${mode}` : null,
    [activeFilePath]
  );

  const saveScrollPosition = useCallback((mode: ViewMode, element: HTMLElement) => {
    const key = getScrollKey(mode);
    if (!key) return;
    scrollPositionsRef.current.set(key, {
      top: element.scrollTop,
      left: element.scrollLeft,
    });
  }, [getScrollKey]);

  useEffect(() => {
    setViewMode('preview');
  }, [activeFilePath]);

  useLayoutEffect(() => {
    const key = getScrollKey(viewMode);
    const element = viewMode === 'preview' ? previewRef.current : editRef.current;
    if (!key || !element) return;
    const position = scrollPositionsRef.current.get(key);
    if (!position) return;
    element.scrollTop = position.top;
    element.scrollLeft = position.left;
    if (element instanceof HTMLTextAreaElement) {
      element.dispatchEvent(new Event('scroll'));
    }
  }, [activeFilePath, getScrollKey, useHtmlPreview, useMarkdownPreview, viewMode]);

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

  const handleViewModeChange = (nextMode: ViewMode) => {
    if (nextMode === viewMode) return;
    const currentElement = viewMode === 'preview' ? previewRef.current : editRef.current;
    if (currentElement) {
      saveScrollPosition(viewMode, currentElement);
      const nextKey = getScrollKey(nextMode);
      if (nextKey && !scrollPositionsRef.current.has(nextKey)) {
        scrollPositionsRef.current.set(nextKey, {
          top: currentElement.scrollTop,
          left: currentElement.scrollLeft,
        });
      }
    }
    setViewMode(nextMode);
  };

  if (!activeFile) {
    return (
      <div className="flex-1 flex items-center justify-center text-spore-muted">
        {isLoading ? t('common.loading') : t('chatPanel.fileEditorContent.selectFile')}
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
          {useHtmlPreview && (
            <button
              onClick={toggleFrontendAgent}
              className={`flex items-center gap-1.5 px-2 py-1 text-xs rounded border transition-colors ${
                frontendAgentEnabled
                  ? 'border-spore-highlight/50 bg-spore-highlight/10 text-spore-highlight hover:bg-spore-highlight/20'
                  : 'border-spore-border/30 bg-spore-bg/40 text-spore-muted hover:bg-spore-accent/50 hover:text-spore-text'
              }`}
              title={frontendAgentEnabled
                ? t('chatPanel.htmlPreview.frontendAgentDisableTitle')
                : t('chatPanel.htmlPreview.frontendAgentEnableTitle')}
            >
              <span className={`inline-block h-1.5 w-1.5 rounded-full flex-shrink-0 ${
                frontendAgentEnabled ? 'bg-spore-highlight' : 'bg-spore-muted'
              }`} />
              {t('chatPanel.htmlPreview.frontendAgent')}
            </button>
          )}
          <div className="flex overflow-hidden rounded-md border border-spore-border/30 bg-spore-bg/40">
            <button
              onClick={() => handleViewModeChange('preview')}
              className={`px-2.5 py-1 text-xs transition-colors ${
                viewMode === 'preview'
                  ? 'bg-spore-highlight text-white'
                  : 'text-spore-muted hover:bg-spore-accent/50 hover:text-spore-text'
              }`}
              title={t('chatPanel.fileEditorContent.previewTitle')}
            >
              {t('chatPanel.fileEditorContent.preview')}
            </button>
            <button
              onClick={() => handleViewModeChange('edit')}
              className={`px-2.5 py-1 text-xs transition-colors ${
                viewMode === 'edit'
                  ? 'bg-spore-highlight text-white'
                  : 'text-spore-muted hover:bg-spore-accent/50 hover:text-spore-text'
              }`}
              title={t('chatPanel.fileEditorContent.editTitle')}
            >
              {t('common.edit')}
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
            title={t('chatPanel.fileEditorContent.saveTitle')}
          >
            {isSaving ? t('chatPanel.fileEditorContent.saving') : t('common.save')}
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-hidden p-2">
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <span className="text-spore-muted">{t('common.loading')}</span>
          </div>
        ) : viewMode === 'preview' ? (
          <FilePreviewBoundary
            key={activeFile.path}
            resetKey={`${activeFile.path}:${activeFile.content.length}:${language.id}:${activeFile.content.slice(0, 256)}`}
            fallbackText={t('chatPanel.fileEditorContent.previewFailed')}
          >
            {useHtmlPreview ? (
              <HtmlPreview
                content={activeFile.content}
                title={t('chatPanel.htmlPreview.fileTitle', { name: activeFile.name })}
                variant="file"
                artifactId={getHtmlArtifactIdFromPath(activeFile.path)}
                onContentChange={(content) => replacePersistedContent(activeFile.path, content)}
                frontendAgentEnabled={frontendAgentEnabled}
              />
            ) : useMarkdownPreview ? (
              <SafeMarkdownRenderer
                content={activeFile.content}
                variant="file"
                containerRef={previewRef}
                onScroll={(event) => saveScrollPosition('preview', event.currentTarget)}
              />
            ) : (
              <SyntaxHighlighter
                content={activeFile.content}
                fileName={fileName}
                language={language.id}
                viewerRef={previewRef}
                onScroll={(event) => saveScrollPosition('preview', event.currentTarget)}
              />
            )}
          </FilePreviewBoundary>
        ) : (
          <LineNumberedTextarea
            value={activeFile.content}
            onChange={(event) => updateContent(event.target.value)}
            onScroll={(event) => saveScrollPosition('edit', event.currentTarget)}
            textareaRef={editRef}
            spellCheck={false}
          />
        )}
      </div>
    </div>
  );
};
