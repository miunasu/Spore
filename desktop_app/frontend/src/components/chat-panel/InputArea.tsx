/**
 * 输入区域组件 - 现代化设计
 * 支持粘贴系统文件：解析路径并在发送时一并提交
 */
import React, { useState, useRef, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { useChatStore } from '../../stores/chatStore';
import { CommandMenu } from './CommandMenu';
import { ConfirmBar } from './ConfirmBar';
import { useT } from '../../i18n';

interface InputAreaProps {
  /** mini 模式：隐藏底部提示文字，输入框更紧凑 */
  mini?: boolean;
}

type SystemFileClipboard = {
  paths: string[];
  operation: string;
};

/** 从路径中取文件名，用于附件芯片展示 */
function getFileName(path: string): string {
  const normalized = path.replace(/\\/g, '/');
  const parts = normalized.split('/').filter(Boolean);
  return parts[parts.length - 1] || path;
}

export const InputArea: React.FC<InputAreaProps> = ({ mini = false }) => {
  const t = useT();
  const { inputValue, setInputValue, sendMessage, interrupt } = useChatStore();
  const isGenerating = useChatStore((state) => state.isGenerating());
  const backendStatus = useChatStore(
    (state) => state.activeConversation()?.backendStatus
  );
  const [isComposing, setIsComposing] = useState(false);
  const [attachedPaths, setAttachedPaths] = useState<string[]>([]);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  // 防止 paste 事件中异步读取剪贴板时重复处理
  const pasteHandlingRef = useRef(false);

  // 后端是否就绪
  const isBackendReady = backendStatus === 'running';
  const isBackendStarting = backendStatus === 'starting' || backendStatus === 'none';
  const isBackendError = backendStatus === 'error';

  // 自动调整高度
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 200) + 'px';
    }
  }, [inputValue]);

  const addAttachedPaths = (paths: string[]) => {
    if (!paths.length) return;
    setAttachedPaths((prev) => {
      const seen = new Set(prev);
      const next = [...prev];
      for (const path of paths) {
        const normalized = path.trim();
        if (!normalized || seen.has(normalized)) continue;
        seen.add(normalized);
        next.push(normalized);
      }
      return next;
    });
  };

  const removeAttachedPath = (path: string) => {
    setAttachedPaths((prev) => prev.filter((item) => item !== path));
  };

  const handleSubmit = () => {
    if (isGenerating) return;
    const content = inputValue.trim();
    if (!content && attachedPaths.length === 0) return;
    sendMessage(content, attachedPaths);
    setAttachedPaths([]);
  };

  const handleInterrupt = () => {
    void interrupt();
    window.setTimeout(() => textareaRef.current?.focus(), 0);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey && !isComposing) {
      e.preventDefault();
      handleSubmit();
    }
  };

  /**
   * 粘贴处理：
   * 1. 若系统剪贴板是文件（Windows CF_HDROP），通过 Tauri get_file_clipboard 取真实路径
   * 2. 若浏览器剪贴板项里有 file 类型，也尝试走同一路径解析
   * 3. 纯文本粘贴保持默认行为
   */
  const handlePaste = (e: React.ClipboardEvent<HTMLTextAreaElement>) => {
    if (isGenerating || !isBackendReady || pasteHandlingRef.current) {
      return;
    }

    const clipboardData = e.clipboardData;
    const hasBrowserFiles = clipboardData
      ? Array.from(clipboardData.items || []).some((item) => item.kind === 'file')
      : false;
    // 资源管理器复制文件时，text/plain 往往为空或仅有文件名；有 file 项时优先当文件处理
    const plainText = clipboardData?.getData('text/plain')?.trim() ?? '';

    // 没有明显文件迹象时，交给默认文本粘贴
    if (!hasBrowserFiles && plainText) {
      return;
    }

    // 有 file 项，或完全没有文本（可能是纯文件剪贴板）时，异步解析系统文件路径
    e.preventDefault();
    pasteHandlingRef.current = true;

    void (async () => {
      try {
        const systemClipboard = await invoke<SystemFileClipboard | null>('get_file_clipboard');
        const paths = systemClipboard?.paths?.filter(Boolean) ?? [];
        if (paths.length > 0) {
          addAttachedPaths(paths);
          return;
        }

        // 系统剪贴板没有文件：若用户剪贴板其实是文本，补回插入
        if (plainText) {
          const el = textareaRef.current;
          if (el) {
            const start = el.selectionStart ?? inputValue.length;
            const end = el.selectionEnd ?? inputValue.length;
            const next = inputValue.slice(0, start) + plainText + inputValue.slice(end);
            setInputValue(next);
          } else {
            setInputValue(inputValue + plainText);
          }
        }
      } catch (error) {
        console.error('解析粘贴文件路径失败:', error);
        // 失败时尽量恢复文本粘贴，避免用户输入丢失
        if (plainText) {
          setInputValue(inputValue + plainText);
        }
      } finally {
        pasteHandlingRef.current = false;
      }
    })();
  };

  const canSend =
    Boolean(inputValue.trim() || attachedPaths.length > 0) && isBackendReady && !isGenerating;

  return (
    <div>
      {/* 确认栏（阻塞：删除 / 高危操作确认） */}
      <ConfirmBar />

      <div className="bg-spore-card border border-spore-border/50 rounded-2xl shadow-card p-2 transition-all focus-within:border-spore-highlight/50 focus-within:shadow-glow">
        {/* 已粘贴文件路径附件条 */}
        {attachedPaths.length > 0 && (
          <div className="flex flex-wrap gap-1.5 px-2 pt-1 pb-2">
            {attachedPaths.map((path) => (
              <div
                key={path}
                className="group flex items-center gap-1.5 max-w-full bg-spore-accent/40 border border-spore-border/60 rounded-lg px-2 py-1 text-xs text-spore-text"
                title={path}
              >
                <svg className="w-3.5 h-3.5 flex-shrink-0 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"
                  />
                </svg>
                <span className="truncate max-w-[180px]">{getFileName(path)}</span>
                <button
                  type="button"
                  onClick={() => removeAttachedPath(path)}
                  className="flex-shrink-0 w-4 h-4 flex items-center justify-center rounded hover:bg-spore-border/60 text-spore-muted hover:text-spore-text"
                  title={t('inputArea.removeAttachment')}
                  aria-label={t('inputArea.removeAttachment')}
                >
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            ))}
          </div>
        )}

        <div className="flex items-end gap-2">
          <textarea
            ref={textareaRef}
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            onPaste={handlePaste}
            onCompositionStart={() => setIsComposing(true)}
            onCompositionEnd={() => setIsComposing(false)}
            placeholder={
              isBackendError
                ? t('inputArea.backendError')
                : isBackendStarting
                  ? t('inputArea.backendStarting')
                  : isGenerating
                    ? t('inputArea.generating')
                    : attachedPaths.length > 0
                      ? t('inputArea.placeholderWithFiles')
                      : t('inputArea.placeholder')
            }
            disabled={isGenerating || !isBackendReady}
            className="flex-1 bg-transparent px-3 py-2 text-sm resize-none focus:outline-none disabled:opacity-50 placeholder:text-spore-muted min-h-[40px] max-h-[200px]"
            rows={1}
          />

          {/* 右侧按钮组 - 水平并排 */}
          <div className="flex items-center gap-1 flex-shrink-0">
            {/* 命令菜单 - 三个点竖直图标 */}
            <CommandMenu vertical mini={mini} />

            {/* 发送/停止按钮 */}
            {isGenerating ? (
              <button
                onClick={handleInterrupt}
                className="flex items-center justify-center w-9 h-9 bg-spore-error hover:bg-spore-error/80 text-white rounded-lg transition-all cursor-pointer z-50"
                title={t('common.stop')}
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            ) : (
              <button
                onClick={handleSubmit}
                disabled={!canSend}
                className="flex items-center justify-center w-9 h-9 bg-spore-accent hover:bg-spore-border text-spore-text rounded-lg transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                title={t('common.send')}
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                </svg>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* 提示文字（mini 模式下省略） */}
      {!mini && (
        <div className="flex items-center justify-center text-xs text-spore-muted mt-2 px-1">
          <span className="text-center">
            {t('inputArea.inputHint')}
          </span>
        </div>
      )}
    </div>
  );
};
