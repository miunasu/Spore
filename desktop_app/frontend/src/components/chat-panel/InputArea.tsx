/**
 * 输入区域组件 - 现代化设计
 */
import React, { useState, useRef, useEffect } from 'react';
import { useChatStore } from '../../stores/chatStore';
import { CommandMenu } from './CommandMenu';
import { ConfirmBar } from './ConfirmBar';
import { AgentActivityBar } from './AgentActivityBar';
import { useT } from '../../i18n';

interface InputAreaProps {
  /** mini 模式：隐藏底部提示文字，输入框更紧凑 */
  mini?: boolean;
}

export const InputArea: React.FC<InputAreaProps> = ({ mini = false }) => {
  const t = useT();
  const { inputValue, setInputValue, sendMessage, interrupt } = useChatStore();
  const isGenerating = useChatStore((state) => state.isGenerating());
  const backendStatus = useChatStore(
    (state) => state.activeConversation()?.backendStatus
  );
  const [isComposing, setIsComposing] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

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

  const handleSubmit = () => {
    if (!inputValue.trim() || isGenerating) return;
    sendMessage(inputValue.trim());
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

  return (
    <div>
      {/* Agent 活动提示（非阻塞：命令意图 / 安全扫描）；
          mini 模式下由 MiniModeView 常驻渲染，这里不重复 */}
      {!mini && <AgentActivityBar />}

      {/* 确认栏（阻塞：删除 / 高危操作确认） */}
      <ConfirmBar />
      
      <div className="flex items-end gap-2 bg-spore-card border border-spore-border/50 rounded-2xl shadow-card p-2 transition-all focus-within:border-spore-highlight/50 focus-within:shadow-glow">
        <textarea
          ref={textareaRef}
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyDown={handleKeyDown}
          onCompositionStart={() => setIsComposing(true)}
          onCompositionEnd={() => setIsComposing(false)}
          placeholder={
            isBackendError
              ? t('inputArea.backendError')
              : isBackendStarting
                ? t('inputArea.backendStarting')
                : isGenerating
                  ? t('inputArea.generating')
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
              disabled={!inputValue.trim()}
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
