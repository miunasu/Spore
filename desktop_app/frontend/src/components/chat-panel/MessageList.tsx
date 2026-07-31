/**
 * 消息列表组件 - 现代化设计
 */
import React, { useRef, useEffect, useState } from 'react';
import { useChatStore } from '../../stores/chatStore';
import { MessageDetailButton, MessageDetailContent } from './MessageDetail';
import { AssistantMessageContent } from './AssistantMessageContent';
import { useT } from '../../i18n';
import { getAttachmentName } from '../../utils/messageAttachments';

export const MessageList: React.FC = () => {
  const t = useT();
  // 直接订阅 conversations 和 activeConversationId，确保状态变化时重新渲染
  const conversations = useChatStore((state) => state.conversations);
  const activeConversationId = useChatStore((state) => state.activeConversationId);
  const isGenerating = useChatStore((state) => state.isGenerating());
  const containerRef = useRef<HTMLDivElement>(null);
  
  // 根据当前活动对话获取消息
  const messages = React.useMemo(() => {
    const activeConv = conversations.find(c => c.id === activeConversationId);
    return activeConv?.messages || [];
  }, [conversations, activeConversationId]);
  
  // 为每条消息维护展开状态
  const [expandedMessages, setExpandedMessages] = useState<Set<string>>(new Set());

  // 切换对话时清空展开状态
  useEffect(() => {
    setExpandedMessages(new Set());
  }, [activeConversationId]);

  // 自动滚动到底部
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [messages]);

  const toggleMessageDetail = (messageId: string) => {
    setExpandedMessages(prev => {
      const newSet = new Set(prev);
      if (newSet.has(messageId)) {
        newSet.delete(messageId);
      } else {
        newSet.add(messageId);
      }
      return newSet;
    });
  };

  return (
    <div
      ref={containerRef}
      className="h-full overflow-y-auto overflow-x-hidden px-6 py-4"
    >
      {messages.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-full text-center">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-spore-highlight/20 to-spore-info/20 flex items-center justify-center mb-4">
            <svg className="w-8 h-8 text-spore-highlight" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
          </div>
          <h3 className="text-lg font-medium text-spore-text mb-2">{t('messageList.startConversation')}</h3>
          <p className="text-sm text-spore-muted max-w-sm">
            {t('messageList.emptyHint')}
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {messages.map((message) => message.role === 'system' ? (
            <div key={message.id} className="flex justify-center animate-fade-in">
              <div className="max-w-[85%] rounded-full border border-spore-border/60 bg-spore-card/60 px-4 py-2 text-xs text-spore-muted text-center">
                {message.content}
              </div>
            </div>
          ) : (
            <div
              key={message.id}
              className={`flex gap-4 animate-fade-in ${
                message.role === 'user' ? 'flex-row-reverse' : ''
              }`}
            >
              {/* 头像 */}
              <div className={`flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center ${
                message.role === 'user' 
                  ? 'bg-spore-info/20 text-spore-info' 
                  : 'bg-spore-highlight/20 text-spore-highlight'
              }`}>
                {message.role === 'user' ? (
                  <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clipRule="evenodd" />
                  </svg>
                ) : (
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                )}
              </div>
              
              {/* 消息内容 */}
              <div className={`min-w-0 max-w-[85%] ${message.role === 'user' ? '' : 'flex-1'}`}>
                {/* 消息气泡和按钮的容器 - 使用 items-center 垂直居中 */}
                <div className="flex items-center gap-2">
                  <div className={`inline-block rounded-2xl px-4 py-3 max-w-full text-left ${
                    message.role === 'user'
                      ? 'bg-spore-info text-white rounded-tr-md'
                      : 'bg-spore-card text-spore-text rounded-tl-md'
                  }`}>
                    {message.role === 'assistant' ? (
                      <AssistantMessageContent content={message.content} />
                    ) : (
                      <>
                        {message.content && (
                          <div className="whitespace-pre-wrap break-all text-sm leading-relaxed overflow-hidden">
                            {message.content}
                          </div>
                        )}
                        {message.attachments && message.attachments.length > 0 && (
                          <div className={`flex flex-wrap gap-1.5 ${message.content ? 'mt-2' : ''}`}>
                            {message.attachments.map((path) => (
                              <div
                                key={path}
                                className="flex min-w-0 max-w-full items-center gap-1.5 rounded-lg border border-white/25 bg-black/10 px-2 py-1 text-xs text-white"
                                title={path}
                              >
                                <svg
                                  className="h-3.5 w-3.5 flex-shrink-0"
                                  fill="none"
                                  stroke="currentColor"
                                  viewBox="0 0 24 24"
                                  aria-hidden="true"
                                >
                                  <path
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                    strokeWidth={2}
                                    d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"
                                  />
                                </svg>
                                <span className="max-w-[220px] truncate">{getAttachmentName(path)}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </>
                    )}

                    {/* 命令意图脚注（安全 Agent 解析，持久化显示；恶意标红） */}
                    {message.role === 'assistant' &&
                      message.command_intents &&
                      message.command_intents.length > 0 && (
                      <div className="mt-2.5 pt-2 border-t border-spore-border/40 space-y-1.5">
                        {message.command_intents.map((ci, index) => (
                          <div key={index} className="flex items-start gap-2 min-w-0">
                            <span className="text-xs flex-shrink-0 leading-4">
                              {ci.is_malicious ? '🚨' : '💡'}
                            </span>
                            <div className="flex-1 min-w-0">
                              <div
                                className={`text-xs leading-4 ${
                                  ci.is_malicious ? 'text-red-400 font-medium' : 'text-spore-muted'
                                }`}
                              >
                                {ci.intent}
                              </div>
                              {ci.is_malicious && ci.malicious_reason && (
                                <div className="text-[11px] text-red-400/80 leading-4">
                                  {t('messageList.maliciousReason', { reason: ci.malicious_reason })}
                                </div>
                              )}
                              <div
                                className={`text-[11px] font-mono truncate ${
                                  ci.is_malicious ? 'text-red-400/60' : 'text-spore-muted/60'
                                }`}
                                title={ci.command}
                              >
                                $ {ci.command.replace(/\s+/g, ' ')}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                  
                  {/* 查看详情按钮（仅assistant消息，显示在消息右侧，垂直居中） */}
                  {message.role === 'assistant' && message.sent_messages && (
                    <MessageDetailButton 
                      message={message} 
                      onClick={() => toggleMessageDetail(message.id)}
                      showDetail={expandedMessages.has(message.id)}
                    />
                  )}
                </div>
                
                {/* 详情内容（展开时显示在消息下方） */}
                {message.role === 'assistant' && expandedMessages.has(message.id) && (
                  <MessageDetailContent message={message} />
                )}
              </div>
            </div>
          ))}
          
          {/* 生成中指示器 */}
          {isGenerating && (
            <div className="flex gap-4 animate-fade-in">
              <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-spore-highlight/20 text-spore-highlight flex items-center justify-center">
                <svg className="w-4 h-4 animate-pulse-soft" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <div className="bg-spore-card rounded-2xl rounded-tl-md px-4 py-3">
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 bg-spore-muted rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></span>
                  <span className="w-2 h-2 bg-spore-muted rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></span>
                  <span className="w-2 h-2 bg-spore-muted rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
