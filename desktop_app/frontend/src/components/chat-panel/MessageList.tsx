/**
 * 消息列表组件 - 现代化设计
 */
import React, { useRef, useEffect, useState } from 'react';
import { useChatStore } from '../../stores/chatStore';
import { MessageDetailButton, MessageDetailContent } from './MessageDetail';

export const MessageList: React.FC = () => {
  const messages = useChatStore((state) => state.activeMessages());
  const isGenerating = useChatStore((state) => state.isGenerating());
  const containerRef = useRef<HTMLDivElement>(null);
  
  // 为每条消息维护展开状态
  const [expandedMessages, setExpandedMessages] = useState<Set<string>>(new Set());

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
          <h3 className="text-lg font-medium text-spore-text mb-2">开始对话</h3>
          <p className="text-sm text-spore-muted max-w-sm">
            输入消息与 Spore AI 交流，或使用右上角菜单执行命令
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {messages.map((message) => (
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
                    <div className="whitespace-pre-wrap break-all text-sm leading-relaxed overflow-hidden">
                      {message.content}
                    </div>
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
