/**
 * 消息详情组件 - 显示发送和接收的完整消息
 * 分为两部分：按钮（放在消息右侧）和详情内容（放在消息下方）
 */
import React, { useState } from 'react';
import { Message } from '../../types';

interface MessageDetailProps {
  message: Message;
}

// 导出按钮组件
export const MessageDetailButton: React.FC<MessageDetailProps & { onClick: () => void; showDetail: boolean }> = ({ onClick, showDetail }) => {
  return (
    <button
      onClick={onClick}
      className="text-xs text-spore-muted hover:text-spore-text transition-colors flex items-center gap-1 flex-shrink-0"
      title={showDetail ? '隐藏详情' : '查看详情'}
    >
      <svg
        className={`w-3 h-3 transition-transform ${showDetail ? 'rotate-90' : ''}`}
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
      </svg>
      {showDetail ? '隐藏详情' : '查看详情'}
    </button>
  );
};

// 导出详情内容组件
export const MessageDetailContent: React.FC<MessageDetailProps> = ({ message }) => {
  return (
    <div className="mt-3 space-y-3 text-xs">
      {/* 发送的消息 */}
      <div className="bg-spore-bg/50 rounded-lg p-3 border border-spore-border">
        <div className="font-medium text-spore-text mb-2 flex items-center gap-2">
          <svg className="w-4 h-4 text-spore-info" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
          </svg>
          本次发送给LLM的消息 ({message.sent_messages?.length || 0}条)
        </div>
        <div className="text-xs text-spore-muted mb-2">
          仅显示本次请求的内容（system + 当前用户输入），不包含历史记忆
        </div>
        <div className="space-y-2">
          {message.sent_messages?.map((msg, idx) => (
            <div key={idx} className="bg-spore-card/50 rounded p-2">
              <div className="text-spore-muted mb-1">
                <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-medium ${
                  msg.role === 'system' ? 'bg-spore-warning/20 text-spore-warning' :
                  msg.role === 'user' ? 'bg-spore-info/20 text-spore-info' :
                  'bg-spore-highlight/20 text-spore-highlight'
                }`}>
                  {msg.role}
                </span>
              </div>
              <div className="text-spore-text whitespace-pre-wrap break-all max-h-40 overflow-y-auto">
                {msg.content}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 接收的原始响应 */}
      {message.raw_response && (
        <div className="bg-spore-bg/50 rounded-lg p-3 border border-spore-border">
          <div className="font-medium text-spore-text mb-2 flex items-center gap-2">
            <svg className="w-4 h-4 text-spore-highlight" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
            </svg>
            LLM返回的原始响应（包含协议标记）
          </div>
          <div className="bg-spore-card/50 rounded p-2">
            <div className="text-spore-text whitespace-pre-wrap break-all max-h-60 overflow-y-auto font-mono text-[11px]">
              {message.raw_response}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// 默认导出完整组件（保持向后兼容）
export const MessageDetail: React.FC<MessageDetailProps> = ({ message }) => {
  const [showDetail, setShowDetail] = useState(false);

  // 只有assistant消息才有详细信息
  if (message.role !== 'assistant' || !message.sent_messages) {
    return null;
  }

  return (
    <>
      <MessageDetailButton message={message} onClick={() => setShowDetail(!showDetail)} showDetail={showDetail} />
      {showDetail && <MessageDetailContent message={message} />}
    </>
  );
};
