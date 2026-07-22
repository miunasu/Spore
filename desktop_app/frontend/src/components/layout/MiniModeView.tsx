/**
 * Mini 模式视图（类似网易云音乐 mini 模式）
 * 只保留最近两条 LLM 回复消息与辅助 Agent 的实时活动，
 * 鼠标靠近窗口底部时浮现输入栏
 */
import React, { useRef, useEffect, useState } from 'react';
import { useChatStore } from '../../stores/chatStore';
import { useAgentStore } from '../../stores/agentStore';
import { useConfirmStore } from '../../stores/confirmStore';
import { InputArea } from '../chat-panel/InputArea';
import { AgentActivityBar } from '../chat-panel/AgentActivityBar';
import { useT } from '../../i18n';

// 最多保留的 LLM 回复条数
const MAX_ASSISTANT_MESSAGES = 2;

export const MiniModeView: React.FC = () => {
  const t = useT();
  const conversations = useChatStore((state) => state.conversations);
  const activeConversationId = useChatStore((state) => state.activeConversationId);
  const isGenerating = useChatStore((state) => state.isGenerating());

  const agentIds = useAgentStore((state) => state.agentIds);
  const agentsById = useAgentStore((state) => state.agentsById);

  const hasPendingConfirm = useConfirmStore(
    (state) => state.pendingRequests.length > 0
  );

  const containerRef = useRef<HTMLDivElement>(null);
  const [inputHovered, setInputHovered] = useState(false);
  const [inputFocused, setInputFocused] = useState(false);

  // 发送后 textarea 被 disabled，浏览器不会触发 blur，手动清掉聚焦标记
  useEffect(() => {
    if (isGenerating) {
      setInputFocused(false);
    }
  }, [isGenerating]);

  // 鼠标靠近 / 正在输入时可见；
  // 有待确认的高危操作时强制可见（ConfirmBar 在输入栏内，不能被藏起来）
  const showInput = inputHovered || inputFocused || hasPendingConfirm;

  // 最近两条 assistant 回复。
  // 命令解析由安全 Agent 异步研判、往往晚几轮才挂载到"包含该命令的那条消息"上，
  // 此时该消息可能已滚出两条窗口——额外把最新带解析的回复固定在窗口顶部，
  // 保证解析和普通模式一样常驻在对应消息旁。
  const messages = React.useMemo(() => {
    const activeConv = conversations.find((c) => c.id === activeConversationId);
    const all = (activeConv?.messages || []).filter((m) => m.role === 'assistant');
    const recent = all.slice(-MAX_ASSISTANT_MESSAGES);
    for (let i = all.length - 1; i >= 0; i--) {
      const m = all[i];
      if (m.command_intents && m.command_intents.length > 0) {
        if (!recent.includes(m)) {
          return [m, ...recent];
        }
        break;
      }
    }
    return recent;
  }, [conversations, activeConversationId]);

  // 辅助 Agent 活动（沿用 AgentMonitor 的数据源：全部状态都显示，
  // 终态 Agent 会由 agentStore 的定时器自动移除）
  const agents = agentIds.map((id) => agentsById[id]).filter(Boolean);

  // 新消息 / Agent 日志到达时自动滚动到底部
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [messages, agents.length, isGenerating]);

  return (
    <div className="h-full flex flex-col relative bg-spore-bg">
      {/* 消息区域 */}
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto overflow-x-hidden px-3 py-3 space-y-3"
      >
        {messages.length === 0 && agents.length === 0 && !isGenerating ? (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <p className="text-xs text-spore-muted">
              {t('miniModeView.emptyHint')}
            </p>
          </div>
        ) : (
          <>
            {messages.map((message) => (
              <div key={message.id} className="animate-fade-in">
                <div className="bg-spore-card text-spore-text rounded-xl rounded-tl-md px-3 py-2.5">
                  <div className="whitespace-pre-wrap break-all text-xs leading-relaxed overflow-hidden">
                    {message.content}
                  </div>

                  {/* 命令意图脚注（安全 Agent 解析，与普通模式 MessageList 完全一致，恶意标红） */}
                  {message.command_intents && message.command_intents.length > 0 && (
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
                                {t('miniModeView.maliciousReasonLabel')}{ci.malicious_reason}
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
              </div>
            ))}

            {/* 辅助 Agent 实时活动 */}
            {agents.map((agent) => {
              const lastLog = agent.logs[agent.logs.length - 1];
              const dotColor =
                agent.status === 'running'
                  ? 'bg-spore-highlight animate-pulse'
                  : agent.status === 'completed'
                    ? 'bg-spore-success'
                    : agent.status === 'error'
                      ? 'bg-spore-error'
                      : 'bg-spore-muted';
              return (
                <div
                  key={agent.id}
                  className="flex items-center gap-2 px-3 py-2 rounded-xl bg-spore-card/60 border border-spore-border/40 animate-fade-in"
                >
                  <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${dotColor}`} />
                  <span className="text-[11px] font-medium text-spore-highlight flex-shrink-0">
                    {agent.name}
                  </span>
                  <span className="text-[11px] text-spore-muted truncate">
                    {lastLog?.message || agent.status}
                  </span>
                </div>
              );
            })}

            {/* 生成中指示器 */}
            {isGenerating && (
              <div className="bg-spore-card rounded-xl rounded-tl-md px-3 py-2.5 inline-block">
                <div className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 bg-spore-muted rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                  <span className="w-1.5 h-1.5 bg-spore-muted rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                  <span className="w-1.5 h-1.5 bg-spore-muted rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                </div>
              </div>
            )}
          </>
        )}

        {/* 输入栏浮现时垫高，避免遮挡最后一条消息 */}
        {showInput && <div className="h-24 flex-shrink-0" />}
      </div>

      {/* 底部常驻区：Agent 解析常显 + 鼠标靠近时浮现输入栏 */}
      <div
        className="absolute bottom-0 left-0 right-0 z-20"
        onMouseEnter={() => setInputHovered(true)}
        onMouseLeave={() => setInputHovered(false)}
        onFocusCapture={() => setInputFocused(true)}
        onBlurCapture={() => setInputFocused(false)}
      >
        {/* 辅助 Agent 解析（命令意图 / 安全扫描）：不随输入栏隐藏 */}
        <div className="px-2">
          <AgentActivityBar />
        </div>

        {/* 输入栏：收起时高度折叠为 0，不占位、不产生超大悬停区 */}
        <div
          className={`transition-all duration-200 ${
            showInput
              ? 'max-h-64 opacity-100'
              : 'max-h-0 opacity-0 overflow-hidden pointer-events-none'
          }`}
        >
          <div className="px-2 pb-2 pt-1 bg-gradient-to-t from-spore-bg via-spore-bg/90 to-transparent">
            <InputArea mini />
          </div>
        </div>

        {/* 输入栏隐藏时的悬停触发热区 */}
        {!showInput && <div className="h-8" />}
      </div>
    </div>
  );
};
