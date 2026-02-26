/**
 * Agent 监控组件 - 支持 JSON 格式化显示
 * 轮询逻辑已移至 App.tsx 级别，此组件只负责显示
 */
import React, { useRef, useEffect, useMemo, memo } from 'react';
import { useAgentStore } from '../../stores/agentStore';
import { shallow } from 'zustand/shallow';

// 尝试解析并格式化 JSON
const formatMessage = (
  message: string
): { isJson: boolean; formatted: string } => {
  if (!message) return { isJson: false, formatted: message };

  const trimmed = message.trim();

  // 检查是否像 JSON
  if (
    (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
    (trimmed.startsWith('[') && trimmed.endsWith(']'))
  ) {
    try {
      const parsed = JSON.parse(trimmed);
      return {
        isJson: true,
        formatted: JSON.stringify(parsed, null, 2),
      };
    } catch {
      // 不是有效 JSON
    }
  }

  return { isJson: false, formatted: message };
};

// JSON 语法高亮
const JsonHighlight: React.FC<{ content: string }> = memo(({ content }) => {
  const highlighted = useMemo(() => {
    return content
      .replace(/"([^"]+)":/g, '<span class="text-spore-info">"$1"</span>:')
      .replace(
        /: "([^"]*)"/g,
        ': <span class="text-spore-highlight">"$1"</span>'
      )
      .replace(/: (\d+\.?\d*)/g, ': <span class="text-yellow-400">$1</span>')
      .replace(/: (true|false)/g, ': <span class="text-red-400">$1</span>')
      .replace(/: (null)/g, ': <span class="text-spore-muted">$1</span>');
  }, [content]);

  return (
    <pre
      className="whitespace-pre-wrap break-all leading-relaxed"
      dangerouslySetInnerHTML={{ __html: highlighted }}
    />
  );
});

JsonHighlight.displayName = 'JsonHighlight';

// 单条日志项组件
const LogItem = memo(
  ({ log }: { log: { message: string; level: string; timestamp: number } }) => {
    const { isJson, formatted } = useMemo(
      () => formatMessage(log.message),
      [log.message]
    );

    const levelColor =
      {
        INFO: 'text-spore-text',
        WARNING: 'text-yellow-400',
        ERROR: 'text-red-400',
        SUCCESS: 'text-green-400',
      }[log.level] || 'text-spore-text';

    return (
      <div className="py-1 px-1.5 rounded bg-spore-bg/30">
        <span className="text-spore-muted text-[10px]">
          {new Date(log.timestamp * 1000).toLocaleTimeString()}
        </span>
        <div className={`mt-0.5 ${levelColor}`}>
          {isJson ? (
            <JsonHighlight content={formatted} />
          ) : (
            <span className="break-all whitespace-pre-wrap">{formatted}</span>
          )}
        </div>
      </div>
    );
  }
);

LogItem.displayName = 'LogItem';

// 独立的 Agent 面板，直接从 agentsById 订阅
const AgentPanelConnected: React.FC<{ agentId: string; height: string }> = memo(({ agentId, height }) => {
  // 直接订阅这个特定 agent 的数据，使用 shallow 比较
  const agent = useAgentStore((state) => state.agentsById[agentId], shallow);
  
  const containerRef = useRef<HTMLDivElement>(null);
  const shouldAutoScroll = useRef(true);

  // 自动滚动到底部
  useEffect(() => {
    if (shouldAutoScroll.current && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [agent?.logs.length]);

  // 检测用户是否手动滚动
  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    shouldAutoScroll.current = scrollHeight - scrollTop - clientHeight < 50;
  };

  if (!agent) return null;

  // 状态颜色
  const statusColor =
    {
      running: 'text-green-400',
      completed: 'text-blue-400',
      interrupted: 'text-yellow-400',
      error: 'text-red-400',
    }[agent.status] || 'text-spore-muted';

  // 只显示最近的日志
  const visibleLogs = agent.logs.slice(-50);

  return (
    <div
      className="flex flex-col border-b border-spore-accent last:border-0 overflow-hidden"
      style={{ height }}
    >
      {/* 标题栏 */}
      <div className="flex items-center justify-between px-2 py-1 bg-spore-accent/30 text-xs">
        <span className="font-medium truncate">{agent.name}</span>
        <span className={`${statusColor} capitalize`}>{agent.status}</span>
      </div>

      {/* 日志区域 */}
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto p-2 text-xs font-mono"
        onScroll={handleScroll}
      >
        {visibleLogs.length === 0 ? (
          <div className="text-spore-muted text-center py-2">等待输出...</div>
        ) : (
          <div className="space-y-1">
            {visibleLogs.map((log, index) => (
              <LogItem key={index} log={log} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
});

AgentPanelConnected.displayName = 'AgentPanelConnected';

export const AgentMonitor: React.FC = () => {
  // 只订阅 agentIds，使用 shallow 比较
  const agentIds = useAgentStore((state) => state.agentIds, shallow);
  const agentCount = agentIds.length;

  // 空状态
  if (agentCount === 0) {
    return (
      <div className="h-full flex items-center justify-center text-spore-muted text-sm">
        <div className="text-center">
          <svg
            className="w-12 h-12 mx-auto mb-2 opacity-50"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
            />
          </svg>
          <p>暂无活跃的 Agent</p>
        </div>
      </div>
    );
  }

  // 计算每个 Agent 的高度
  const agentHeight = `${100 / Math.min(agentCount, 5)}%`;

  return (
    <div className="h-full flex flex-col">
      {agentIds.slice(0, 5).map((id) => (
        <AgentPanelConnected key={id} agentId={id} height={agentHeight} />
      ))}
    </div>
  );
};
