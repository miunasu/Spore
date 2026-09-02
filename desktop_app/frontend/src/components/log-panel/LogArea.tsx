/**
 * 单个日志区域组件 - 现代美学设计
 */
import React, { useRef, useEffect, useMemo, memo } from 'react';
import { useT } from '../../i18n';
import type { LogType, LogEntry } from '../../types';

interface LogAreaProps {
  type: LogType;
  label: string;
  color: string;
  icon: string;
  logs: LogEntry[];
  onDoubleClick: () => void;
  expanded?: boolean;
}

// 解析日志内容，提取结构化信息
interface ParsedContent {
  type: 'simple' | 'structured' | 'json';
  level?: 'INFO' | 'DEBUG' | 'WARNING' | 'ERROR';
  message: string;
  data?: Record<string, any>;
  rawJson?: string;
}

const parseLogContent = (content: string): ParsedContent => {
  if (!content) return { type: 'simple', message: content };

  const trimmed = content.trim();

  // 检查是否包含 → ERROR: 标记（工具执行失败）
  if (trimmed.includes('→ ERROR:')) {
    return {
      type: 'simple',
      level: 'ERROR',
      message: trimmed,
    };
  }

  // 检查是否是纯 JSON
  if (
    (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
    (trimmed.startsWith('[') && trimmed.endsWith(']'))
  ) {
    try {
      const parsed = JSON.parse(trimmed);
      return {
        type: 'json',
        message: '',
        data: parsed,
        rawJson: JSON.stringify(parsed, null, 2),
      };
    } catch {
      // 继续检查其他格式
    }
  }

  // 检查是否是结构化日志（带前缀的 JSON）
  const jsonMatch = trimmed.match(/^(.+?)\s*(\{[\s\S]*\}|\[[\s\S]*\])$/);
  if (jsonMatch) {
    try {
      const prefix = jsonMatch[1].trim();
      const parsed = JSON.parse(jsonMatch[2]);

      // 提取日志级别
      const levelMatch = prefix.match(/\b(INFO|DEBUG|WARNING|ERROR|WARN)\b/);
      const level = levelMatch ? (levelMatch[1] === 'WARN' ? 'WARNING' : levelMatch[1] as any) : undefined;

      return {
        type: 'structured',
        level,
        message: prefix,
        data: parsed,
      };
    } catch {
      // 继续检查其他格式
    }
  }

  // 简单日志，尝试提取级别
  const levelMatch = trimmed.match(/\b(INFO|DEBUG|WARNING|ERROR|WARN)\b/);
  const level = levelMatch ? (levelMatch[1] === 'WARN' ? 'WARNING' : levelMatch[1] as any) : undefined;

  return {
    type: 'simple',
    level,
    message: trimmed,
  };
};

// 日志级别样式配置
const levelStyles = {
  INFO: {
    bg: 'bg-blue-500/10',
    text: 'text-blue-400',
    border: 'border-blue-500/30',
    icon: '●',
  },
  DEBUG: {
    bg: 'bg-gray-500/10',
    text: 'text-gray-400',
    border: 'border-gray-500/30',
    icon: '◆',
  },
  WARNING: {
    bg: 'bg-yellow-500/10',
    text: 'text-yellow-400',
    border: 'border-yellow-500/30',
    icon: '▲',
  },
  ERROR: {
    bg: 'bg-red-500/10',
    text: 'text-red-400',
    border: 'border-red-500/30',
    icon: '✕',
  },
};

// 数据展示组件 - 以卡片形式展示键值对
const DataCard: React.FC<{ data: Record<string, any>; compact?: boolean }> = memo(({ data, compact = false }) => {
  const entries = Object.entries(data);

  if (entries.length === 0) return null;

  return (
    <div className={`grid gap-1.5 ${compact ? 'text-[10px]' : 'text-xs'}`}>
      {entries.map(([key, value]) => {
        const valueStr = typeof value === 'object'
          ? JSON.stringify(value)
          : String(value);

        return (
          <div key={key} className="flex items-start gap-2 group">
            <span className="text-spore-highlight font-medium flex-shrink-0 min-w-[80px]">
              {key}
            </span>
            <span className="text-spore-muted flex-shrink-0">:</span>
            <span className="text-spore-text break-all flex-1 group-hover:text-spore-highlight transition-colors">
              {valueStr}
            </span>
          </div>
        );
      })}
    </div>
  );
});

DataCard.displayName = 'DataCard';

// 格式化工具日志消息，给主工具名添加颜色
const formatToolMessage = (message: string, isError: boolean): JSX.Element => {
  // 检查是否是工具格式：tool_name → ...
  const arrowIndex = message.indexOf('→');
  if (arrowIndex === -1) {
    // 没有箭头，直接返回
    return <span>{message}</span>;
  }

  const toolName = message.substring(0, arrowIndex).trim();
  const restMessage = message.substring(arrowIndex);

  // 根据是否错误选择颜色
  const toolColor = isError ? 'text-spore-error font-semibold' : 'text-spore-highlight font-medium';

  return (
    <span>
      <span className={toolColor}>{toolName}</span>
      <span>{restMessage}</span>
    </span>
  );
};

// 单条日志项组件 - 现代美学设计
const LogItem: React.FC<{ log: LogEntry; logType: LogType }> = memo(({ log }) => {
  const parsed = useMemo(() => parseLogContent(log.content), [log.content]);
  const [expanded, setExpanded] = React.useState(false);

  // 确定是否需要展开/折叠按钮
  const needsExpansion = parsed.type !== 'simple' && parsed.data;
  const hasLevel = parsed.level !== undefined;
  const levelStyle = hasLevel ? levelStyles[parsed.level!] : null;
  const isError = parsed.level === 'ERROR';

  // 简单日志：单行显示
  if (parsed.type === 'simple') {
    return (
      <div className="group relative">
        <div
          className={`rounded-lg border transition-all px-3 py-1.5 ${
            levelStyle
              ? `${levelStyle.bg} ${levelStyle.border} hover:${levelStyle.border.replace('/30', '/50')}`
              : 'bg-spore-card/50 border-spore-border/20 hover:border-spore-border/40'
          }`}
        >
          <div className="flex items-center gap-3">
            {/* 时间戳 */}
            <span className="text-[10px] text-spore-muted font-mono flex-shrink-0">
              {new Date(log.timestamp * 1000).toLocaleTimeString('en-US', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
              })}
            </span>

            {/* 日志级别标签 */}
            {hasLevel && levelStyle && (
              <span className={`flex items-center gap-1 text-[10px] font-medium flex-shrink-0 ${levelStyle.text}`}>
                <span className="text-xs">{levelStyle.icon}</span>
                {parsed.level}
              </span>
            )}

            {/* 内容 - 主工具名带颜色 */}
            <span className="text-xs leading-relaxed flex-1 truncate">
              {formatToolMessage(parsed.message, isError)}
            </span>
          </div>
        </div>
      </div>
    );
  }

  // 结构化日志：支持展开/折叠
  return (
    <div className="group relative">
      <div
        className={`rounded-lg border transition-all overflow-hidden ${
          levelStyle
            ? `${levelStyle.bg} ${levelStyle.border} hover:${levelStyle.border.replace('/30', '/50')}`
            : 'bg-spore-card/50 border-spore-border/20 hover:border-spore-border/40'
        }`}
      >
        {/* 头部：时间戳 + 级别 + 消息 + 操作按钮 */}
        <div className="flex items-center justify-between px-3 py-1.5 bg-spore-bg/20">
          <div className="flex items-center gap-3 flex-1 min-w-0">
            {/* 时间戳 */}
            <span className="text-[10px] text-spore-muted font-mono flex-shrink-0">
              {new Date(log.timestamp * 1000).toLocaleTimeString('en-US', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
              })}
            </span>

            {/* 日志级别标签 */}
            {hasLevel && levelStyle && (
              <span className={`flex items-center gap-1 text-[10px] font-medium flex-shrink-0 ${levelStyle.text}`}>
                <span className="text-xs">{levelStyle.icon}</span>
                {parsed.level}
              </span>
            )}

            {/* 消息内容 */}
            <span className="text-xs text-spore-text leading-relaxed flex-1 truncate">
              {parsed.message}
            </span>
          </div>

          {/* 展开/折叠按钮 */}
          {needsExpansion && (
            <button
              onClick={() => setExpanded(!expanded)}
              className="text-[10px] px-2 py-0.5 rounded bg-spore-accent/50 hover:bg-spore-accent text-spore-muted hover:text-spore-text transition-colors flex-shrink-0 ml-2"
            >
              {expanded ? '折叠' : '详情'}
            </button>
          )}
        </div>

        {/* 展开的数据内容 */}
        {expanded && (parsed.type === 'json' || parsed.data) && (
          <div className="px-3 py-2 border-t border-spore-border/20">
            <DataCard data={parsed.data || {}} />
          </div>
        )}
      </div>
    </div>
  );
});

LogItem.displayName = 'LogItem';

export const LogArea: React.FC<LogAreaProps> = memo(({
  type,
  label,
  color,
  icon,
  logs,
  onDoubleClick,
}) => {
  const t = useT();
  const containerRef = useRef<HTMLDivElement>(null);
  const shouldAutoScroll = useRef(true);

  // 自动滚动到底部
  useEffect(() => {
    if (shouldAutoScroll.current && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  // 检测用户是否手动滚动
  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    shouldAutoScroll.current = scrollHeight - scrollTop - clientHeight < 50;
  };

  return (
    <div
      className="flex flex-col bg-spore-card rounded-xl border border-spore-border/30 overflow-hidden transition-all hover:border-spore-border/50 h-full shadow-lg"
      onDoubleClick={onDoubleClick}
    >
      {/* 标题栏 - 更紧凑现代 */}
      <div className="px-3 py-2 flex items-center justify-between bg-gradient-to-r from-spore-accent/10 to-spore-accent/5 border-b border-spore-border/20 select-none cursor-pointer backdrop-blur-sm">
        <div className="flex items-center gap-2">
          <svg
            className={`w-3.5 h-3.5 ${color}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d={icon}
            />
          </svg>
          <span className={`text-xs font-semibold ${color} tracking-wide`}>{label}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-spore-muted bg-spore-bg/60 px-2 py-0.5 rounded-full font-medium">
            {logs.length}
          </span>
        </div>
      </div>

      {/* 日志内容 */}
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto p-2 text-xs select-text"
        onScroll={handleScroll}
        style={{
          scrollbarWidth: 'thin',
          scrollbarColor: 'rgb(var(--spore-scrollbar-rgb)) transparent',
        }}
      >
        {logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-spore-muted space-y-2">
            <svg className="w-12 h-12 opacity-20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
              />
            </svg>
            <span className="text-sm">{t('logArea.empty')}</span>
          </div>
        ) : (
          <div className="space-y-2">
            {logs.slice(-100).map((log, index) => (
              <LogItem key={`${log.timestamp}-${index}`} log={log} logType={type} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
});

LogArea.displayName = 'LogArea';
