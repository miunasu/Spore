/**
 * 单个日志区域组件 - 支持 JSON 格式化显示
 */
import React, { useRef, useEffect, useMemo, memo } from 'react';
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

// 尝试解析并格式化 JSON
const formatContent = (
  content: string
): { isJson: boolean; formatted: string; hasEmbeddedJson: boolean; prefix?: string; jsonPart?: string } => {
  if (!content) return { isJson: false, formatted: content, hasEmbeddedJson: false };

  const trimmed = content.trim();

  // 检查是否是纯 JSON
  if (
    (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
    (trimmed.startsWith('[') && trimmed.endsWith(']'))
  ) {
    try {
      const parsed = JSON.parse(trimmed);
      return {
        isJson: true,
        formatted: JSON.stringify(parsed, null, 2),
        hasEmbeddedJson: false,
      };
    } catch {
      // 不是有效 JSON，继续检查
    }
  }

  // 检查内容中是否包含 JSON 对象或数组（找到第一个 { 或 [ 的位置）
  const jsonStartIndex = Math.min(
    trimmed.indexOf('{') === -1 ? Infinity : trimmed.indexOf('{'),
    trimmed.indexOf('[') === -1 ? Infinity : trimmed.indexOf('[')
  );
  
  if (jsonStartIndex !== Infinity && jsonStartIndex > 0) {
    const prefix = trimmed.slice(0, jsonStartIndex).trim();
    const jsonCandidate = trimmed.slice(jsonStartIndex);
    
    try {
      const parsed = JSON.parse(jsonCandidate);
      // 成功解析，返回前缀和 JSON 部分
      return {
        isJson: false,
        formatted: content,
        hasEmbeddedJson: true,
        prefix,
        jsonPart: JSON.stringify(parsed, null, 2),
      };
    } catch {
      // 不是有效 JSON
    }
  }

  return { isJson: false, formatted: content, hasEmbeddedJson: false };
};

// 高亮内容中的特殊元素（JSON、关键字等）
const highlightContent = (content: string): string => {
  let result = content;

  // 转义 HTML
  result = result
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // 高亮 JSON 对象和数组
  result = result.replace(
    /(\{[^{}]*\}|\[[^\[\]]*\])/g,
    '<span class="text-spore-info">$1</span>'
  );

  // 高亮数字
  result = result.replace(
    /\b(\d+\.?\d*)\b/g,
    '<span class="text-spore-warning">$1</span>'
  );

  // 高亮 true/false/null
  result = result.replace(
    /\b(true|false|null)\b/g,
    '<span class="text-spore-error">$1</span>'
  );

  // 高亮引号内的字符串
  result = result.replace(
    /"([^"]*)"/g,
    '<span class="text-spore-highlight">"$1"</span>'
  );

  return result;
};

// 颜色主题配置
type ColorTheme = 'error' | 'warning' | 'default' | 'frontend';

const getColorTheme = (logType: LogType): ColorTheme => {
  switch (logType) {
    case 'system':
      return 'warning';
    case 'frontend':
      return 'frontend';
    default:
      return 'default';
  }
};

// 根据主题获取颜色类
const themeColors = {
  error: {
    key: 'text-red-400',
    string: 'text-red-300',
    number: 'text-red-200',
    boolean: 'text-red-500',
    null: 'text-red-400/50',
    prefix: 'text-red-300',
  },
  warning: {
    key: 'text-yellow-400',
    string: 'text-yellow-300',
    number: 'text-yellow-200',
    boolean: 'text-yellow-500',
    null: 'text-yellow-400/50',
    prefix: 'text-yellow-300',
  },
  default: {
    key: 'text-spore-info',
    string: 'text-spore-highlight',
    number: 'text-spore-warning',
    boolean: 'text-spore-error',
    null: 'text-spore-muted',
    prefix: 'text-spore-highlight',
  },
  frontend: {
    key: 'text-purple-400',
    string: 'text-purple-300',
    number: 'text-purple-200',
    boolean: 'text-purple-500',
    null: 'text-purple-400/50',
    prefix: 'text-purple-300',
  },
};

// JSON 语法高亮组件
const JsonHighlight: React.FC<{ content: string; theme?: ColorTheme }> = memo(({ content, theme = 'default' }) => {
  const colors = themeColors[theme];
  
  const highlighted = useMemo(() => {
    return content
      .replace(/"([^"]+)":/g, `<span class="${colors.key}">"$1"</span>:`)
      .replace(/: "([^"]*)"/g, `: <span class="${colors.string}">"$1"</span>`)
      .replace(/: (\d+\.?\d*)/g, `: <span class="${colors.number}">$1</span>`)
      .replace(/: (true|false)/g, `: <span class="${colors.boolean}">$1</span>`)
      .replace(/: (null)/g, `: <span class="${colors.null}">$1</span>`);
  }, [content, colors]);

  return (
    <pre
      className="whitespace-pre-wrap break-all text-spore-text leading-relaxed"
      dangerouslySetInnerHTML={{ __html: highlighted }}
    />
  );
});

JsonHighlight.displayName = 'JsonHighlight';

// 单条日志项组件
const LogItem: React.FC<{ log: LogEntry; logType: LogType }> = memo(({ log, logType }) => {
  const { isJson, formatted, hasEmbeddedJson, prefix, jsonPart } = useMemo(
    () => formatContent(log.content),
    [log.content]
  );
  const [collapsed, setCollapsed] = React.useState(true);
  const theme = getColorTheme(logType);
  const colors = themeColors[theme];

  // JSON 内容默认折叠，点击展开
  const shouldCollapse = (isJson || hasEmbeddedJson) && (formatted.split('\n').length > 5 || (jsonPart?.split('\n').length || 0) > 5);

  // 对非 JSON 内容应用高亮
  const highlightedContent = useMemo(() => {
    if (isJson || hasEmbeddedJson) return null;
    return highlightContent(formatted);
  }, [isJson, hasEmbeddedJson, formatted]);

  return (
    <div
      className="py-1.5 px-2 rounded-lg bg-spore-bg/30 hover:bg-spore-bg/50 transition-colors"
    >
      {/* 时间戳 */}
      <div className="flex items-center justify-between">
        <span className="text-spore-muted text-[10px]">
          {new Date(log.timestamp * 1000).toLocaleTimeString()}
        </span>
        {shouldCollapse && (
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="text-[10px] text-spore-info hover:text-spore-highlight transition-colors"
          >
            {collapsed ? '展开' : '折叠'}
          </button>
        )}
      </div>

      {/* 内容 */}
      <div className="mt-0.5">
        {isJson ? (
          <div
            className={
              shouldCollapse && collapsed
                ? 'max-h-20 overflow-hidden relative'
                : ''
            }
          >
            <JsonHighlight content={formatted} theme={theme} />
            {shouldCollapse && collapsed && (
              <div className="absolute bottom-0 left-0 right-0 h-8 bg-gradient-to-t from-spore-bg/80 to-transparent" />
            )}
          </div>
        ) : hasEmbeddedJson ? (
          <div>
            {/* 前缀文本 */}
            <span className={colors.prefix}>{prefix}</span>
            {/* JSON 部分 */}
            <div
              className={
                shouldCollapse && collapsed
                  ? 'max-h-20 overflow-hidden relative'
                  : ''
              }
            >
              <JsonHighlight content={jsonPart || ''} theme={theme} />
              {shouldCollapse && collapsed && (
                <div className="absolute bottom-0 left-0 right-0 h-8 bg-gradient-to-t from-spore-bg/80 to-transparent" />
              )}
            </div>
          </div>
        ) : (
          <div
            className="text-spore-text break-all leading-relaxed whitespace-pre-wrap"
            dangerouslySetInnerHTML={{ __html: highlightedContent || '' }}
          />
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
      className="flex flex-col bg-spore-card rounded-xl border border-spore-border/30 overflow-hidden transition-all hover:border-spore-border/50 h-full"
      onDoubleClick={onDoubleClick}
    >
      {/* 标题栏 */}
      <div className="px-3 py-2 flex items-center justify-between bg-spore-accent/20 select-none cursor-pointer">
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
          <span className={`text-xs font-medium ${color}`}>{label}</span>
        </div>
        <span className="text-xs text-spore-muted bg-spore-bg/50 px-2 py-0.5 rounded-full">
          {logs.length}
        </span>
      </div>

      {/* 日志内容 */}
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto p-2 text-xs font-mono select-text"
        onScroll={handleScroll}
      >
        {logs.length === 0 ? (
          <div className="flex items-center justify-center h-full text-spore-muted">
            <span>暂无日志</span>
          </div>
        ) : (
          <div className="space-y-1">
            {logs.slice(-50).map((log, index) => (
              <LogItem key={index} log={log} logType={type} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
});

LogArea.displayName = 'LogArea';
