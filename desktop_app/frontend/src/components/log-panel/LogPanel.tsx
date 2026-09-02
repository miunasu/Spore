/**
 * 日志面板组件 - 现代化设计
 * 竖排三格布局显示三种类型的日志，支持可调节大小
 */
import React, { useMemo, useCallback, useState, useEffect } from 'react';
import { useLogStore } from '../../stores/logStore';
import { useT } from '../../i18n';
import { LogArea } from './LogArea';
import type { LogType } from '../../types';

const LOG_TYPES: { type: LogType; label: string; color: string; icon: string }[] = [
  {
    type: 'system',
    label: 'system',
    color: 'text-spore-info',
    icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z'
  },
  {
    type: 'general',
    label: 'general',
    color: 'text-spore-muted',
    icon: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'
  },
  {
    type: 'frontend',
    label: 'frontend',
    color: 'text-spore-highlight',
    icon: 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z'
  },
];

const STORAGE_KEY = 'spore-log-panel-heights';
const MIN_HEIGHT = 80; // 最小高度（像素）

// 加载保存的高度配置
const loadHeights = (): number[] => {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const heights = JSON.parse(saved);
      if (Array.isArray(heights) && heights.length === 3) {
        return heights;
      }
    }
  } catch (e) {
    console.warn('Failed to load log panel heights:', e);
  }
  // 默认等分
  return [33.33, 33.33, 33.34];
};

// 保存高度配置
const saveHeights = (heights: number[]) => {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(heights));
  } catch (e) {
    console.warn('Failed to save log panel heights:', e);
  }
};

export const LogPanel: React.FC = () => {
  const t = useT();
  const expandedLog = useLogStore((state) => state.expandedLog);
  const setExpanded = useLogStore((state) => state.setExpanded);
  const activeConversationId = useLogStore((state) => state.activeConversationId);
  const conversationLogs = useLogStore((state) => state.conversationLogs);
  const globalLogs = useLogStore((state) => state.globalLogs);

  // 高度管理（百分比）
  const [heights, setHeights] = useState<number[]>(loadHeights);
  const [draggingIndex, setDraggingIndex] = useState<number | null>(null);

  // 保存高度配置
  useEffect(() => {
    saveHeights(heights);
  }, [heights]);

  // 获取当前对话的日志（后端日志跟随对话）
  const conversationBasedLogs = useMemo(() => {
    if (activeConversationId && conversationLogs[activeConversationId]) {
      return conversationLogs[activeConversationId];
    }
    return globalLogs;
  }, [activeConversationId, conversationLogs, globalLogs]);

  // 获取指定类型的日志，frontend 始终使用全局日志
  const getLogsForType = useCallback((type: LogType) => {
    if (type === 'frontend') {
      return globalLogs.frontend;
    }
    return conversationBasedLogs[type];
  }, [globalLogs.frontend, conversationBasedLogs]);

  const handleDoubleClick = useCallback((type: LogType) => {
    setExpanded(expandedLog === type ? null : type);
  }, [expandedLog, setExpanded]);

  // 处理拖拽调整大小
  const handleMouseDown = useCallback((index: number) => {
    setDraggingIndex(index);
  }, []);

  const handleMouseMove = useCallback((e: MouseEvent) => {
    if (draggingIndex === null) return;

    const container = document.getElementById('log-panel-container');
    if (!container) return;

    const containerRect = container.getBoundingClientRect();
    const containerHeight = containerRect.height;
    const mouseY = e.clientY - containerRect.top;

    // 计算到容器顶部的百分比
    let totalPercentBefore = 0;
    for (let i = 0; i < draggingIndex; i++) {
      totalPercentBefore += heights[i];
    }

    const mousePercent = (mouseY / containerHeight) * 100;
    const currentHeight = heights[draggingIndex];
    const nextHeight = heights[draggingIndex + 1];

    // 计算新的高度
    let newCurrentPercent = mousePercent - totalPercentBefore;
    let newNextPercent = currentHeight + nextHeight - newCurrentPercent;

    // 应用最小高度限制
    const minPercent = (MIN_HEIGHT / containerHeight) * 100;
    if (newCurrentPercent < minPercent) {
      newCurrentPercent = minPercent;
      newNextPercent = currentHeight + nextHeight - newCurrentPercent;
    }
    if (newNextPercent < minPercent) {
      newNextPercent = minPercent;
      newCurrentPercent = currentHeight + nextHeight - newNextPercent;
    }

    // 更新高度
    const newHeights = [...heights];
    newHeights[draggingIndex] = newCurrentPercent;
    newHeights[draggingIndex + 1] = newNextPercent;
    setHeights(newHeights);
  }, [draggingIndex, heights]);

  const handleMouseUp = useCallback(() => {
    setDraggingIndex(null);
  }, []);

  // 添加全局鼠标事件监听
  useEffect(() => {
    if (draggingIndex !== null) {
      window.addEventListener('mousemove', handleMouseMove);
      window.addEventListener('mouseup', handleMouseUp);
      return () => {
        window.removeEventListener('mousemove', handleMouseMove);
        window.removeEventListener('mouseup', handleMouseUp);
      };
    }
  }, [draggingIndex, handleMouseMove, handleMouseUp]);

  // 展开模式：只显示一个日志区域
  if (expandedLog) {
    const logConfig = LOG_TYPES.find((l) => l.type === expandedLog);
    return (
      <div className="h-full flex flex-col p-2">
        <LogArea
          type={expandedLog}
          label={t(`logPanel.types.${expandedLog}`)}
          color={logConfig?.color || ''}
          icon={logConfig?.icon || ''}
          logs={getLogsForType(expandedLog)}
          onDoubleClick={() => handleDoubleClick(expandedLog)}
          expanded
        />
      </div>
    );
  }

  // 竖排三格布局，支持拖拽调整高度
  return (
    <div id="log-panel-container" className="h-full flex flex-col p-2" style={{ userSelect: draggingIndex !== null ? 'none' : 'auto' }}>
      {LOG_TYPES.map(({ type, color, icon }, index) => (
        <React.Fragment key={type}>
          <div style={{ height: `${heights[index]}%`, minHeight: MIN_HEIGHT }}>
            <LogArea
              type={type}
              label={t(`logPanel.types.${type}`)}
              color={color}
              icon={icon}
              logs={getLogsForType(type)}
              onDoubleClick={() => handleDoubleClick(type)}
            />
          </div>
          {/* 分隔条 */}
          {index < LOG_TYPES.length - 1 && (
            <div
              className={`h-2 flex items-center justify-center cursor-row-resize group ${
                draggingIndex === index ? 'bg-spore-accent/40' : 'hover:bg-spore-accent/30'
              } transition-colors`}
              onMouseDown={() => handleMouseDown(index)}
            >
              <div className="w-12 h-1 rounded-full bg-spore-border group-hover:bg-spore-muted transition-colors" />
            </div>
          )}
        </React.Fragment>
      ))}
    </div>
  );
};
