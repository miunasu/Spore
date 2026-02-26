/**
 * 日志面板组件 - 现代化设计
 * 竖排三格布局显示三种类型的日志
 */
import React, { useMemo, useCallback } from 'react';
import { useLogStore } from '../../stores/logStore';
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

export const LogPanel: React.FC = () => {
  const expandedLog = useLogStore((state) => state.expandedLog);
  const setExpanded = useLogStore((state) => state.setExpanded);
  const activeConversationId = useLogStore((state) => state.activeConversationId);
  const conversationLogs = useLogStore((state) => state.conversationLogs);
  const globalLogs = useLogStore((state) => state.globalLogs);

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

  // 展开模式：只显示一个日志区域
  if (expandedLog) {
    const logConfig = LOG_TYPES.find((l) => l.type === expandedLog);
    return (
      <div className="h-full flex flex-col p-2">
        <LogArea
          type={expandedLog}
          label={logConfig?.label || ''}
          color={logConfig?.color || ''}
          icon={logConfig?.icon || ''}
          logs={getLogsForType(expandedLog)}
          onDoubleClick={() => handleDoubleClick(expandedLog)}
          expanded
        />
      </div>
    );
  }

  // 竖排四格布局，等分高度，无标题栏
  return (
    <div className="h-full flex flex-col gap-2 p-2">
      {LOG_TYPES.map(({ type, label, color, icon }) => (
        <div key={type} className="flex-1 min-h-0">
          <LogArea
            type={type}
            label={label}
            color={color}
            icon={icon}
            logs={getLogsForType(type)}
            onDoubleClick={() => handleDoubleClick(type)}
          />
        </div>
      ))}
    </div>
  );
};
