/**
 * 日志状态管理 - 支持按对话分组
 */
import { create } from 'zustand';
import type { LogType, LogEntry } from '../types';

interface LogStore {
  // 全局日志（所有对话共享）
  globalLogs: Record<LogType, LogEntry[]>;
  // 按对话分组的日志
  conversationLogs: Record<string, Record<LogType, LogEntry[]>>;
  // 当前关联的对话 ID
  activeConversationId: string | null;
  // 展开的日志类型
  expandedLog: LogType | null;

  // Actions
  setActiveConversation: (id: string | null) => void;
  addLog: (type: LogType, entry: LogEntry) => void;
  addFrontendLog: (content: string) => void; // 便捷方法添加前端日志
  setExpanded: (type: LogType | null) => void;
  clearLogs: () => void;
  clearLogType: (type: LogType) => void;
  clearConversationLogs: (conversationId: string) => void;

  // Getters
  getCurrentLogs: () => Record<LogType, LogEntry[]>;
}

const createEmptyLogs = (): Record<LogType, LogEntry[]> => ({
  system: [],
  general: [],
  frontend: [],
});

// 日志缓冲区，用于批量更新
const logBuffer: { type: LogType; entry: LogEntry }[] = [];
let flushTimer: ReturnType<typeof setTimeout> | null = null;

export const useLogStore = create<LogStore>((set, get) => ({
  globalLogs: createEmptyLogs(),
  conversationLogs: {},
  activeConversationId: null,
  expandedLog: null,

  setActiveConversation: (id) => {
    set({ activeConversationId: id });
    // 确保该对话有日志存储
    if (id && !get().conversationLogs[id]) {
      set((state) => ({
        conversationLogs: {
          ...state.conversationLogs,
          [id]: createEmptyLogs(),
        },
      }));
    }
  },

  addLog: (type, entry) => {
    const { activeConversationId } = get();
    const entryWithConv = {
      ...entry,
      conversationId: activeConversationId || undefined,
    };

    // 添加到缓冲区
    logBuffer.push({ type, entry: entryWithConv });

    // 设置批量刷新定时器（100ms 内的日志会被批量处理）
    if (!flushTimer) {
      flushTimer = setTimeout(() => {
        set((state) => {
          const newGlobalLogs = { ...state.globalLogs };
          const newConvLogs = { ...state.conversationLogs };

          // 处理缓冲区中的所有日志
          for (const { type: logType, entry: logEntry } of logBuffer) {
            // 添加到全局日志
            newGlobalLogs[logType] = [
              ...newGlobalLogs[logType],
              logEntry,
            ].slice(-300);

            // 如果有活跃对话，也添加到对话日志
            const convId = logEntry.conversationId;
            if (convId) {
              if (!newConvLogs[convId]) {
                newConvLogs[convId] = createEmptyLogs();
              }
              newConvLogs[convId] = {
                ...newConvLogs[convId],
                [logType]: [...newConvLogs[convId][logType], logEntry].slice(
                  -100
                ),
              };
            }
          }

          // 清空缓冲区
          logBuffer.length = 0;
          flushTimer = null;

          return {
            globalLogs: newGlobalLogs,
            conversationLogs: newConvLogs,
          };
        });
      }, 100);
    }
  },

  addFrontendLog: (content) => {
    const entry: LogEntry = {
      log_type: 'frontend',
      content,
      timestamp: Date.now() / 1000,
    };
    // 前端日志只添加到全局，不跟随对话
    set((state) => ({
      globalLogs: {
        ...state.globalLogs,
        frontend: [...state.globalLogs.frontend, entry].slice(-500),
      },
    }));
  },

  setExpanded: (type) => set({ expandedLog: type }),

  clearLogs: () => {
    // 清空缓冲区
    logBuffer.length = 0;
    if (flushTimer) {
      clearTimeout(flushTimer);
      flushTimer = null;
    }
    set({
      globalLogs: createEmptyLogs(),
      conversationLogs: {},
    });
  },

  clearLogType: (type) => {
    const { activeConversationId } = get();

    set((state) => {
      const newGlobalLogs = { ...state.globalLogs, [type]: [] };

      if (
        activeConversationId &&
        state.conversationLogs[activeConversationId]
      ) {
        return {
          globalLogs: newGlobalLogs,
          conversationLogs: {
            ...state.conversationLogs,
            [activeConversationId]: {
              ...state.conversationLogs[activeConversationId],
              [type]: [],
            },
          },
        };
      }

      return { globalLogs: newGlobalLogs };
    });
  },

  clearConversationLogs: (conversationId) => {
    set((state) => ({
      conversationLogs: {
        ...state.conversationLogs,
        [conversationId]: createEmptyLogs(),
      },
    }));
  },

  getCurrentLogs: () => {
    const { activeConversationId, conversationLogs, globalLogs } = get();
    if (activeConversationId && conversationLogs[activeConversationId]) {
      return conversationLogs[activeConversationId];
    }
    return globalLogs;
  },
}));
