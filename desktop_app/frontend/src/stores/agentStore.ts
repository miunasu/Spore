/**
 * Agent 监控状态管理
 * 使用 Map 结构存储，支持细粒度订阅
 */
import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import type { Agent, AgentStatus, AgentLog } from '../types';
import { agentsApi } from '../services/api';

// 存储定时器引用
const removalTimers: Map<string, NodeJS.Timeout> = new Map();

// 缓冲区
const logBuffer: Map<string, AgentLog[]> = new Map();
const agentBuffer: Map<string, Agent> = new Map();
const statusBuffer: Map<string, AgentStatus> = new Map();

let flushTimer: NodeJS.Timeout | null = null;
const FLUSH_INTERVAL = 100;

interface AgentStore {
  // 使用 Map 结构，key 是 agent id
  agentsById: Record<string, Agent>;
  // agent IDs 列表（用于渲染顺序）
  agentIds: string[];

  // Actions
  addAgent: (agent: Agent) => void;
  updateAgentStatus: (id: string, status: AgentStatus) => void;
  addAgentLog: (id: string, log: AgentLog) => void;
  removeAgent: (id: string) => void;
  clearAgents: () => void;

  // Selectors
  getAgent: (id: string) => Agent | undefined;

  // API Actions
  loadAgents: () => Promise<void>;
}

// 调度批量刷新
const scheduleFlush = (flush: () => void) => {
  if (!flushTimer) {
    flushTimer = setTimeout(() => {
      flush();
      flushTimer = null;
    }, FLUSH_INTERVAL);
  }
};

export const useAgentStore = create<AgentStore>()(
  subscribeWithSelector((set, get) => {
    const flushAll = () => {
      set((state) => {
        const newAgentsById = { ...state.agentsById };
        let newAgentIds = [...state.agentIds];

        // 1. 添加新 Agent
        agentBuffer.forEach((agent, id) => {
          if (!newAgentsById[id]) {
            newAgentsById[id] = agent;
            newAgentIds.push(id);
          }
        });
        agentBuffer.clear();

        // 2. 更新状态
        statusBuffer.forEach((status, id) => {
          if (newAgentsById[id]) {
            newAgentsById[id] = { ...newAgentsById[id], status };
          }
        });
        statusBuffer.clear();

        // 3. 添加日志
        logBuffer.forEach((logs, id) => {
          if (newAgentsById[id] && logs.length > 0) {
            newAgentsById[id] = {
              ...newAgentsById[id],
              logs: [...newAgentsById[id].logs, ...logs].slice(-100),
            };
          }
        });
        logBuffer.clear();

        // 最多保留 5 个 Agent
        if (newAgentIds.length > 5) {
          const toRemove = newAgentIds.slice(0, newAgentIds.length - 5);
          toRemove.forEach((id) => delete newAgentsById[id]);
          newAgentIds = newAgentIds.slice(-5);
        }

        return { agentsById: newAgentsById, agentIds: newAgentIds };
      });
    };

    return {
      agentsById: {},
      agentIds: [],

      addAgent: (agent) => {
        // 立即添加新 Agent，不使用缓冲区
        // 这样可以确保 Agent 面板立即显示
        set((state) => {
          if (state.agentsById[agent.id]) return state;
          
          const newAgentsById = { ...state.agentsById, [agent.id]: agent };
          let newAgentIds = [...state.agentIds, agent.id];
          
          // 最多保留 5 个 Agent
          if (newAgentIds.length > 5) {
            const toRemove = newAgentIds.slice(0, newAgentIds.length - 5);
            toRemove.forEach((id) => delete newAgentsById[id]);
            newAgentIds = newAgentIds.slice(-5);
          }
          
          return { agentsById: newAgentsById, agentIds: newAgentIds };
        });
      },

      updateAgentStatus: (id, status) => {
        statusBuffer.set(id, status);
        scheduleFlush(flushAll);

        if (status === 'completed' || status === 'interrupted' || status === 'error') {
          const existingTimer = removalTimers.get(id);
          if (existingTimer) clearTimeout(existingTimer);

          // 根据状态设置不同的清理延迟
          let delay = 3000; // 默认3秒
          if (status === 'interrupted') {
            delay = 500; // 中断后0.5秒清理
          } else if (status === 'completed') {
            delay = 2000; // 完成后2秒清理
          }

          const timer = setTimeout(() => {
            get().removeAgent(id);
            removalTimers.delete(id);
          }, delay);

          removalTimers.set(id, timer);
        }
      },

      addAgentLog: (id, log) => {
        const buffer = logBuffer.get(id) || [];
        buffer.push(log);
        logBuffer.set(id, buffer);
        scheduleFlush(flushAll);
      },

      removeAgent: (id) => {
        const timer = removalTimers.get(id);
        if (timer) {
          clearTimeout(timer);
          removalTimers.delete(id);
        }

        logBuffer.delete(id);
        agentBuffer.delete(id);
        statusBuffer.delete(id);

        set((state) => {
          const newAgentsById = { ...state.agentsById };
          delete newAgentsById[id];
          return {
            agentsById: newAgentsById,
            agentIds: state.agentIds.filter((aid) => aid !== id),
          };
        });
      },

      clearAgents: () => {
        removalTimers.forEach((timer) => clearTimeout(timer));
        removalTimers.clear();
        logBuffer.clear();
        agentBuffer.clear();
        statusBuffer.clear();

        if (flushTimer) {
          clearTimeout(flushTimer);
          flushTimer = null;
        }

        set({ agentsById: {}, agentIds: [] });
      },

      getAgent: (id) => get().agentsById[id],

      loadAgents: async () => {
        try {
          const response = await agentsApi.list();
          const agentsById: Record<string, Agent> = {};
          const agentIds: string[] = [];

          response.agents.forEach((a) => {
            agentsById[a.id] = {
              id: a.id,
              name: a.name,
              status: a.status as AgentStatus,
              logs: [],
            };
            agentIds.push(a.id);
          });

          set({ agentsById, agentIds });
        } catch (error) {
          console.error('加载 Agent 列表失败:', error);
        }
      },
    };
  })
);
