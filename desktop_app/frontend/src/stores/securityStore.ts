/**
 * 安全事件状态管理 —— 恶意命令熔断弹窗
 *
 * security_malicious 事件到达时登记事件（建议生成中），security_remediation
 * 事件到达时挂载处置建议。SecurityRemediationModal 按队列逐个弹窗，
 * 用户选择"手动处理"或"自动修复"后移除。
 */
import { create } from 'zustand';

export interface SecurityIncident {
  id: string; // `${sessionId}::${command}`
  sessionId: string;
  command: string;
  intent: string;
  maliciousReason: string;
  interrupted: boolean;
  createdAt: number;
  // 处置建议（二次研判产出，到达前 adviceReady=false 显示加载态）
  adviceReady: boolean;
  summary?: string;
  impact?: string;
  manualSteps?: string[];
  autoFixPrompt?: string;
  aiGenerated?: boolean;
}

export interface SecurityAdvice {
  summary: string;
  impact: string;
  manualSteps: string[];
  autoFixPrompt: string;
  aiGenerated: boolean;
}

const incidentId = (sessionId: string, command: string) =>
  `${sessionId}::${command}`;

interface SecurityStore {
  incidents: SecurityIncident[];
  addIncident: (incident: {
    sessionId: string;
    command: string;
    intent: string;
    maliciousReason: string;
    interrupted: boolean;
  }) => void;
  attachAdvice: (sessionId: string, command: string, advice: SecurityAdvice) => void;
  removeIncident: (id: string) => void;
}

export const useSecurityStore = create<SecurityStore>((set) => ({
  incidents: [],

  addIncident: (incident) =>
    set((state) => {
      const id = incidentId(incident.sessionId, incident.command);
      if (state.incidents.some((i) => i.id === id)) return state;
      return {
        incidents: [
          ...state.incidents,
          {
            id,
            sessionId: incident.sessionId,
            command: incident.command,
            intent: incident.intent,
            maliciousReason: incident.maliciousReason,
            interrupted: incident.interrupted,
            createdAt: Date.now(),
            adviceReady: false,
          },
        ],
      };
    }),

  attachAdvice: (sessionId, command, advice) =>
    set((state) => {
      const id = incidentId(sessionId, command);
      const existing = state.incidents.find((i) => i.id === id);
      // 事件乱序容错：security_remediation 先到（或 malicious 事件丢失）时直接建条目
      if (!existing) {
        return {
          incidents: [
            ...state.incidents,
            {
              id,
              sessionId,
              command,
              intent: '',
              maliciousReason: '',
              interrupted: true,
              createdAt: Date.now(),
              adviceReady: true,
              summary: advice.summary,
              impact: advice.impact,
              manualSteps: advice.manualSteps,
              autoFixPrompt: advice.autoFixPrompt,
              aiGenerated: advice.aiGenerated,
            },
          ],
        };
      }
      return {
        incidents: state.incidents.map((i) =>
          i.id === id
            ? {
                ...i,
                adviceReady: true,
                summary: advice.summary,
                impact: advice.impact,
                manualSteps: advice.manualSteps,
                autoFixPrompt: advice.autoFixPrompt,
                aiGenerated: advice.aiGenerated,
              }
            : i
        ),
      };
    }),

  removeIncident: (id) =>
    set((state) => ({
      incidents: state.incidents.filter((i) => i.id !== id),
    })),
}));
