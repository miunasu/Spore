/**
 * Confirm Store - 管理确认请求状态
 *
 * 队列化：多个高危命令并行触发确认时（后端 confirm_manager 按 request_id
 * 支持并发等待），请求按到达顺序排队逐个确认，不再互相覆盖。
 */
import { create } from 'zustand';

export interface ConfirmRequest {
  request_id: string;
  action_type: string;
  title: string;
  message: string;
  details: string[];
  timestamp: number;
}

interface ConfirmState {
  pendingRequests: ConfirmRequest[];
  enqueueRequest: (request: ConfirmRequest) => void;
  removeRequest: (requestId: string) => void;
  clearAll: () => void;
}

export const useConfirmStore = create<ConfirmState>((set) => ({
  pendingRequests: [],

  enqueueRequest: (request) =>
    set((state) => (
      state.pendingRequests.some((r) => r.request_id === request.request_id)
        ? state
        : { pendingRequests: [...state.pendingRequests, request] }
    )),

  removeRequest: (requestId) =>
    set((state) => ({
      pendingRequests: state.pendingRequests.filter(
        (r) => r.request_id !== requestId
      ),
    })),

  clearAll: () => set({ pendingRequests: [] }),
}));
