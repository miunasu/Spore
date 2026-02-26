/**
 * Confirm Store - 管理确认请求状态
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
  pendingRequest: ConfirmRequest | null;
  setPendingRequest: (request: ConfirmRequest | null) => void;
  clearRequest: () => void;
}

export const useConfirmStore = create<ConfirmState>((set) => ({
  pendingRequest: null,
  
  setPendingRequest: (request) => set({ pendingRequest: request }),
  
  clearRequest: () => set({ pendingRequest: null }),
}));
