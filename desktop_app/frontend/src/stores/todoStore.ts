/**
 * Todo Store - 管理任务列表状态
 */
import { create } from 'zustand';
import type { TodoItem } from '../types';

interface TodoState {
  todos: TodoItem[];
  isExpanded: boolean;
  setTodos: (todos: TodoItem[]) => void;
  toggleExpanded: () => void;
}

export const useTodoStore = create<TodoState>((set) => ({
  todos: [],
  isExpanded: false,
  
  setTodos: (todos) => set({ todos }),
  
  toggleExpanded: () => set((state) => ({ isExpanded: !state.isExpanded })),
}));
