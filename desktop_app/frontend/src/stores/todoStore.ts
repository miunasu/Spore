/**
 * Todo Store - 管理任务列表状态
 * 支持多会话独立管理
 */
import { create } from 'zustand';
import type { TodoItem } from '../types';

interface TodoState {
  // 按会话ID存储todos
  todosByConversation: Record<string, TodoItem[]>;
  isExpanded: boolean;
  
  // 获取指定会话的todos
  getTodos: (conversationId: string) => TodoItem[];
  
  // 设置指定会话的todos
  setTodos: (conversationId: string, todos: TodoItem[]) => void;
  
  // 清除指定会话的todos
  clearTodos: (conversationId: string) => void;
  
  toggleExpanded: () => void;
}

export const useTodoStore = create<TodoState>((set, get) => ({
  todosByConversation: {},
  isExpanded: false,
  
  getTodos: (conversationId) => {
    return get().todosByConversation[conversationId] || [];
  },
  
  setTodos: (conversationId, todos) => set((state) => ({
    todosByConversation: {
      ...state.todosByConversation,
      [conversationId]: todos
    }
  })),
  
  clearTodos: (conversationId) => set((state) => {
    const newTodos = { ...state.todosByConversation };
    delete newTodos[conversationId];
    return { todosByConversation: newTodos };
  }),
  
  toggleExpanded: () => set((state) => ({ isExpanded: !state.isExpanded })),
}));
