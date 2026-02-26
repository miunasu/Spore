/**
 * 文件管理状态
 */
import { create } from 'zustand';
import type { FileItem } from '../types';
import { filesApi } from '../services/api';

interface FileStore {
  currentPath: string;
  rootPath: string; // 当前 tab 的根目录限制
  items: FileItem[];
  editingFile: FileItem | null;
  editingContent: string;
  editingOriginalContent: string; // 原始内容，用于判断是否修改
  editingScrollTop: number; // 保存滚动位置
  isLoading: boolean;
  
  // Actions
  setPath: (path: string) => void;
  setRootPath: (path: string) => void;
  setItems: (items: FileItem[]) => void;
  setEditingFile: (file: FileItem | null) => void;
  setEditingContent: (content: string) => void;
  setEditingScrollTop: (scrollTop: number) => void;
  isDirty: () => boolean; // 判断是否有修改
  
  // API Actions
  loadDirectory: (path: string) => Promise<void>;
  refreshDirectory: () => Promise<void>;
  openFile: (file: FileItem) => Promise<void>;
  saveFile: () => Promise<void>;
  closeEditor: () => void;
  deleteItem: (path: string) => Promise<void>;
  createItem: (name: string, type: 'file' | 'folder') => Promise<void>;
  renameItem: (oldPath: string, newName: string) => Promise<void>;
}

export const useFileStore = create<FileStore>((set, get) => ({
  currentPath: 'output',
  rootPath: 'output',
  items: [],
  editingFile: null,
  editingContent: '',
  editingOriginalContent: '',
  editingScrollTop: 0,
  isLoading: false,

  setPath: (path) => set({ currentPath: path }),
  setRootPath: (path) => set({ rootPath: path }),
  setItems: (items) => set({ items }),
  setEditingFile: (file) => set({ editingFile: file }),
  setEditingContent: (content) => set({ editingContent: content }),
  setEditingScrollTop: (scrollTop) => set({ editingScrollTop: scrollTop }),
  isDirty: () => get().editingContent !== get().editingOriginalContent,

  loadDirectory: async (path) => {
    // 如果已经在加载，不重复请求
    if (get().isLoading) return;
    
    set({ isLoading: true });
    try {
      // 添加超时控制
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5秒超时
      
      const response = await filesApi.list(path);
      clearTimeout(timeoutId);
      
      set({
        currentPath: response.path,
        items: response.items as FileItem[],
      });
    } catch (error) {
      console.error('加载目录失败:', error);
    } finally {
      set({ isLoading: false });
    }
  },

  // 静默刷新当前目录（不显示 loading 状态）
  refreshDirectory: async () => {
    const { currentPath, isLoading } = get();
    if (isLoading || !currentPath) return;
    
    try {
      const response = await filesApi.list(currentPath);
      set({ items: response.items as FileItem[] });
    } catch (error) {
      // 静默失败，不打印错误
    }
  },

  openFile: async (file) => {
    if (file.type === 'folder') {
      await get().loadDirectory(file.path);
      return;
    }
    
    try {
      const response = await filesApi.read(file.path);
      set({
        editingFile: file,
        editingContent: response.content,
        editingOriginalContent: response.content,
      });
    } catch (error) {
      console.error('打开文件失败:', error);
    }
  },

  saveFile: async () => {
    const { editingFile, editingContent, loadDirectory, currentPath } = get();
    if (!editingFile) return;
    
    try {
      await filesApi.write(editingFile.path, editingContent);
      // 保存后更新原始内容
      set({ editingOriginalContent: editingContent });
      await loadDirectory(currentPath);
    } catch (error) {
      console.error('保存文件失败:', error);
    }
  },

  closeEditor: () => set({ editingFile: null, editingContent: '', editingOriginalContent: '', editingScrollTop: 0 }),

  deleteItem: async (path) => {
    const { loadDirectory, currentPath } = get();
    try {
      await filesApi.delete(path);
      await loadDirectory(currentPath);
    } catch (error) {
      console.error('删除失败:', error);
    }
  },

  createItem: async (name, type) => {
    const { currentPath, loadDirectory } = get();
    const newPath = `${currentPath}/${name}`;
    try {
      await filesApi.create(newPath, type);
      await loadDirectory(currentPath);
    } catch (error) {
      console.error('创建失败:', error);
    }
  },

  renameItem: async (oldPath, newName) => {
    const { currentPath, loadDirectory } = get();
    const parts = oldPath.split('/');
    parts[parts.length - 1] = newName;
    const newPath = parts.join('/');
    
    try {
      await filesApi.rename(oldPath, newPath);
      await loadDirectory(currentPath);
    } catch (error) {
      console.error('重命名失败:', error);
    }
  },
}));
