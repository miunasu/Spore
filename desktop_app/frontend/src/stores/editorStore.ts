/**
 * 中栏编辑器 Store - 管理拖拽到中栏的文件编辑（支持多标签页）
 */
import { create } from 'zustand';
import { filesApi } from '../services/api';

interface EditorFile {
  path: string;
  name: string;
  content: string;
  originalContent: string;
  hasChanges: boolean;
}

interface EditorStore {
  // 打开的文件列表
  openFiles: EditorFile[];
  // 当前活跃的文件路径
  activeFilePath: string | null;
  isLoading: boolean;
  isSaving: boolean;
  error: string | null;

  // Getters
  editingFile: EditorFile | null;

  // Actions
  openFile: (path: string, name: string) => Promise<void>;
  switchFile: (path: string) => void;
  closeFile: (path?: string) => void;
  updateContent: (content: string) => void;
  saveFile: (path?: string) => Promise<void>;
}

export const useEditorStore = create<EditorStore>((set, get) => ({
  openFiles: [],
  activeFilePath: null,
  isLoading: false,
  isSaving: false,
  error: null,

  // 获取当前编辑的文件
  get editingFile() {
    const { openFiles, activeFilePath } = get();
    return openFiles.find((f) => f.path === activeFilePath) || null;
  },

  openFile: async (path: string, name: string) => {
    const { openFiles } = get();

    // 如果文件已打开，直接切换
    const existing = openFiles.find((f) => f.path === path);
    if (existing) {
      set({ activeFilePath: path });
      return;
    }

    set({ isLoading: true, error: null });
    try {
      const response = await filesApi.read(path);
      const newFile: EditorFile = {
        path,
        name,
        content: response.content,
        originalContent: response.content,
        hasChanges: false,
      };
      set({
        openFiles: [...get().openFiles, newFile],
        activeFilePath: path,
        isLoading: false,
      });
    } catch (err) {
      set({
        error: '打开文件失败',
        isLoading: false,
      });
    }
  },

  switchFile: (path: string) => {
    set({ activeFilePath: path });
  },

  closeFile: (path?: string) => {
    const { openFiles, activeFilePath } = get();
    const targetPath = path || activeFilePath;
    if (!targetPath) return;

    const newFiles = openFiles.filter((f) => f.path !== targetPath);
    let newActivePath: string | null = null;

    if (newFiles.length > 0) {
      // 如果关闭的是当前文件，切换到相邻文件
      if (targetPath === activeFilePath) {
        const closedIndex = openFiles.findIndex((f) => f.path === targetPath);
        const newIndex = Math.min(closedIndex, newFiles.length - 1);
        newActivePath = newFiles[newIndex]?.path || null;
      } else {
        newActivePath = activeFilePath;
      }
    }

    set({
      openFiles: newFiles,
      activeFilePath: newActivePath,
      error: null,
    });
  },

  updateContent: (content: string) => {
    const { openFiles, activeFilePath } = get();
    if (!activeFilePath) return;

    set({
      openFiles: openFiles.map((f) =>
        f.path === activeFilePath
          ? { ...f, content, hasChanges: content !== f.originalContent }
          : f
      ),
    });
  },

  saveFile: async (path?: string) => {
    const { openFiles, activeFilePath } = get();
    const targetPath = path || activeFilePath;
    const file = openFiles.find((f) => f.path === targetPath);
    if (!file) return;

    set({ isSaving: true, error: null });
    try {
      await filesApi.write(file.path, file.content);
      set({
        openFiles: openFiles.map((f) =>
          f.path === targetPath
            ? { ...f, originalContent: f.content, hasChanges: false }
            : f
        ),
        isSaving: false,
      });
    } catch (err) {
      set({
        error: '保存失败',
        isSaving: false,
      });
    }
  },
}));
