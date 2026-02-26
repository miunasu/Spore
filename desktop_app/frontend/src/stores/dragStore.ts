/**
 * 拖拽状态管理 - 用于在组件间传递拖拽信息
 */
import { create } from 'zustand';

interface DragFile {
  path: string;
  name: string;
}

interface DragStore {
  draggingFile: DragFile | null;
  isDragging: boolean;
  
  startDrag: (file: DragFile) => void;
  endDrag: () => void;
  getDraggedFile: () => DragFile | null;
}

export const useDragStore = create<DragStore>((set, get) => ({
  draggingFile: null,
  isDragging: false,

  startDrag: (file) => {
    set({ draggingFile: file, isDragging: true });
    // 添加全局拖拽样式
    document.body.classList.add('dragging-file');
  },

  endDrag: () => {
    set({ draggingFile: null, isDragging: false });
    // 移除全局拖拽样式
    document.body.classList.remove('dragging-file');
  },

  getDraggedFile: () => get().draggingFile,
}));
