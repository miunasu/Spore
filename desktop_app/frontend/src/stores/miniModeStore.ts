/**
 * Mini 模式状态管理（类似网易云音乐 mini 模式）
 * 进入时把窗口缩成紧凑悬浮窗并置顶，退出时还原窗口尺寸/位置与置顶状态
 */
import { create } from 'zustand';
import {
  appWindow,
  LogicalSize,
  PhysicalSize,
  PhysicalPosition,
} from '@tauri-apps/api/window';

// mini 窗口尺寸
const MINI_SIZE = new LogicalSize(380, 520);
const MINI_MIN_SIZE = new LogicalSize(300, 240);
// 与 tauri.conf.json 中 minWidth/minHeight 保持一致
const NORMAL_MIN_SIZE = new LogicalSize(400, 400);

interface MiniModeState {
  miniMode: boolean;
  /** 进入 mini 模式；alwaysOnTop 传入当前置顶状态，退出时据此还原 */
  enterMiniMode: (alwaysOnTop: boolean) => Promise<void>;
  exitMiniMode: () => Promise<void>;
}

// 进入 mini 前的窗口状态（无需持久化，仅本次会话内还原用）
let prevSize: PhysicalSize | null = null;
let prevPosition: PhysicalPosition | null = null;
let prevMaximized = false;
let prevAlwaysOnTop = false;

export const useMiniModeStore = create<MiniModeState>((set, get) => ({
  miniMode: false,

  enterMiniMode: async (alwaysOnTop) => {
    if (get().miniMode) return;
    try {
      prevAlwaysOnTop = alwaysOnTop;
      prevMaximized = await appWindow.isMaximized();
      if (prevMaximized) {
        await appWindow.unmaximize();
      }
      prevSize = await appWindow.innerSize();
      prevPosition = await appWindow.outerPosition();

      await appWindow.setMinSize(MINI_MIN_SIZE);
      await appWindow.setSize(MINI_SIZE);
      await appWindow.setAlwaysOnTop(true);
    } catch (err) {
      console.warn('Failed to enter mini mode:', err);
    }
    set({ miniMode: true });
  },

  exitMiniMode: async () => {
    if (!get().miniMode) return;
    try {
      await appWindow.setAlwaysOnTop(prevAlwaysOnTop);
      await appWindow.setMinSize(NORMAL_MIN_SIZE);
      if (prevMaximized) {
        await appWindow.maximize();
      } else {
        if (prevSize) await appWindow.setSize(prevSize);
        if (prevPosition) await appWindow.setPosition(prevPosition);
      }
    } catch (err) {
      console.warn('Failed to exit mini mode:', err);
    }
    set({ miniMode: false });
  },
}));
