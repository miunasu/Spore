/**
 * Mini 模式状态管理（类似网易云音乐 mini 模式）
 * 进入时把窗口缩成紧凑悬浮窗并置顶，退出时还原窗口尺寸/位置与置顶状态。
 * 靠边吸附由 Tauri Rust 原生层处理，这里只同步设置与展示状态。
 */
import { create } from 'zustand';
import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/tauri';
import {
  appWindow,
  LogicalSize,
  PhysicalSize,
  PhysicalPosition,
} from '@tauri-apps/api/window';

const MINI_SIZE = new LogicalSize(380, 520);
const MINI_MIN_SIZE = new LogicalSize(300, 240);
const NORMAL_MIN_SIZE = new LogicalSize(400, 400);

export type SnapEdge = 'left' | 'right' | 'top' | 'bottom';

interface EdgeSnapPayload {
  edge: SnapEdge | null;
  hidden: boolean;
}

interface MiniModeState {
  miniMode: boolean;
  snapEnabled: boolean;
  snapBusy: boolean;
  snapEdge: SnapEdge | null;
  isSnappedHidden: boolean;
  enterMiniMode: (alwaysOnTop: boolean) => Promise<void>;
  exitMiniMode: () => Promise<void>;
  setSnapEnabled: (value: boolean) => Promise<void>;
}

let prevSize: PhysicalSize | null = null;
let prevPosition: PhysicalPosition | null = null;
let prevMaximized = false;
let prevAlwaysOnTop = false;
let edgeSnapListenerStarted = false;

async function configureNativeEdgeSnap(miniMode: boolean, enabled: boolean) {
  await invoke('configure_edge_snap', { miniMode, enabled });
}

export const useMiniModeStore = create<MiniModeState>((set, get) => ({
  miniMode: false,
  snapEnabled: true,
  snapBusy: false,
  snapEdge: null,
  isSnappedHidden: false,

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
      await configureNativeEdgeSnap(true, get().snapEnabled);
      set({ miniMode: true });
    } catch (err) {
      console.warn('Failed to enter mini mode:', err);
      try {
        await configureNativeEdgeSnap(false, false);
      } catch {
        // Ignore cleanup errors and preserve the original failure.
      }
    }
  },

  exitMiniMode: async () => {
    if (!get().miniMode) return;
    try {
      await configureNativeEdgeSnap(false, false);
      await appWindow.setAlwaysOnTop(prevAlwaysOnTop);
      await appWindow.setMinSize(NORMAL_MIN_SIZE);
      if (prevMaximized) {
        await appWindow.maximize();
      } else {
        if (prevSize) await appWindow.setSize(prevSize);
        if (prevPosition) await appWindow.setPosition(prevPosition);
      }
      set({
        miniMode: false,
        snapEdge: null,
        isSnappedHidden: false,
      });
    } catch (err) {
      console.warn('Failed to exit mini mode:', err);
    }
  },

  setSnapEnabled: async (value) => {
    if (get().snapBusy || value === get().snapEnabled) return;
    set({ snapBusy: true });
    try {
      await configureNativeEdgeSnap(get().miniMode, value);
      set({
        snapEnabled: value,
        snapEdge: value ? get().snapEdge : null,
        isSnappedHidden: value ? get().isSnappedHidden : false,
      });
    } catch (err) {
      console.warn('Failed to configure edge snap:', err);
    } finally {
      set({ snapBusy: false });
    }
  },
}));

export function initializeEdgeSnapListener() {
  if (edgeSnapListenerStarted) return;
  edgeSnapListenerStarted = true;

  listen<EdgeSnapPayload>('edge-snap-state', (event) => {
    useMiniModeStore.setState({
      snapEdge: event.payload.edge,
      isSnappedHidden: event.payload.hidden,
    });
  }).catch((err) => {
    edgeSnapListenerStarted = false;
    console.warn('Failed to listen for edge snap state:', err);
  });
}
