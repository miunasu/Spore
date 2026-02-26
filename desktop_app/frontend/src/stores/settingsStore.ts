/**
 * 设置 Store - 管理应用设置
 */
import { create } from 'zustand';

const STORAGE_KEY = 'spore-settings';

interface SettingsState {
  // 自动清理短日志
  autoCleanShortLogs: boolean;
  autoCleanMinLines: number;
  
  // Actions
  setAutoCleanShortLogs: (enabled: boolean) => void;
  setAutoCleanMinLines: (minLines: number) => void;
}

interface SettingsConfig {
  autoCleanShortLogs: boolean;
  autoCleanMinLines: number;
}

const loadSettings = (): SettingsConfig => {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const config = JSON.parse(saved);
      return {
        autoCleanShortLogs: config.autoCleanShortLogs ?? false,
        autoCleanMinLines: config.autoCleanMinLines ?? 10,
      };
    }
  } catch (e) {
    console.warn('Failed to load settings:', e);
  }
  return { autoCleanShortLogs: false, autoCleanMinLines: 10 };
};

const saveSettings = (config: SettingsConfig) => {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
  } catch (e) {
    console.warn('Failed to save settings:', e);
  }
};

export const useSettingsStore = create<SettingsState>((set, get) => ({
  ...loadSettings(),

  setAutoCleanShortLogs: (enabled) => {
    set({ autoCleanShortLogs: enabled });
    saveSettings({ autoCleanShortLogs: enabled, autoCleanMinLines: get().autoCleanMinLines });
  },

  setAutoCleanMinLines: (minLines) => {
    set({ autoCleanMinLines: minLines });
    saveSettings({ autoCleanShortLogs: get().autoCleanShortLogs, autoCleanMinLines: minLines });
  },
}));
