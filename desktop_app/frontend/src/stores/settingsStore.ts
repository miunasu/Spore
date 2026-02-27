/**
 * Settings store.
 */
import { create } from 'zustand';

const STORAGE_KEY = 'spore-settings';

export type ThemeMode = 'dark' | 'light';

interface SettingsState {
  autoCleanShortLogs: boolean;
  autoCleanMinLines: number;
  theme: ThemeMode;
  setAutoCleanShortLogs: (enabled: boolean) => void;
  setAutoCleanMinLines: (minLines: number) => void;
  setTheme: (theme: ThemeMode) => void;
  toggleTheme: () => void;
}

interface SettingsConfig {
  autoCleanShortLogs: boolean;
  autoCleanMinLines: number;
  theme: ThemeMode;
}

const DEFAULT_SETTINGS: SettingsConfig = {
  autoCleanShortLogs: false,
  autoCleanMinLines: 10,
  theme: 'dark',
};

const isValidTheme = (value: unknown): value is ThemeMode =>
  value === 'dark' || value === 'light';

const loadSettings = (): SettingsConfig => {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const config = JSON.parse(saved);
      return {
        autoCleanShortLogs: config.autoCleanShortLogs ?? DEFAULT_SETTINGS.autoCleanShortLogs,
        autoCleanMinLines: config.autoCleanMinLines ?? DEFAULT_SETTINGS.autoCleanMinLines,
        theme: isValidTheme(config.theme) ? config.theme : DEFAULT_SETTINGS.theme,
      };
    }
  } catch (e) {
    console.warn('Failed to load settings:', e);
  }
  return DEFAULT_SETTINGS;
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
    saveSettings({
      autoCleanShortLogs: enabled,
      autoCleanMinLines: get().autoCleanMinLines,
      theme: get().theme,
    });
  },

  setAutoCleanMinLines: (minLines) => {
    set({ autoCleanMinLines: minLines });
    saveSettings({
      autoCleanShortLogs: get().autoCleanShortLogs,
      autoCleanMinLines: minLines,
      theme: get().theme,
    });
  },

  setTheme: (theme) => {
    set({ theme });
    saveSettings({
      autoCleanShortLogs: get().autoCleanShortLogs,
      autoCleanMinLines: get().autoCleanMinLines,
      theme,
    });
  },

  toggleTheme: () => {
    const nextTheme: ThemeMode = get().theme === 'dark' ? 'light' : 'dark';
    set({ theme: nextTheme });
    saveSettings({
      autoCleanShortLogs: get().autoCleanShortLogs,
      autoCleanMinLines: get().autoCleanMinLines,
      theme: nextTheme,
    });
  },
}));

