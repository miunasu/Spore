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
  htmlRenderingEnabled: boolean;
  frontendAgentEnabled: boolean;
  setAutoCleanShortLogs: (enabled: boolean) => void;
  setAutoCleanMinLines: (minLines: number) => void;
  setTheme: (theme: ThemeMode) => void;
  toggleTheme: () => void;
  setHtmlRenderingEnabled: (enabled: boolean) => void;
  toggleHtmlRendering: () => void;
  setFrontendAgentEnabled: (enabled: boolean) => void;
  toggleFrontendAgent: () => void;
}

interface SettingsConfig {
  autoCleanShortLogs: boolean;
  autoCleanMinLines: number;
  theme: ThemeMode;
  htmlRenderingEnabled: boolean;
  frontendAgentEnabled: boolean;
}

const DEFAULT_SETTINGS: SettingsConfig = {
  autoCleanShortLogs: false,
  autoCleanMinLines: 10,
  theme: 'dark',
  htmlRenderingEnabled: false,
  frontendAgentEnabled: true,
};

const isValidTheme = (value: unknown): value is ThemeMode =>
  value === 'dark' || value === 'light';

const loadSettings = (): SettingsConfig => {
  try {
    if (typeof localStorage === 'undefined' || typeof localStorage.getItem !== 'function') {
      return DEFAULT_SETTINGS;
    }
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const config = JSON.parse(saved);
      return {
        autoCleanShortLogs: config.autoCleanShortLogs ?? DEFAULT_SETTINGS.autoCleanShortLogs,
        autoCleanMinLines: config.autoCleanMinLines ?? DEFAULT_SETTINGS.autoCleanMinLines,
        theme: isValidTheme(config.theme) ? config.theme : DEFAULT_SETTINGS.theme,
        htmlRenderingEnabled: config.htmlRenderingEnabled ?? DEFAULT_SETTINGS.htmlRenderingEnabled,
        frontendAgentEnabled: config.frontendAgentEnabled ?? DEFAULT_SETTINGS.frontendAgentEnabled,
      };
    }
  } catch (e) {
    console.warn('Failed to load settings:', e);
  }
  return DEFAULT_SETTINGS;
};

const saveSettings = (config: SettingsConfig) => {
  try {
    if (typeof localStorage === 'undefined' || typeof localStorage.setItem !== 'function') return;
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
      htmlRenderingEnabled: get().htmlRenderingEnabled,
      frontendAgentEnabled: get().frontendAgentEnabled,
    });
  },

  setAutoCleanMinLines: (minLines) => {
    set({ autoCleanMinLines: minLines });
    saveSettings({
      autoCleanShortLogs: get().autoCleanShortLogs,
      autoCleanMinLines: minLines,
      theme: get().theme,
      htmlRenderingEnabled: get().htmlRenderingEnabled,
      frontendAgentEnabled: get().frontendAgentEnabled,
    });
  },

  setTheme: (theme) => {
    set({ theme });
    saveSettings({
      autoCleanShortLogs: get().autoCleanShortLogs,
      autoCleanMinLines: get().autoCleanMinLines,
      theme,
      htmlRenderingEnabled: get().htmlRenderingEnabled,
      frontendAgentEnabled: get().frontendAgentEnabled,
    });
  },

  toggleTheme: () => {
    const nextTheme: ThemeMode = get().theme === 'dark' ? 'light' : 'dark';
    set({ theme: nextTheme });
    saveSettings({
      autoCleanShortLogs: get().autoCleanShortLogs,
      autoCleanMinLines: get().autoCleanMinLines,
      theme: nextTheme,
      htmlRenderingEnabled: get().htmlRenderingEnabled,
      frontendAgentEnabled: get().frontendAgentEnabled,
    });
  },

  setHtmlRenderingEnabled: (enabled) => {
    set({ htmlRenderingEnabled: enabled });
    saveSettings({
      autoCleanShortLogs: get().autoCleanShortLogs,
      autoCleanMinLines: get().autoCleanMinLines,
      theme: get().theme,
      htmlRenderingEnabled: enabled,
      frontendAgentEnabled: get().frontendAgentEnabled,
    });
  },

  toggleHtmlRendering: () => {
    get().setHtmlRenderingEnabled(!get().htmlRenderingEnabled);
  },

  setFrontendAgentEnabled: (enabled) => {
    set({ frontendAgentEnabled: enabled });
    saveSettings({
      autoCleanShortLogs: get().autoCleanShortLogs,
      autoCleanMinLines: get().autoCleanMinLines,
      theme: get().theme,
      htmlRenderingEnabled: get().htmlRenderingEnabled,
      frontendAgentEnabled: enabled,
    });
  },

  toggleFrontendAgent: () => {
    get().setFrontendAgentEnabled(!get().frontendAgentEnabled);
  },
}));

