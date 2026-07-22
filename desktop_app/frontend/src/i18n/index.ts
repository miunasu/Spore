/**
 * Lightweight i18n for Spore.
 *
 * - No external deps (consistent with the minimal frontend stack).
 * - Language is persisted to localStorage and exposed via a Zustand store so
 *   components re-render on switch.
 * - Lookup falls back requested-lang -> zh -> raw key, so an incomplete English
 *   translation shows Chinese rather than a bare key during incremental rollout.
 */
import { create } from 'zustand';
import { messages } from './locales';

export type Lang = 'zh' | 'en';

const STORAGE_KEY = 'spore-lang';

const detectDefaultLang = (): Lang => {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'zh' || saved === 'en') return saved;
  } catch {
    /* ignore */
  }
  try {
    const nav = (navigator.language || '').toLowerCase();
    if (nav.startsWith('zh')) return 'zh';
  } catch {
    /* ignore */
  }
  // Existing UI content is Chinese-first; default to zh when unsure.
  return 'zh';
};

interface LangState {
  lang: Lang;
  setLang: (lang: Lang) => void;
  toggleLang: () => void;
}

export const useLangStore = create<LangState>((set, get) => ({
  lang: detectDefaultLang(),
  setLang: (lang) => {
    try {
      localStorage.setItem(STORAGE_KEY, lang);
    } catch {
      /* ignore */
    }
    set({ lang });
  },
  toggleLang: () => get().setLang(get().lang === 'zh' ? 'en' : 'zh'),
}));

type Dict = Record<string, unknown>;

const lookup = (dict: Dict, key: string): string | undefined => {
  const value = key.split('.').reduce<unknown>((acc, part) => {
    if (acc && typeof acc === 'object') {
      return (acc as Dict)[part];
    }
    return undefined;
  }, dict);
  return typeof value === 'string' ? value : undefined;
};

const interpolate = (template: string, params?: Record<string, string | number>): string => {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (match, name) => {
    const replacement = params[name];
    return replacement === undefined ? match : String(replacement);
  });
};

/**
 * Translate a key for a given language. Falls back to zh, then the raw key.
 * Safe to call outside React (uses the current store value).
 */
export const translate = (
  lang: Lang,
  key: string,
  params?: Record<string, string | number>,
): string => {
  const primary = lookup(messages[lang] as Dict, key);
  if (primary !== undefined) return interpolate(primary, params);
  const zhFallback = lang !== 'zh' ? lookup(messages.zh as Dict, key) : undefined;
  if (zhFallback !== undefined) return interpolate(zhFallback, params);
  return key;
};

/**
 * Non-reactive translate using the current language. Use inside stores/services
 * or event handlers where a hook isn't available.
 */
export const t = (key: string, params?: Record<string, string | number>): string =>
  translate(useLangStore.getState().lang, key, params);

/**
 * BCP-47 locale tag for the given (or current) language, for
 * `toLocaleString` / `Intl` date & number formatting.
 */
export const localeTag = (lang?: Lang): string =>
  (lang ?? useLangStore.getState().lang) === 'zh' ? 'zh-CN' : 'en-US';

/**
 * React hook: returns a `t` bound to the current language and re-renders on switch.
 */
export const useT = () => {
  const lang = useLangStore((s) => s.lang);
  return (key: string, params?: Record<string, string | number>): string =>
    translate(lang, key, params);
};
