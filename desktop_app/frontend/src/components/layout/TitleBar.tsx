/**
 * 自定义标题栏组件
 * 与深色主题融合，支持窗口拖拽和控制按钮
 */
import React, { useRef, useState } from 'react';
import { appWindow } from '@tauri-apps/api/window';
import sporeIcon from '@icons/32x32.png';
import { useSettingsStore } from '../../stores/settingsStore';
import { useMiniModeStore } from '../../stores/miniModeStore';
import { useT, useLangStore } from '../../i18n';

export const TitleBar: React.FC = () => {
  const t = useT();
  const { lang, toggleLang } = useLangStore();
  const mouseDownPos = useRef<{ x: number; y: number } | null>(null);
  const isDragging = useRef(false);
  const lastClickTime = useRef(0);
  const { theme, toggleTheme } = useSettingsStore();
  const [alwaysOnTop, setAlwaysOnTop] = useState(false);
  const { miniMode, enterMiniMode, exitMiniMode } = useMiniModeStore();

  const handleMinimize = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    await appWindow.minimize();
  };

  const handleMaximize = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    await appWindow.toggleMaximize();
  };

  const handleClose = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    await appWindow.close();
  };

  const handleToggleTheme = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    toggleTheme();
  };

  const handleToggleLang = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    toggleLang();
  };

  const handleToggleAlwaysOnTop = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const next = !alwaysOnTop;
    try {
      await appWindow.setAlwaysOnTop(next);
      setAlwaysOnTop(next);
    } catch (err) {
      console.warn('Failed to set always on top:', err);
    }
  };

  const handleToggleMiniMode = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (miniMode) {
      // 退出后置顶还原为进入前的状态（即本地 alwaysOnTop 值），无需同步
      await exitMiniMode();
    } else {
      await enterMiniMode(alwaysOnTop);
    }
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('button')) return;
    if (e.button !== 0) return;
    
    const now = Date.now();
    const timeSinceLastClick = now - lastClickTime.current;
    
    // 双击检测（300ms内的第二次点击）
    if (timeSinceLastClick < 300) {
      lastClickTime.current = 0;
      appWindow.toggleMaximize();
      return;
    }
    
    lastClickTime.current = now;
    mouseDownPos.current = { x: e.clientX, y: e.clientY };
    isDragging.current = false;
  };

  const handleMouseMove = async (e: React.MouseEvent) => {
    if (!mouseDownPos.current || isDragging.current) return;
    
    const dx = Math.abs(e.clientX - mouseDownPos.current.x);
    const dy = Math.abs(e.clientY - mouseDownPos.current.y);
    
    // 移动超过 3px 才开始拖拽
    if (dx > 3 || dy > 3) {
      isDragging.current = true;
      mouseDownPos.current = null;
      await appWindow.startDragging();
    }
  };

  const handleMouseUp = () => {
    mouseDownPos.current = null;
    isDragging.current = false;
  };

  const handleMouseLeave = () => {
    mouseDownPos.current = null;
    isDragging.current = false;
  };

  return (
    <div
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseLeave}
      className="h-8 bg-spore-panel flex items-center justify-between px-3 select-none border-b border-spore-border/30 cursor-default"
    >
      {/* 左侧 - 应用标题 */}
      <div className="flex items-center gap-2 pointer-events-none">
        <img src={sporeIcon} alt="Spore" className="w-5 h-5 rounded" />
        <span className="text-xs font-medium text-spore-muted">Spore</span>
      </div>

      {/* 右侧 - 窗口控制按钮 */}
      <div className="flex items-center -mr-3">
        <button
          onClick={handleToggleMiniMode}
          className={`w-10 h-8 flex items-center justify-center transition-colors ${
            miniMode
              ? 'bg-spore-highlight/30 text-spore-highlight hover:bg-spore-highlight/40'
              : 'hover:bg-spore-accent/50 text-spore-muted'
          }`}
          title={miniMode ? t('titleBar.exitMiniMode') : t('titleBar.miniMode')}
          aria-pressed={miniMode}
        >
          <svg
            className="w-3.5 h-3.5"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.8}
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M21 9V6a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2h4"
            />
            <rect x="12" y="12" width="9" height="7" rx="1.5" />
          </svg>
        </button>

        <button
          onClick={handleToggleAlwaysOnTop}
          disabled={miniMode}
          className={`w-10 h-8 flex items-center justify-center transition-colors ${
            alwaysOnTop
              ? 'bg-spore-highlight/30 text-spore-highlight hover:bg-spore-highlight/40'
              : 'hover:bg-spore-accent/50 text-spore-muted'
          } ${miniMode ? 'opacity-40 cursor-not-allowed' : ''}`}
          title={miniMode ? t('titleBar.alwaysOnTopInMini') : alwaysOnTop ? t('titleBar.unpinWindow') : t('titleBar.pinWindow')}
          aria-pressed={alwaysOnTop}
        >
          <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
            <path d="M16 9V4h1c.55 0 1-.45 1-1s-.45-1-1-1H7c-.55 0-1 .45-1 1s.45 1 1 1h1v5c0 1.66-1.34 3-3 3v2h5.97v7l1 1 1-1v-7H19v-2c-1.66 0-3-1.34-3-3z" />
          </svg>
        </button>

        <button
          onClick={handleToggleLang}
          className="min-w-[2.5rem] h-8 px-2 flex items-center justify-center hover:bg-spore-accent/50 transition-colors text-[11px] font-medium text-spore-muted"
          title={t('titleBar.switchLanguage')}
          aria-label={t('titleBar.switchLanguage')}
        >
          {lang === 'zh' ? '中' : 'EN'}
        </button>

        <button
          onClick={handleToggleTheme}
          className="w-10 h-8 flex items-center justify-center hover:bg-spore-accent/50 transition-colors"
          title={theme === 'dark' ? t('titleBar.switchToLight') : t('titleBar.switchToDark')}
        >
          {theme === 'dark' ? (
            <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M12 3v2m0 14v2m7-9h2M3 12H5m11.364 6.364l1.414 1.414M6.222 6.222l1.414 1.414m0 8.728l-1.414 1.414m11.142-11.142l-1.414 1.414M12 8a4 4 0 100 8 4 4 0 000-8z"
              />
            </svg>
          ) : (
            <svg className="w-4 h-4 text-spore-muted" fill="currentColor" viewBox="0 0 24 24">
              <path d="M21.752 15.002a9.718 9.718 0 01-3.434.63c-5.385 0-9.75-4.365-9.75-9.75 0-1.199.217-2.347.614-3.408A9.751 9.751 0 1021.752 15z" />
            </svg>
          )}
        </button>

        <button
          onClick={handleMinimize}
          className="w-12 h-8 flex items-center justify-center hover:bg-spore-accent/50 transition-colors"
        >
          <svg className="w-4 h-[1px]" fill="currentColor" viewBox="0 0 16 1">
            <rect width="10" height="1" x="3" className="text-spore-muted" />
          </svg>
        </button>

        <button
          onClick={handleMaximize}
          className="w-12 h-8 flex items-center justify-center hover:bg-spore-accent/50 transition-colors"
        >
          <svg className="w-3 h-3 text-spore-muted" fill="none" stroke="currentColor" strokeWidth="1" viewBox="0 0 10 10">
            <rect x="0.5" y="0.5" width="9" height="9" />
          </svg>
        </button>

        <button
          onClick={handleClose}
          className="w-12 h-8 flex items-center justify-center hover:bg-red-600 transition-colors group"
        >
          <svg className="w-3 h-3 text-spore-muted group-hover:text-white" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 10 10">
            <path d="M1 1l8 8M9 1l-8 8" />
          </svg>
        </button>
      </div>
    </div>
  );
};
