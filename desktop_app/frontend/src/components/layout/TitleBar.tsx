/**
 * 自定义标题栏组件
 * 与深色主题融合，支持窗口拖拽和控制按钮
 */
import React, { useRef } from 'react';
import { appWindow } from '@tauri-apps/api/window';
import sporeIcon from '@icons/32x32.png';
import { useSettingsStore } from '../../stores/settingsStore';

export const TitleBar: React.FC = () => {
  const mouseDownPos = useRef<{ x: number; y: number } | null>(null);
  const isDragging = useRef(false);
  const lastClickTime = useRef(0);
  const { theme, toggleTheme } = useSettingsStore();

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
          onClick={handleToggleTheme}
          className="w-10 h-8 flex items-center justify-center hover:bg-spore-accent/50 transition-colors"
          title={theme === 'dark' ? '切换到亮色主题' : '切换到暗色主题'}
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
