/**
 * 主布局组件
 * 三栏布局：左栏日志 | 中栏对话 | 右栏文件/Agent
 * 支持拖拽调整各栏宽度，配置持久化到localStorage
 * 支持隐藏/显示左右栏
 */
import React, { useState, useCallback, useEffect } from 'react';
import { Resizer } from './Resizer';

interface MainLayoutProps {
  leftPanel: React.ReactNode;
  centerPanel: React.ReactNode;
  rightPanel: React.ReactNode;
}

const MIN_LEFT_WIDTH = 200;
const MAX_LEFT_WIDTH = 500;
const MIN_RIGHT_WIDTH = 250;
const MAX_RIGHT_WIDTH = 600;
const STORAGE_KEY = 'spore-layout-config';

interface LayoutConfig {
  leftWidth: number;
  rightWidth: number;
  leftVisible: boolean;
  rightVisible: boolean;
}

const loadConfig = (): LayoutConfig => {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const config = JSON.parse(saved);
      return {
        leftWidth: config.leftWidth ?? 280,
        rightWidth: config.rightWidth ?? 320,
        leftVisible: config.leftVisible ?? true,
        rightVisible: config.rightVisible ?? true,
      };
    }
  } catch (e) {
    console.warn('Failed to load layout config:', e);
  }
  return { leftWidth: 280, rightWidth: 320, leftVisible: true, rightVisible: true };
};

const saveConfig = (config: LayoutConfig) => {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
  } catch (e) {
    console.warn('Failed to save layout config:', e);
  }
};

export const MainLayout: React.FC<MainLayoutProps> = ({
  leftPanel,
  centerPanel,
  rightPanel,
}) => {
  const [leftWidth, setLeftWidth] = useState(() => loadConfig().leftWidth);
  const [rightWidth, setRightWidth] = useState(() => loadConfig().rightWidth);
  const [leftVisible, setLeftVisible] = useState(() => loadConfig().leftVisible);
  const [rightVisible, setRightVisible] = useState(() => loadConfig().rightVisible);

  // 保存配置到localStorage
  useEffect(() => {
    saveConfig({ leftWidth, rightWidth, leftVisible, rightVisible });
  }, [leftWidth, rightWidth, leftVisible, rightVisible]);

  const handleLeftResize = useCallback((delta: number) => {
    setLeftWidth((prev) => Math.min(MAX_LEFT_WIDTH, Math.max(MIN_LEFT_WIDTH, prev + delta)));
  }, []);

  const handleRightResize = useCallback((delta: number) => {
    setRightWidth((prev) => Math.min(MAX_RIGHT_WIDTH, Math.max(MIN_RIGHT_WIDTH, prev - delta)));
  }, []);

  return (
    <div className="flex h-full bg-spore-bg text-spore-text relative">
      {/* 左栏 - 日志面板 */}
      {leftVisible && (
        <>
          <div className="bg-spore-panel flex-shrink-0 overflow-hidden" style={{ width: leftWidth }}>
            {leftPanel}
          </div>
          <Resizer direction="horizontal" onResize={handleLeftResize} />
        </>
      )}

      {/* 中栏 - 对话面板 */}
      <div className="flex-1 min-w-[300px] bg-spore-bg overflow-hidden relative">
        {centerPanel}

        {/* 左栏切换按钮 */}
        <button
          onClick={() => setLeftVisible((v) => !v)}
          className="absolute left-2 top-1/2 -translate-y-1/2 p-1.5 hover:bg-spore-accent/50 rounded-lg transition-all z-10 opacity-0 hover:opacity-100"
          title={leftVisible ? '隐藏左栏' : '显示左栏'}
        >
          <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d={leftVisible ? 'M11 19l-7-7 7-7' : 'M13 5l7 7-7 7'}
            />
          </svg>
        </button>

        {/* 右栏切换按钮 */}
        <button
          onClick={() => setRightVisible((v) => !v)}
          className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 hover:bg-spore-accent/50 rounded-lg transition-all z-10 opacity-0 hover:opacity-100"
          title={rightVisible ? '隐藏右栏' : '显示右栏'}
        >
          <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d={rightVisible ? 'M13 5l7 7-7 7' : 'M11 19l-7-7 7-7'}
            />
          </svg>
        </button>
      </div>

      {/* 右栏 - 侧边面板 */}
      {rightVisible && (
        <>
          <Resizer direction="horizontal" onResize={handleRightResize} />
          <div className="bg-spore-panel flex-shrink-0 overflow-hidden" style={{ width: rightWidth }}>
            {rightPanel}
          </div>
        </>
      )}
    </div>
  );
};
