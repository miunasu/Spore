/**
 * 侧边面板组件 - 现代化设计
 * 包含文件管理器和 Agent 监控
 */
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { FileManager } from './FileManager';
import { AgentMonitor } from './AgentMonitor';
import { NoteEditor } from './NoteEditor';
import { useFileStore } from '../../stores/fileStore';
import type { TabType, FileItem } from '../../types';

const TABS: { id: TabType; label: string; path?: string; icon: string }[] = [
  { id: 'note', label: 'note', icon: 'M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z' },
  { id: 'output', label: 'output', path: 'output', icon: 'M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4' },
  { id: 'agents', label: 'Agent', icon: 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z' },
  { id: 'prompt', label: 'prompt', path: 'prompt', icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
  { id: 'skills', label: 'skills', path: 'skills', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
  { id: 'history', label: 'history', path: 'history', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
  { id: 'characters', label: 'characters', path: 'characters', icon: 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z' },
];

// 每个 tab 的状态：要么是文件夹路径，要么是打开的文件+滚动位置
interface TabState {
  type: 'folder' | 'file';
  path: string; // 文件夹路径 或 文件路径
  // 文件状态
  file?: FileItem;
  content?: string;
  scrollTop?: number;
}

// 判断是否是文件管理器 tab
const isFileTab = (tabId: TabType) => tabId !== 'agents' && tabId !== 'note';

// 获取 tab 的根目录
const getTabRoot = (tabId: TabType): string | null => {
  const tab = TABS.find((t) => t.id === tabId);
  return tab?.path || null;
};

// 检查路径是否属于指定 tab 的根目录
const isPathBelongsToTab = (path: string, tabId: TabType): boolean => {
  const root = getTabRoot(tabId);
  if (!root) return false;
  const normalizedPath = path.replace(/\\/g, '/');
  return normalizedPath === root || normalizedPath.startsWith(root + '/');
};

export const SidePanel: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>('note');
  // 每个 tab 的状态缓存
  const [tabStates, setTabStates] = useState<Record<string, TabState>>({});
  
  const {
    currentPath,
    editingFile,
    editingContent,
    editingScrollTop,
    loadDirectory,
    setRootPath,
    setEditingFile,
    setEditingContent,
    setEditingScrollTop,
    closeEditor,
  } = useFileStore();
  
  const tabsRef = useRef<HTMLDivElement>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [startX, setStartX] = useState(0);
  const [scrollLeft, setScrollLeft] = useState(0);
  const isInitialMount = useRef(true);
  const prevTabRef = useRef<TabType>('note');

  // 保存当前 tab 的状态
  const saveCurrentTabState = useCallback(() => {
    if (!isFileTab(activeTab)) return;
    
    if (editingFile) {
      // 正在编辑文件 → 保存文件状态
      setTabStates(prev => ({
        ...prev,
        [activeTab]: {
          type: 'file',
          path: editingFile.path,
          file: editingFile,
          content: editingContent,
          scrollTop: editingScrollTop,
        },
      }));
    } else if (currentPath && isPathBelongsToTab(currentPath, activeTab)) {
      // 在文件夹中 → 保存路径
      setTabStates(prev => ({
        ...prev,
        [activeTab]: {
          type: 'folder',
          path: currentPath,
        },
      }));
    }
  }, [activeTab, editingFile, editingContent, editingScrollTop, currentPath]);

  // 恢复 tab 的状态
  const restoreTabState = useCallback(async (tabId: TabType) => {
    const state = tabStates[tabId];
    const tab = TABS.find(t => t.id === tabId);
    const root = tab?.path || tabId;
    
    // 设置根目录限制
    setRootPath(root);
    
    if (state) {
      // 校验缓存的路径是否属于当前 tab 的根目录
      const isValidPath = isPathBelongsToTab(state.path, tabId);
      
      if (isValidPath && state.type === 'file' && state.file) {
        // 恢复文件编辑状态
        setEditingFile(state.file);
        setEditingContent(state.content || '');
        setEditingScrollTop(state.scrollTop || 0);
      } else if (isValidPath && state.type === 'folder') {
        // 恢复文件夹路径
        closeEditor();
        await loadDirectory(state.path);
      } else {
        // 路径无效，加载默认根目录
        closeEditor();
        await loadDirectory(root);
      }
    } else {
      // 没有保存的状态，加载默认路径
      closeEditor();
      await loadDirectory(root);
    }
  }, [tabStates, loadDirectory, setRootPath, setEditingFile, setEditingContent, setEditingScrollTop, closeEditor]);

  // 切换 Tab
  const handleTabChange = useCallback(async (newTab: TabType) => {
    if (newTab === activeTab) return;
    
    // 保存当前 tab 状态
    saveCurrentTabState();
    
    setActiveTab(newTab);
    prevTabRef.current = newTab;
    
    // 恢复新 tab 的状态
    if (isFileTab(newTab)) {
      await restoreTabState(newTab);
    }
  }, [activeTab, saveCurrentTabState, restoreTabState]);

  // 初始加载
  useEffect(() => {
    if (isInitialMount.current) {
      isInitialMount.current = false;
      if (isFileTab(activeTab)) {
        const tab = TABS.find(t => t.id === activeTab);
        const root = tab?.path || activeTab;
        setRootPath(root);
        loadDirectory(root);
      }
    }
  }, []);

  // 鼠标拖动滑动
  const handleMouseDown = (e: React.MouseEvent) => {
    if (!tabsRef.current) return;
    setIsDragging(true);
    setStartX(e.pageX - tabsRef.current.offsetLeft);
    setScrollLeft(tabsRef.current.scrollLeft);
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging || !tabsRef.current) return;
    e.preventDefault();
    const x = e.pageX - tabsRef.current.offsetLeft;
    const walk = (x - startX) * 1.5;
    tabsRef.current.scrollLeft = scrollLeft - walk;
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleMouseLeave = () => {
    setIsDragging(false);
  };

  return (
    <div className="h-full flex flex-col">
      {/* Tab 栏 - 支持拖动滑动 */}
      <div
        ref={tabsRef}
        className={`flex border-b border-spore-border/30 px-1 pt-2 gap-0.5 overflow-x-auto scrollbar-hide select-none ${isDragging ? 'cursor-grabbing' : 'cursor-grab'}`}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseLeave}
      >
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => !isDragging && handleTabChange(tab.id)}
            className={`flex items-center gap-1 px-2 py-1.5 text-xs font-medium whitespace-nowrap rounded-t-lg transition-colors flex-shrink-0 ${
              activeTab === tab.id
                ? 'text-spore-highlight bg-spore-card border-t border-l border-r border-spore-border/30'
                : 'text-spore-muted hover:text-spore-text hover:bg-spore-accent/30 border-t border-l border-r border-transparent'
            }`}
          >
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={tab.icon} />
            </svg>
            {tab.label}
          </button>
        ))}
      </div>

      {/* 内容区域 */}
      <div className="flex-1 overflow-hidden">
        {activeTab === 'agents' ? (
          <AgentMonitor />
        ) : activeTab === 'note' ? (
          <NoteEditor />
        ) : (
          <FileManager />
        )}
      </div>
    </div>
  );
};
