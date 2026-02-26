/**
 * 对话面板组件 - 浏览器风格多标签页（对话 + 文件编辑）
 */
import React, { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { MessageList } from './MessageList';
import { InputArea } from './InputArea';
import { TodoBar } from './TodoBar';
import { FileEditorContent } from './FileEditorContent';
import { ModeSelector } from '../common/ModeSelector';
import { useChatStore } from '../../stores/chatStore';
import { useLogStore } from '../../stores/logStore';
import { useEditorStore } from '../../stores/editorStore';
import { useDragStore } from '../../stores/dragStore';
import { commandsApi } from '../../services/api';

// 标签类型
type TabType = 'chat' | 'file';
interface Tab {
  id: string;
  type: TabType;
  name: string;
  // 文件标签额外信息
  path?: string;
  hasChanges?: boolean;
}

export const ChatPanel: React.FC = () => {
  const {
    conversations,
    activeConversationId,
    historyFiles,
    newConversation,
    switchConversation,
    closeConversation,
    renameConversation,
    fetchHistoryFiles,
    loadHistoryFile,
  } = useChatStore();

  const { setActiveConversation } = useLogStore();
  const {
    openFiles,
    activeFilePath,
    switchFile,
    closeFile,
    openFile: openEditorFile,
  } = useEditorStore();
  const { isDragging, draggingFile, endDrag } = useDragStore();

  // 当前活跃标签：可能是对话或文件
  const [activeTabType, setActiveTabType] = useState<TabType>('chat');
  const [editingTabId, setEditingTabId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState('');
  const [showHistoryMenu, setShowHistoryMenu] = useState(false);
  const [menuPosition, setMenuPosition] = useState({ top: 0, right: 0 });
  const [isDragOver, setIsDragOver] = useState(false);
  const tabsRef = useRef<HTMLDivElement>(null);
  const historyButtonRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const dragCounterRef = useRef(0);
  const [tokenCount, setTokenCount] = useState<number | null>(null);
  
  // 上下文模式状态
  const [contextMode, setContextMode] = useState<string>('strong_context');
  const [availableModes, setAvailableModes] = useState<Array<{
    value: string;
    label: string;
    description: string;
  }>>([]);

  // 获取当前模式
  useEffect(() => {
    const fetchMode = async () => {
      try {
        const result = await commandsApi.getMode();
        setContextMode(result.mode);
        setAvailableModes(result.available_modes);
      } catch (err) {
        console.error('Failed to fetch context mode:', err);
      }
    };
    fetchMode();
  }, []);

  // 切换模式
  const handleModeChange = async (newMode: string) => {
    try {
      await commandsApi.setMode(newMode);
      setContextMode(newMode);
    } catch (err) {
      console.error('Failed to set context mode:', err);
    }
  };

  // 当对话切换时，通知后端并获取该对话的 token 数和模式
  useEffect(() => {
    if (activeConversationId) {
      // 通知后端当前活跃对话
      commandsApi.setActiveConversation(activeConversationId).catch(() => {});
      
      // 获取该对话的模式
      commandsApi.getMode().then((result) => {
        setContextMode(result.mode);
      }).catch(() => {});
    }
  }, [activeConversationId]);

  // 定时获取当前对话的 token 数量
  useEffect(() => {
    const fetchTokens = async () => {
      try {
        const result = await commandsApi.getTokens(activeConversationId || undefined);
        setTokenCount(result.token_count);
      } catch (err) {
        // 忽略错误
      }
    };

    fetchTokens();
    const interval = setInterval(fetchTokens, 5000);
    return () => clearInterval(interval);
  }, [activeConversationId]);

  // 格式化 token 数量
  const formatTokenCount = (count: number): string => {
    if (count >= 1000) {
      return `${(count / 1000).toFixed(1)}k`;
    }
    return count.toString();
  };

  // 构建统一的标签列表
  const tabs: Tab[] = [
    // 对话标签
    ...conversations.map((conv) => ({
      id: `chat-${conv.id}`,
      type: 'chat' as TabType,
      name: conv.name,
    })),
    // 文件标签
    ...openFiles.map((file) => ({
      id: `file-${file.path}`,
      type: 'file' as TabType,
      name: file.name,
      path: file.path,
      hasChanges: file.hasChanges,
    })),
  ];

  // 当前活跃标签 ID
  const activeTabId =
    activeTabType === 'chat'
      ? `chat-${activeConversationId}`
      : activeFilePath
        ? `file-${activeFilePath}`
        : null;

  // 同步日志 store 的活跃对话
  useEffect(() => {
    if (activeTabType === 'chat') {
      setActiveConversation(activeConversationId);
    }
  }, [activeConversationId, activeTabType, setActiveConversation]);

  // 当打开文件时自动切换到文件标签
  useEffect(() => {
    if (openFiles.length > 0 && activeFilePath) {
      setActiveTabType('file');
    }
  }, [openFiles.length, activeFilePath]);

  // 点击外部关闭菜单
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as Node;
      if (historyButtonRef.current?.contains(target)) return;
      const menuEl = document.getElementById('history-menu');
      if (menuEl?.contains(target)) return;
      setShowHistoryMenu(false);
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // 获取历史文件列表
  useEffect(() => {
    if (showHistoryMenu) {
      fetchHistoryFiles();
    }
  }, [showHistoryMenu, fetchHistoryFiles]);

  // 更新菜单位置
  useEffect(() => {
    if (showHistoryMenu && historyButtonRef.current) {
      const rect = historyButtonRef.current.getBoundingClientRect();
      setMenuPosition({
        top: rect.bottom + 4,
        right: window.innerWidth - rect.right,
      });
    }
  }, [showHistoryMenu]);

  // 全局 mouseup 监听 - 解决 Tauri webview 中 HTML5 drag-drop 不工作的问题
  useEffect(() => {
    const handleGlobalMouseUp = (e: MouseEvent) => {
      if (!isDragging || !draggingFile) return;

      if (panelRef.current) {
        const rect = panelRef.current.getBoundingClientRect();
        const isInPanel =
          e.clientX >= rect.left &&
          e.clientX <= rect.right &&
          e.clientY >= rect.top &&
          e.clientY <= rect.bottom;

        if (isInPanel) {
          openEditorFile(draggingFile.path, draggingFile.name);
        }
      }

      endDrag();
      setIsDragOver(false);
    };

    document.addEventListener('mouseup', handleGlobalMouseUp);
    return () => document.removeEventListener('mouseup', handleGlobalMouseUp);
  }, [isDragging, draggingFile, openEditorFile, endDrag]);

  // 监听拖拽状态变化
  useEffect(() => {
    setIsDragOver(isDragging);
  }, [isDragging]);

  // 点击标签
  const handleTabClick = (tab: Tab) => {
    if (tab.type === 'chat') {
      const convId = tab.id.replace('chat-', '');
      switchConversation(convId);
      setActiveTabType('chat');
    } else {
      switchFile(tab.path!);
      setActiveTabType('file');
    }
  };

  // 关闭标签
  const handleCloseTab = (e: React.MouseEvent, tab: Tab) => {
    e.stopPropagation();
    if (tab.type === 'chat') {
      const convId = tab.id.replace('chat-', '');
      closeConversation(convId);
    } else {
      closeFile(tab.path);
      // 如果关闭的是当前文件且没有其他文件了，切回对话
      if (openFiles.length <= 1) {
        setActiveTabType('chat');
      }
    }
  };

  // 鼠标中键关闭标签
  const handleMiddleClick = (e: React.MouseEvent, tab: Tab) => {
    if (e.button === 1) {
      e.preventDefault();
      handleCloseTab(e, tab);
    }
  };

  // 双击编辑标签名（仅对话标签）
  const handleDoubleClick = (tab: Tab) => {
    if (tab.type === 'chat') {
      setEditingTabId(tab.id);
      setEditingName(tab.name);
    }
  };

  const handleRenameSubmit = (tab: Tab) => {
    if (editingName.trim() && tab.type === 'chat') {
      const convId = tab.id.replace('chat-', '');
      renameConversation(convId, editingName.trim());
    }
    setEditingTabId(null);
  };

  // 拖拽处理
  const handleDragEnter = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounterRef.current++;
    if (
      isDragging ||
      e.dataTransfer.types.includes('application/json') ||
      e.dataTransfer.types.includes('text/plain')
    ) {
      setIsDragOver(true);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    e.dataTransfer.dropEffect = 'copy';
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounterRef.current--;
    if (dragCounterRef.current === 0 && !isDragging) {
      setIsDragOver(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounterRef.current = 0;
    setIsDragOver(false);

    if (draggingFile) {
      openEditorFile(draggingFile.path, draggingFile.name);
      endDrag();
      return;
    }

    let fileData = e.dataTransfer.getData('application/json');
    if (!fileData) {
      fileData = e.dataTransfer.getData('text/plain');
    }

    if (fileData) {
      try {
        const file = JSON.parse(fileData);
        if (file.type === 'file' && file.path && file.name) {
          openEditorFile(file.path, file.name);
        }
      } catch (err) {
        console.error('Failed to parse dropped file data:', err);
      }
    }
  };

  // 历史文件菜单
  const historyMenuContent = showHistoryMenu && (
    <div
      id="history-menu"
      className="fixed w-64 max-h-80 overflow-y-auto bg-spore-card border border-spore-border/50 rounded-lg shadow-lg py-1"
      style={{
        top: menuPosition.top,
        right: menuPosition.right,
        zIndex: 99999,
      }}
    >
      <div className="px-3 py-1.5 text-xs text-spore-muted border-b border-spore-border/30">
        历史对话
      </div>
      {historyFiles.length === 0 ? (
        <div className="px-3 py-4 text-sm text-spore-muted text-center">
          暂无历史记录
        </div>
      ) : (
        historyFiles.map((file) => (
          <button
            key={file.name}
            onClick={() => {
              loadHistoryFile(file.name);
              setShowHistoryMenu(false);
            }}
            className="w-full flex flex-col items-start px-3 py-2 text-sm text-spore-text hover:bg-spore-accent/30 transition-colors"
          >
            <span className="truncate w-full text-left">
              {file.name.replace('.mem', '')}
            </span>
            <span className="text-xs text-spore-muted">
              {new Date(file.modified * 1000).toLocaleString('zh-CN')}
            </span>
          </button>
        ))
      )}
    </div>
  );

  // 判断标签是否可关闭
  const canCloseTab = (tab: Tab) => {
    if (tab.type === 'chat') {
      return conversations.length > 1;
    }
    return true; // 文件标签总是可以关闭
  };

  return (
    <div
      ref={panelRef}
      className={`h-full flex flex-col relative ${isDragOver ? 'ring-2 ring-spore-highlight ring-inset' : ''}`}
      onDragEnter={handleDragEnter}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* 拖拽提示 */}
      {isDragOver && (
        <div className="absolute inset-0 bg-spore-highlight/10 flex items-center justify-center z-20 pointer-events-none">
          <div className="bg-spore-card border border-spore-highlight rounded-xl px-6 py-4 shadow-lg">
            <span className="text-spore-highlight font-medium">
              {draggingFile ? `释放以编辑: ${draggingFile.name}` : '释放以编辑文件'}
            </span>
          </div>
        </div>
      )}

      {/* 标签栏 */}
      <div className="flex items-center border-b border-spore-border/30 bg-spore-bg/50">
        {/* 标签页 */}
        <div
          ref={tabsRef}
          className="flex-1 flex items-center overflow-x-auto scrollbar-hide"
        >
          {tabs.map((tab) => (
            <div
              key={tab.id}
              onMouseDown={(e) => handleMiddleClick(e, tab)}
              onClick={() => handleTabClick(tab)}
              onDoubleClick={() => handleDoubleClick(tab)}
              className={`group flex items-center gap-1 px-3 py-2 min-w-[100px] max-w-[180px] cursor-pointer border-r border-spore-border/20 transition-colors ${
                tab.id === activeTabId
                  ? 'bg-spore-card text-spore-text'
                  : 'text-spore-muted hover:bg-spore-accent/20 hover:text-spore-text'
              }`}
            >
              {/* 标签图标 */}
              {tab.type === 'chat' ? (
                <span className="text-xs flex-shrink-0">💬</span>
              ) : (
                <svg
                  className="w-3.5 h-3.5 flex-shrink-0 text-spore-muted"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                  />
                </svg>
              )}

              {/* 标签名 */}
              {editingTabId === tab.id ? (
                <input
                  type="text"
                  value={editingName}
                  onChange={(e) => setEditingName(e.target.value)}
                  onBlur={() => handleRenameSubmit(tab)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleRenameSubmit(tab);
                    if (e.key === 'Escape') setEditingTabId(null);
                  }}
                  autoFocus
                  className="flex-1 min-w-0 bg-transparent border-b border-spore-highlight text-xs outline-none"
                />
              ) : (
                <span className="flex-1 text-xs truncate">{tab.name}</span>
              )}

              {/* 修改标记（文件标签） */}
              {tab.type === 'file' && tab.hasChanges && (
                <span className="text-spore-warning text-xs flex-shrink-0">●</span>
              )}

              {/* 关闭按钮 */}
              {canCloseTab(tab) && (
                <button
                  onClick={(e) => handleCloseTab(e, tab)}
                  className="opacity-0 group-hover:opacity-100 p-0.5 rounded hover:bg-spore-accent/50 transition-opacity"
                >
                  <svg
                    className="w-3 h-3"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M6 18L18 6M6 6l12 12"
                    />
                  </svg>
                </button>
              )}
            </div>
          ))}
        </div>

        {/* 操作按钮 */}
        <div className="flex items-center px-2 gap-1">
          {/* Token 显示 */}
          {tokenCount !== null && (
            <span className="text-xs text-spore-muted/60 px-2">
              {formatTokenCount(tokenCount)} tokens
            </span>
          )}

          {/* 上下文模式选择 */}
          <ModeSelector
            value={contextMode}
            modes={availableModes}
            onChange={handleModeChange}
          />

          {/* 新建对话标签 */}
          <button
            onClick={() => {
              newConversation();
              setActiveTabType('chat');
            }}
            className="p-1.5 rounded hover:bg-spore-accent/30 text-spore-muted hover:text-spore-text transition-colors"
            title="新建对话"
          >
            <svg
              className="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 4v16m8-8H4"
              />
            </svg>
          </button>

          {/* 历史对话按钮 */}
          <button
            ref={historyButtonRef}
            onClick={() => setShowHistoryMenu(!showHistoryMenu)}
            className="p-1.5 rounded hover:bg-spore-accent/30 text-spore-muted hover:text-spore-text transition-colors"
            title="加载历史对话"
          >
            <svg
              className="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
          </button>
        </div>
      </div>

      {/* 内容区域 */}
      {activeTabType === 'file' && activeFilePath ? (
        // 文件编辑内容
        <FileEditorContent />
      ) : (
        // 对话内容
        <>
          {/* Todo 进度条 */}
          <TodoBar />

          {/* 消息区域 */}
          <div className="flex-1 overflow-hidden">
            <MessageList />
          </div>

          {/* 输入区域 */}
          <div className="p-4">
            <InputArea />
          </div>
        </>
      )}

      {/* 使用 Portal 渲染历史菜单到 body */}
      {createPortal(historyMenuContent, document.body)}
    </div>
  );
};
