/**
 * 文件管理器组件 - 现代化设计
 */
import React, { useState, useRef, useEffect } from 'react';
import { useFileStore } from '../../stores/fileStore';
import { useDragStore } from '../../stores/dragStore';
import { useEditorStore } from '../../stores/editorStore';
import { FileEditor } from './FileEditor';
import type { FileItem } from '../../types';

// 拖拽触发的最小移动距离（像素）
const DRAG_THRESHOLD = 5;
// 文件列表刷新间隔（毫秒）
const REFRESH_INTERVAL = 3000;

export const FileManager: React.FC = () => {
  const {
    currentPath,
    rootPath,
    items,
    editingFile,
    isLoading,
    loadDirectory,
    refreshDirectory,
    openFile,
    deleteItem,
    createItem,
    renameItem,
  } = useFileStore();

  const { startDrag, isDragging } = useDragStore();
  const { openFile: openInCenter } = useEditorStore();

  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    item?: FileItem;
  } | null>(null);
  const [menuPosition, setMenuPosition] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const contextMenuRef = useRef<HTMLDivElement>(null);
  const [newItemName, setNewItemName] = useState('');
  const [newItemType, setNewItemType] = useState<'file' | 'folder' | null>(null);
  const [renamingItem, setRenamingItem] = useState<FileItem | null>(null);
  const [renameValue, setRenameValue] = useState('');

  // 拖拽状态追踪
  const dragStartRef = useRef<{ x: number; y: number; item: FileItem } | null>(null);
  const isDragStartedRef = useRef(false);

  // 计算右键菜单位置，确保不超出窗口边界
  useEffect(() => {
    if (contextMenu && contextMenuRef.current) {
      const menuRect = contextMenuRef.current.getBoundingClientRect();
      const menuHeight = menuRect.height || 150; // 预估菜单高度
      const menuWidth = menuRect.width || 140;
      
      let x = contextMenu.x;
      let y = contextMenu.y;
      
      // 检查右边界
      if (x + menuWidth > window.innerWidth) {
        x = window.innerWidth - menuWidth - 8;
      }
      
      // 检查下边界 - 如果超出则向上展开
      if (y + menuHeight > window.innerHeight) {
        y = contextMenu.y - menuHeight;
        // 如果向上也超出，则贴近底部
        if (y < 0) {
          y = window.innerHeight - menuHeight - 8;
        }
      }
      
      // 确保不超出左边界和上边界
      x = Math.max(8, x);
      y = Math.max(8, y);
      
      setMenuPosition({ x, y });
    }
  }, [contextMenu]);

  // 定时刷新文件列表
  useEffect(() => {
    if (editingFile) return; // 编辑文件时不刷新
    
    const interval = setInterval(() => {
      refreshDirectory();
    }, REFRESH_INTERVAL);

    return () => clearInterval(interval);
  }, [editingFile, refreshDirectory]);

  // 如果正在编辑文件，显示编辑器
  if (editingFile) {
    return <FileEditor />;
  }

  // 返回上级目录（不能超出 rootPath）
  const handleGoUp = () => {
    if (!currentPath || currentPath === '.' || currentPath === '/') {
      return;
    }
    
    const normalizedPath = currentPath.replace(/\\/g, '/');
    const normalizedRoot = rootPath.replace(/\\/g, '/');
    
    // 如果已经在根目录，不能再往上
    if (normalizedPath === normalizedRoot) {
      return;
    }
    
    const parts = normalizedPath.split('/').filter(Boolean);
    if (parts.length > 1) {
      parts.pop();
      const parentPath = parts.join('/');
      // 确保不会超出根目录
      if (parentPath.startsWith(normalizedRoot) || parentPath === normalizedRoot) {
        loadDirectory(parentPath);
      } else {
        loadDirectory(normalizedRoot);
      }
    }
  };

  const handleDoubleClick = (item: FileItem) => {
    openFile(item);
  };

  const handleContextMenu = (e: React.MouseEvent, item?: FileItem) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, item });
  };

  const handleCreate = async () => {
    if (!newItemName.trim() || !newItemType) return;
    await createItem(newItemName.trim(), newItemType);
    setNewItemName('');
    setNewItemType(null);
  };

  const handleRename = async () => {
    if (!renamingItem || !renameValue.trim()) return;
    await renameItem(renamingItem.path, renameValue.trim());
    setRenamingItem(null);
    setRenameValue('');
  };

  // 处理鼠标按下 - 记录起始位置
  const handleMouseDown = (e: React.MouseEvent, item: FileItem) => {
    if (e.button === 0 && item.type === 'file') {
      dragStartRef.current = { x: e.clientX, y: e.clientY, item };
      isDragStartedRef.current = false;
    }
  };

  // 处理鼠标移动 - 检测是否超过阈值触发拖拽
  const handleMouseMove = (e: React.MouseEvent) => {
    if (!dragStartRef.current || isDragStartedRef.current || isDragging) return;

    const dx = Math.abs(e.clientX - dragStartRef.current.x);
    const dy = Math.abs(e.clientY - dragStartRef.current.y);
    const distance = Math.sqrt(dx * dx + dy * dy);

    if (distance >= DRAG_THRESHOLD) {
      // 超过阈值，开始拖拽
      isDragStartedRef.current = true;
      startDrag({
        path: dragStartRef.current.item.path,
        name: dragStartRef.current.item.name,
      });
    }
  };

  // 处理鼠标释放 - 清理状态
  const handleMouseUp = () => {
    dragStartRef.current = null;
    isDragStartedRef.current = false;
  };

  return (
    <div className="h-full flex flex-col">
      {/* 路径栏 */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-spore-border/30">
        <button
          onClick={handleGoUp}
          className="p-1.5 hover:bg-spore-accent rounded-lg transition-colors"
          title="返回上级"
        >
          <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
        </button>
        <div className="flex-1 flex items-center gap-1 text-xs text-spore-muted bg-spore-bg/50 rounded-lg px-2 py-1.5 truncate">
          <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
          </svg>
          <span className="truncate">{currentPath || '/'}</span>
        </div>
        <button
          onClick={() => setNewItemType('file')}
          className="p-1.5 hover:bg-spore-accent rounded-lg transition-colors"
          title="新建文件"
        >
          <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 13h6m-3-3v6m5 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
        </button>
        <button
          onClick={() => setNewItemType('folder')}
          className="p-1.5 hover:bg-spore-accent rounded-lg transition-colors"
          title="新建文件夹"
        >
          <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 13h6m-3-3v6m-9 1V7a2 2 0 012-2h6l2 2h6a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
          </svg>
        </button>
      </div>

      {/* 新建输入框 */}
      {newItemType && (
        <div className="p-3 border-b border-spore-border/30 bg-spore-card/50">
          <div className="flex gap-2">
            <input
              type="text"
              value={newItemName}
              onChange={(e) => setNewItemName(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
              placeholder={`新建${newItemType === 'file' ? '文件' : '文件夹'}名称`}
              className="flex-1 bg-spore-bg border border-spore-border/50 rounded-lg px-3 py-2 text-xs focus:border-spore-highlight/50 focus:outline-none"
              autoFocus
            />
            <button
              onClick={handleCreate}
              className="px-3 py-2 bg-spore-highlight hover:bg-spore-highlight-hover text-white rounded-lg text-xs font-medium transition-colors"
            >
              创建
            </button>
            <button
              onClick={() => { setNewItemType(null); setNewItemName(''); }}
              className="px-3 py-2 bg-spore-accent hover:bg-spore-border rounded-lg text-xs transition-colors"
            >
              取消
            </button>
          </div>
        </div>
      )}

      {/* 文件列表 */}
      <div
        className="flex-1 overflow-y-auto p-2"
        onContextMenu={(e) => handleContextMenu(e)}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <div className="flex items-center gap-2 text-spore-muted text-sm">
              <svg className="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              加载中...
            </div>
          </div>
        ) : items.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-spore-muted">
            <svg className="w-12 h-12 mb-2 opacity-30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
            </svg>
            <span className="text-sm">空目录</span>
          </div>
        ) : (
          <div className="space-y-1">
            {items.map((item) => (
              <div
                key={item.path}
                onMouseDown={(e) => handleMouseDown(e, item)}
                onClick={(e) => {
                  // Ctrl+Click 在中栏打开文件
                  if (e.ctrlKey && item.type === 'file') {
                    e.stopPropagation();
                    openInCenter(item.path, item.name);
                  }
                }}
                className={`flex items-center gap-3 px-3 py-2 hover:bg-spore-accent/50 rounded-lg cursor-pointer transition-colors group ${item.type === 'file' ? 'select-none' : ''}`}
                onDoubleClick={(e) => {
                  e.stopPropagation();
                  // 只有没有触发拖拽时才处理双击
                  if (!isDragStartedRef.current) {
                    handleDoubleClick(item);
                  }
                }}
                onContextMenu={(e) => { e.stopPropagation(); handleContextMenu(e, item); }}
              >
                {/* 图标 */}
                {item.type === 'folder' ? (
                  <svg className="w-5 h-5 text-spore-warning flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                  </svg>
                ) : (
                  <svg className="w-5 h-5 text-spore-muted flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clipRule="evenodd" />
                  </svg>
                )}
                
                {/* 名称 */}
                {renamingItem?.path === item.path ? (
                  <input
                    type="text"
                    value={renameValue}
                    onChange={(e) => setRenameValue(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') handleRename();
                      if (e.key === 'Escape') { setRenamingItem(null); setRenameValue(''); }
                    }}
                    onBlur={handleRename}
                    className="flex-1 bg-spore-bg border border-spore-highlight/50 rounded-lg px-2 py-1 text-sm focus:outline-none"
                    autoFocus
                    onClick={(e) => e.stopPropagation()}
                  />
                ) : (
                  <span className="flex-1 truncate text-sm text-spore-text group-hover:text-white transition-colors">
                    {item.name}
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 右键菜单 */}
      {contextMenu && (
        <>
          <div
            className="fixed inset-0 z-10"
            onClick={() => setContextMenu(null)}
          />
          <div
            ref={contextMenuRef}
            className="fixed bg-spore-card border border-spore-border/50 rounded-xl shadow-elevated z-20 py-2 min-w-[140px] animate-fade-in"
            style={{ left: menuPosition.x || contextMenu.x, top: menuPosition.y || contextMenu.y }}
          >
            {contextMenu.item && (
              <>
                <button
                  onClick={() => {
                    setRenamingItem(contextMenu.item!);
                    setRenameValue(contextMenu.item!.name);
                    setContextMenu(null);
                  }}
                  className="w-full px-4 py-2 text-left text-sm hover:bg-spore-accent/50 flex items-center gap-2 transition-colors"
                >
                  <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                  </svg>
                  重命名
                </button>
                <button
                  onClick={() => {
                    if (confirm(`确定删除 ${contextMenu.item!.name}？`)) {
                      deleteItem(contextMenu.item!.path);
                    }
                    setContextMenu(null);
                  }}
                  className="w-full px-4 py-2 text-left text-sm hover:bg-spore-error/20 text-spore-error flex items-center gap-2 transition-colors"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                  删除
                </button>
              </>
            )}
            <button
              onClick={() => { setNewItemType('file'); setContextMenu(null); }}
              className="w-full px-4 py-2 text-left text-sm hover:bg-spore-accent/50 flex items-center gap-2 transition-colors"
            >
              <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 13h6m-3-3v6m5 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              新建文件
            </button>
            <button
              onClick={() => { setNewItemType('folder'); setContextMenu(null); }}
              className="w-full px-4 py-2 text-left text-sm hover:bg-spore-accent/50 flex items-center gap-2 transition-colors"
            >
              <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 13h6m-3-3v6m-9 1V7a2 2 0 012-2h6l2 2h6a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
              </svg>
              新建文件夹
            </button>
          </div>
        </>
      )}
    </div>
  );
};
