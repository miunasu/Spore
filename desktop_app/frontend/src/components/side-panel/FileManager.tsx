/**
 * 文件管理器组件 - 现代化设计
 */
import React, { useState, useRef, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { useFileStore } from '../../stores/fileStore';
import { useDragStore } from '../../stores/dragStore';
import { useEditorStore } from '../../stores/editorStore';
import { useT } from '../../i18n';
import { FileEditor } from './FileEditor';
import type { FileItem } from '../../types';

// 拖拽触发的最小移动距离（像素）
const DRAG_THRESHOLD = 5;
// 文件列表刷新间隔（毫秒）
const REFRESH_INTERVAL = 3000;

type ClipboardMode = 'copy' | 'cut';

type SystemFileClipboard = {
  paths: string[];
  operation: ClipboardMode;
};

export const FileManager: React.FC<{ isSporeTab?: boolean }> = ({ isSporeTab = false }) => {
  const t = useT();
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
    copyItem,
    moveItem,
    openLocation,
  } = useFileStore();

  // Spore tab过滤逻辑：只显示目录，排除.spore和根目录文件
  const filteredItems = isSporeTab
    ? items.filter(item => {
        // 排除.spore目录
        if (item.name === '.spore') return false;

        // 检查是否在根目录
        const normalizedPath = currentPath.replace(/\\/g, '/');
        const normalizedRoot = rootPath.replace(/\\/g, '/');
        const isInRoot = normalizedPath === normalizedRoot || normalizedPath === '' || normalizedPath === '.';

        // 根目录：只显示目录
        if (isInRoot) {
          return item.type === 'folder';
        }

        // 子目录：显示所有内容
        return true;
      })
    : items;

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
  const [clipboardItem, setClipboardItem] = useState<{
    item: FileItem;
    mode: ClipboardMode;
  } | null>(null);
  const [canPasteFiles, setCanPasteFiles] = useState(false);

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

    // 移除最后一级
    parts.pop();

    // 如果pop后为空，返回根目录
    if (parts.length === 0) {
      loadDirectory(normalizedRoot);
      return;
    }

    // 拼接上级路径
    const parentPath = parts.join('/');

    // 直接加载上级路径（已经通过前面的检查确保不会超出根目录）
    loadDirectory(parentPath);
  };

  const handleDoubleClick = (item: FileItem) => {
    openFile(item);
  };

  const syncSystemClipboard = async () => {
    try {
      const systemClipboard = await invoke<SystemFileClipboard | null>('get_file_clipboard');
      const hasSystemFiles = Boolean(systemClipboard?.paths?.length);
      setCanPasteFiles(hasSystemFiles || Boolean(clipboardItem));
      return systemClipboard;
    } catch (error) {
      setCanPasteFiles(Boolean(clipboardItem));
      return null;
    }
  };

  const handleClipboardAction = async (item: FileItem, mode: ClipboardMode) => {
    setClipboardItem({ item, mode });
    setCanPasteFiles(true);

    try {
      await invoke('set_file_clipboard', {
        paths: [item.path],
        operation: mode,
      });
    } catch (error) {
      console.error('写入系统文件剪贴板失败:', error);
    }

    setContextMenu(null);
  };

  const handleContextMenu = (e: React.MouseEvent, item?: FileItem) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, item });
    void syncSystemClipboard();
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

  const getTargetDirectory = (item?: FileItem) => {
    if (item?.type === 'folder') {
      return item.path;
    }
    return currentPath || rootPath || '.';
  };

  const buildPastePath = (targetDirectory: string, item: FileItem) => {
    const directory = targetDirectory.replace(/\\/g, '/').replace(/\/$/, '');
    const existingNames = new Set(filteredItems.map((existingItem) => existingItem.name));
    const joinPath = (name: string) => directory && directory !== '.' ? `${directory}/${name}` : name;

    if (!existingNames.has(item.name)) {
      return joinPath(item.name);
    }

    const dotIndex = item.type === 'file' ? item.name.lastIndexOf('.') : -1;
    const baseName = dotIndex > 0 ? item.name.slice(0, dotIndex) : item.name;
    const extension = dotIndex > 0 ? item.name.slice(dotIndex) : '';

    for (let index = 1; index < 1000; index++) {
      const suffix = index === 1 ? ' - 副本' : ` - 副本 ${index}`;
      const candidateName = `${baseName}${suffix}${extension}`;
      if (!existingNames.has(candidateName)) {
        return joinPath(candidateName);
      }
    }

    return joinPath(`${baseName} - 副本 ${Date.now()}${extension}`);
  };

  const handlePaste = async (targetItem?: FileItem) => {
    const targetDirectory = getTargetDirectory(targetItem);

    try {
      const systemClipboard = await invoke<SystemFileClipboard | null>('get_file_clipboard');
      if (systemClipboard?.paths?.length) {
        await invoke<string[]>('paste_file_clipboard', { targetDirectory });
        await refreshDirectory();

        if (systemClipboard.operation === 'cut') {
          setClipboardItem(null);
          setCanPasteFiles(false);
        } else {
          setCanPasteFiles(true);
        }

        setContextMenu(null);
        return;
      }
    } catch (error) {
      console.error('系统文件剪贴板粘贴失败:', error);
    }

    if (!clipboardItem) {
      setCanPasteFiles(false);
      setContextMenu(null);
      return;
    }

    const targetPath = buildPastePath(targetDirectory, clipboardItem.item);

    if (clipboardItem.mode === 'copy') {
      await copyItem(clipboardItem.item.path, targetPath);
      setCanPasteFiles(true);
    } else {
      await moveItem(clipboardItem.item.path, targetPath);
      setClipboardItem(null);
      setCanPasteFiles(false);
    }
    setContextMenu(null);
  };

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
          title={t('fileManager.goUp')}
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
          title={t('fileManager.newFile')}
        >
          <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 13h6m-3-3v6m5 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
        </button>
        <button
          onClick={() => setNewItemType('folder')}
          className="p-1.5 hover:bg-spore-accent rounded-lg transition-colors"
          title={t('fileManager.newFolder')}
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
              placeholder={t(newItemType === 'file' ? 'fileManager.newFilePlaceholder' : 'fileManager.newFolderPlaceholder')}
              className="flex-1 bg-spore-bg border border-spore-border/50 rounded-lg px-3 py-2 text-xs focus:border-spore-highlight/50 focus:outline-none"
              autoFocus
            />
            <button
              onClick={handleCreate}
              className="px-3 py-2 bg-spore-highlight hover:bg-spore-highlight-hover text-white rounded-lg text-xs font-medium transition-colors"
            >
              {t('fileManager.create')}
            </button>
            <button
              onClick={() => { setNewItemType(null); setNewItemName(''); }}
              className="px-3 py-2 bg-spore-accent hover:bg-spore-border rounded-lg text-xs transition-colors"
            >
              {t('common.cancel')}
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
              {t('common.loading')}
            </div>
          </div>
        ) : items.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-spore-muted">
            <svg className="w-12 h-12 mb-2 opacity-30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
            </svg>
            <span className="text-sm">{t('fileManager.emptyDir')}</span>
          </div>
        ) : (
          <div className="space-y-1">
            {filteredItems.map((item) => (
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
                  onClick={() => handleClipboardAction(contextMenu.item!, 'copy')}
                  className="w-full px-4 py-2 text-left text-sm hover:bg-spore-accent/50 flex items-center gap-2 transition-colors"
                >
                  <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                  {t('common.copy')}
                </button>
                <button
                  onClick={() => handleClipboardAction(contextMenu.item!, 'cut')}
                  className="w-full px-4 py-2 text-left text-sm hover:bg-spore-accent/50 flex items-center gap-2 transition-colors"
                >
                  <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.121 14.121L19 19m-7-7l7-7M5 19l4.879-4.879M12 12L5 5m7 7l-2.121 2.121M12 12l2.121 2.121" />
                  </svg>
                  {t('fileManager.cut')}
                </button>
                {(canPasteFiles || clipboardItem) && contextMenu.item!.type === 'folder' && (
                  <button
                    onClick={() => handlePaste(contextMenu.item)}
                    className="w-full px-4 py-2 text-left text-sm hover:bg-spore-accent/50 flex items-center gap-2 transition-colors"
                  >
                    <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
                    </svg>
                    {t('fileManager.pasteToFolder')}
                  </button>
                )}
                <button
                  onClick={() => {
                    openLocation(contextMenu.item!.path);
                    setContextMenu(null);
                  }}
                  className="w-full px-4 py-2 text-left text-sm hover:bg-spore-accent/50 flex items-center gap-2 transition-colors"
                >
                  <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                  </svg>
                  {t('fileManager.openLocation')}
                </button>
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
                  {t('common.rename')}
                </button>
                <button
                  onClick={() => {
                    if (confirm(t('fileManager.deleteConfirm', { name: contextMenu.item!.name }))) {
                      deleteItem(contextMenu.item!.path);
                    }
                    setContextMenu(null);
                  }}
                  className="w-full px-4 py-2 text-left text-sm hover:bg-spore-error/20 text-spore-error flex items-center gap-2 transition-colors"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                  {t('common.delete')}
                </button>
              </>
            )}
            {(canPasteFiles || clipboardItem) && (
              <button
                onClick={() => handlePaste()}
                className="w-full px-4 py-2 text-left text-sm hover:bg-spore-accent/50 flex items-center gap-2 transition-colors"
              >
                <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
                </svg>
                {t('fileManager.pasteToCurrent')}
              </button>
            )}
            <button
              onClick={() => { setNewItemType('file'); setContextMenu(null); }}
              className="w-full px-4 py-2 text-left text-sm hover:bg-spore-accent/50 flex items-center gap-2 transition-colors"
            >
              <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 13h6m-3-3v6m5 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              {t('fileManager.newFile')}
            </button>
            <button
              onClick={() => { setNewItemType('folder'); setContextMenu(null); }}
              className="w-full px-4 py-2 text-left text-sm hover:bg-spore-accent/50 flex items-center gap-2 transition-colors"
            >
              <svg className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 13h6m-3-3v6m-9 1V7a2 2 0 012-2h6l2 2h6a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
              </svg>
              {t('fileManager.newFolder')}
            </button>
          </div>
        </>
      )}
    </div>
  );
};

