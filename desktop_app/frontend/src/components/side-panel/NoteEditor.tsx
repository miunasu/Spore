/**
 * Note 编辑器组件 - 编辑根目录的 note.txt
 * 支持 Note / Todo 双视图，通过 ======TODO======== 分隔符区分。
 * Todo 条目格式：`[ ] text`（待办）/ `[x] text`（已完成）
 */
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { filesApi } from '../../services/api';
import { useT } from '../../i18n';

const NOTE_PATH = 'note.txt';
export const TODO_SEPARATOR = '======TODO========';
const DELETE_ANIMATION_MS = 220;
const UNDO_TIMEOUT_MS = 5000;
const TODO_DRAG_HOLD_MS = 220;
const TODO_DRAG_MOVE_TOLERANCE = 6;

// ─── 数据模型 ────────────────────────────────────────────────────────────────

interface TodoEntry {
  id: string;
  text: string;
  done: boolean;
}

interface PendingDeletion {
  item: TodoEntry;
  index: number;
  phase: 'staged' | 'exiting' | 'undoable';
}

interface NoteEditorProps {
  active?: boolean;
}

type ViewMode = 'note' | 'todo';
type TodoDropPosition = 'before' | 'after';

function genId(): string {
  return Math.random().toString(36).slice(2, 10);
}

// ─── 序列化 / 反序列化 ────────────────────────────────────────────────────────

function parseContent(raw: string): { noteText: string; todos: TodoEntry[] } {
  const separatorPattern = new RegExp(`^${TODO_SEPARATOR}$`, 'gm');
  const separatorMatches = [...raw.matchAll(separatorPattern)];

  // 从后向前寻找后续内容全部符合 Todo 标记的分隔行，避免误拆笔记中的同名文本。
  for (let i = separatorMatches.length - 1; i >= 0; i -= 1) {
    const match = separatorMatches[i];
    const separatorIndex = match.index ?? -1;
    if (separatorIndex < 0) continue;

    const sectionStart = separatorIndex + TODO_SEPARATOR.length;
    const todoSection = raw.slice(sectionStart).replace(/^\r?\n/, '');
    const todoLines = todoSection.split(/\r?\n/).filter((line) => line.trim() !== '');
    if (todoLines.length === 0 || todoLines.some((line) => !/^\[(?: |x|X)\] /.test(line))) {
      continue;
    }

    const todos = todoLines.map((line) => ({
      id: genId(),
      text: line.slice(4),
      done: line.startsWith('[x] ') || line.startsWith('[X] '),
    }));
    const noteEnd = raw.slice(0, separatorIndex).endsWith('\r\n')
      ? separatorIndex - 2
      : raw.slice(0, separatorIndex).endsWith('\n')
        ? separatorIndex - 1
        : separatorIndex;
    return { noteText: raw.slice(0, noteEnd), todos };
  }

  return { noteText: raw, todos: [] };
}

function serializeContent(noteText: string, todos: TodoEntry[]): string {
  if (todos.length === 0) return noteText;
  const todoLines = todos.map((t) => `${t.done ? '[x]' : '[ ]'} ${t.text}`).join('\n');
  return `${noteText}\n${TODO_SEPARATOR}\n${todoLines}`;
}

function applyEditingDraft(
  todos: TodoEntry[],
  editingId: string | null,
  editingText: string,
): TodoEntry[] {
  if (editingId === null) return todos;
  const text = editingText.trim();
  if (!text) return todos.filter((item) => item.id !== editingId);
  return todos.map((item) => (item.id === editingId ? { ...item, text } : item));
}

// ─── 组件 ─────────────────────────────────────────────────────────────────────

export const NoteEditor: React.FC<NoteEditorProps> = ({ active = true }) => {
  const t = useT();

  const [view, setView] = useState<ViewMode>('note');
  const [noteText, setNoteText] = useState('');
  const [todos, setTodos] = useState<TodoEntry[]>([]);
  const [savedContent, setSavedContent] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const [hideCompleted, setHideCompleted] = useState(false);

  // Todo 长按拖拽排序
  const [draggedTodoId, setDraggedTodoId] = useState<string | null>(null);
  const [dropTarget, setDropTarget] = useState<{ id: string; position: TodoDropPosition } | null>(null);
  const draggedTodoIdRef = useRef<string | null>(null);
  const dropTargetRef = useRef<{ id: string; position: TodoDropPosition } | null>(null);
  const dragPressTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const dragClickResetTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const dragPointerIdRef = useRef<number | null>(null);
  const dragStartPointRef = useRef<{ x: number; y: number } | null>(null);
  const dragSourceElementRef = useRef<HTMLDivElement | null>(null);
  const suppressTodoClickRef = useRef(false);

  // 新增 todo 输入
  const [newTodoText, setNewTodoText] = useState('');
  const [enteringId, setEnteringId] = useState<string | null>(null);
  const newTodoRef = useRef<HTMLInputElement>(null);
  const undoButtonRef = useRef<HTMLButtonElement>(null);

  // 行内编辑
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingText, setEditingText] = useState('');
  const editRef = useRef<HTMLInputElement>(null);

  // 删除动画 + 撤销
  const [pendingDeletion, setPendingDeletion] = useState<PendingDeletion | null>(null);
  const deleteAnimationTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const undoTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const effectiveTodos = applyEditingDraft(todos, editingId, editingText);
  const currentContent = serializeContent(noteText, effectiveTodos);
  const hasChanges = currentContent !== savedContent;

  const clearDeletionTimers = useCallback(() => {
    if (deleteAnimationTimerRef.current) {
      clearTimeout(deleteAnimationTimerRef.current);
      deleteAnimationTimerRef.current = null;
    }
    if (undoTimerRef.current) {
      clearTimeout(undoTimerRef.current);
      undoTimerRef.current = null;
    }
  }, []);

  useEffect(() => clearDeletionTimers, [clearDeletionTimers]);

  useEffect(() => () => {
    if (dragPressTimerRef.current) clearTimeout(dragPressTimerRef.current);
    if (dragClickResetTimerRef.current) clearTimeout(dragClickResetTimerRef.current);
  }, []);

  // ── 加载 ───────────────────────────────────────────────────────────────────

  const loadNote = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    clearDeletionTimers();
    setPendingDeletion(null);
    setEditingId(null);
    setEditingText('');
    try {
      const response = await filesApi.read(NOTE_PATH);
      const parsed = parseContent(response.content);
      setNoteText(parsed.noteText);
      setTodos(parsed.todos);
      setSavedContent(serializeContent(parsed.noteText, parsed.todos));
    } catch (err) {
      if ((err as any)?.status === 404) {
        setNoteText('');
        setTodos([]);
        setSavedContent('');
      } else {
        setError(t('noteEditor.loadFailed'));
        setAnnouncement(t('noteEditor.loadFailed'));
      }
    } finally {
      setIsLoading(false);
    }
  }, [clearDeletionTimers]);

  useEffect(() => {
    loadNote();
  }, [loadNote]);

  // ── 保存 ───────────────────────────────────────────────────────────────────

  const saveNote = useCallback(async () => {
    if (isSaving) return;

    const todosSnapshot = applyEditingDraft(todos, editingId, editingText);
    const contentSnapshot = serializeContent(noteText, todosSnapshot);

    setTodos(todosSnapshot);
    setEditingId(null);
    setEditingText('');
    setIsSaving(true);
    setError(null);
    try {
      await filesApi.write(NOTE_PATH, contentSnapshot);
      setSavedContent(contentSnapshot);
    } catch {
      setError(t('noteEditor.saveFailed'));
      setAnnouncement(t('noteEditor.saveFailed'));
    } finally {
      setIsSaving(false);
    }
  }, [editingId, editingText, isSaving, noteText, todos]);

  const handleRefresh = () => {
    if (isSaving) return;
    if (hasChanges && !window.confirm(t('noteEditor.discardChanges'))) return;
    loadNote();
  };

  // Ctrl+S
  useEffect(() => {
    if (!active) return;
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
        e.preventDefault();
        if (hasChanges && !isSaving) saveNote();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [active, hasChanges, isSaving, saveNote]);

  // 编辑框 auto-focus
  useEffect(() => {
    if (editingId && editRef.current) {
      editRef.current.focus();
      editRef.current.select();
    }
  }, [editingId]);

  useEffect(() => {
    if (!enteringId) return;
    const timer = setTimeout(() => setEnteringId(null), 300);
    return () => clearTimeout(timer);
  }, [enteringId]);

  // ── Note 操作 ──────────────────────────────────────────────────────────────

  const handleNoteChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setNoteText(e.target.value);
  };

  // ── Todo 操作 ─────────────────────────────────────────────────────────────

  const toggleTodo = (id: string) => {
    setTodos((prev) => prev.map((item) => (item.id === id ? { ...item, done: !item.done } : item)));
  };

  const clearTodoDragTimer = () => {
    if (dragPressTimerRef.current) {
      clearTimeout(dragPressTimerRef.current);
      dragPressTimerRef.current = null;
    }
  };

  const clearTodoDrag = () => {
    clearTodoDragTimer();
    draggedTodoIdRef.current = null;
    dropTargetRef.current = null;
    dragPointerIdRef.current = null;
    dragStartPointRef.current = null;
    dragSourceElementRef.current = null;
    setDraggedTodoId(null);
    setDropTarget(null);
  };

  const reorderTodo = (sourceId: string, targetId: string, position: TodoDropPosition) => {
    const movedItem = todos.find((item) => item.id === sourceId);
    if (!movedItem || sourceId === targetId) return;

    setTodos((prev) => {
      const sourceIndex = prev.findIndex((item) => item.id === sourceId);
      if (sourceIndex === -1) return prev;

      const reordered = [...prev];
      const [sourceItem] = reordered.splice(sourceIndex, 1);
      const targetIndex = reordered.findIndex((item) => item.id === targetId);
      if (targetIndex === -1) return prev;
      reordered.splice(position === 'after' ? targetIndex + 1 : targetIndex, 0, sourceItem);
      return reordered;
    });
    setAnnouncement(t('noteEditor.todoReordered', { text: movedItem.text }));
  };

  const handleTodoPointerDown = (event: React.PointerEvent<HTMLDivElement>, id: string) => {
    const dragBlocked = editingId !== null
      || pendingDeletion?.phase === 'staged'
      || pendingDeletion?.phase === 'exiting';
    if (event.button !== 0 || dragBlocked) return;

    clearTodoDragTimer();
    const pointerId = event.pointerId;
    const sourceElement = event.currentTarget;
    dragPointerIdRef.current = pointerId;
    dragStartPointRef.current = { x: event.clientX, y: event.clientY };
    dragSourceElementRef.current = sourceElement;

    dragPressTimerRef.current = setTimeout(() => {
      if (dragPointerIdRef.current !== pointerId) return;
      draggedTodoIdRef.current = id;
      suppressTodoClickRef.current = true;
      setDraggedTodoId(id);
      setAnnouncement(t('noteEditor.todoDragStarted', { text: todos.find((item) => item.id === id)?.text ?? '' }));
      try {
        sourceElement.setPointerCapture?.(pointerId);
      } catch {
        // Pointer may already have been released by the WebView.
      }
      dragPressTimerRef.current = null;
    }, TODO_DRAG_HOLD_MS);
  };

  const handleTodoPointerMove = (event: React.PointerEvent<HTMLDivElement>) => {
    if (dragPointerIdRef.current !== event.pointerId) return;

    const sourceId = draggedTodoIdRef.current;
    if (!sourceId) {
      const start = dragStartPointRef.current;
      if (
        start
        && Math.hypot(event.clientX - start.x, event.clientY - start.y) > TODO_DRAG_MOVE_TOLERANCE
      ) {
        clearTodoDragTimer();
        dragPointerIdRef.current = null;
        dragStartPointRef.current = null;
        dragSourceElementRef.current = null;
      }
      return;
    }

    event.preventDefault();
    const rows = Array.from(document.querySelectorAll<HTMLElement>('[data-todo-id]'));
    const targetRow = rows.find((row) => {
      const rect = row.getBoundingClientRect();
      return event.clientY >= rect.top && event.clientY <= rect.bottom;
    });
    const targetId = targetRow?.dataset.todoId;
    if (!targetRow || !targetId || targetId === sourceId) {
      dropTargetRef.current = null;
      setDropTarget(null);
      return;
    }

    const rect = targetRow.getBoundingClientRect();
    const nextTarget = {
      id: targetId,
      position: (event.clientY < rect.top + rect.height / 2 ? 'before' : 'after') as TodoDropPosition,
    };
    dropTargetRef.current = nextTarget;
    setDropTarget((current) =>
      current?.id === nextTarget.id && current.position === nextTarget.position
        ? current
        : nextTarget,
    );
  };

  const finishTodoPointerDrag = (event: React.PointerEvent<HTMLDivElement>, shouldReorder: boolean) => {
    if (dragPointerIdRef.current !== event.pointerId) return;

    const sourceId = draggedTodoIdRef.current;
    const target = dropTargetRef.current;
    clearTodoDragTimer();
    if (sourceId && shouldReorder && target) {
      reorderTodo(sourceId, target.id, target.position);
    }

    try {
      if (event.currentTarget.hasPointerCapture?.(event.pointerId)) {
        event.currentTarget.releasePointerCapture?.(event.pointerId);
      }
    } catch {
      // Ignore WebView pointer-capture races.
    }
    clearTodoDrag();

    if (sourceId) {
      if (dragClickResetTimerRef.current) clearTimeout(dragClickResetTimerRef.current);
      dragClickResetTimerRef.current = setTimeout(() => {
        suppressTodoClickRef.current = false;
        dragClickResetTimerRef.current = null;
      }, 0);
    }
  };

  const handleTodoPointerLeave = (event: React.PointerEvent<HTMLDivElement>) => {
    if (dragPointerIdRef.current !== event.pointerId || draggedTodoIdRef.current) return;
    clearTodoDrag();
  };

  const handleTodoClickCapture = (event: React.MouseEvent<HTMLDivElement>) => {
    if (!suppressTodoClickRef.current) return;
    event.preventDefault();
    event.stopPropagation();
  };

  const deleteTodo = (id: string) => {
    if (pendingDeletion?.phase === 'staged' || pendingDeletion?.phase === 'exiting') return;

    const index = todos.findIndex((item) => item.id === id);
    if (index === -1) return;
    const item = todos[index];

    clearDeletionTimers();
    if (editingId === id) {
      setEditingId(null);
      setEditingText('');
    }
    setTodos((prev) => prev.filter((todo) => todo.id !== id));
    setPendingDeletion({ item, index, phase: 'staged' });
    setAnnouncement(t('noteEditor.todoDeleted', { text: item.text }));

    // 先渲染完整高度，再下一帧触发收拢，确保 CSS transition 生效。
    requestAnimationFrame(() => {
      setPendingDeletion((current) => {
        if (!current || current.item.id !== id) return current;
        return { ...current, phase: 'exiting' };
      });
      deleteAnimationTimerRef.current = setTimeout(() => {
        setPendingDeletion((current) => {
          if (!current || current.item.id !== id) return current;
          return { ...current, phase: 'undoable' };
        });
        deleteAnimationTimerRef.current = null;
        requestAnimationFrame(() => undoButtonRef.current?.focus());
        undoTimerRef.current = setTimeout(() => {
          setPendingDeletion((current) =>
            current?.item.id === id ? null : current,
          );
          undoTimerRef.current = null;
        }, UNDO_TIMEOUT_MS);
      }, DELETE_ANIMATION_MS);
    });
  };

  const undoDelete = () => {
    if (!pendingDeletion) return;
    const { item, index } = pendingDeletion;
    clearDeletionTimers();
    setTodos((prev) => {
      const restored = [...prev];
      restored.splice(Math.min(index, restored.length), 0, item);
      return restored;
    });
    setEnteringId(item.id);
    setPendingDeletion(null);
    setAnnouncement(t('noteEditor.todoRestored', { text: item.text }));
    requestAnimationFrame(() => newTodoRef.current?.focus());
  };

  const addTodo = (e?: React.FormEvent) => {
    e?.preventDefault();
    const text = newTodoText.trim();
    if (!text) return;
    const item = { id: genId(), text, done: false };
    setTodos((prev) => [...prev, item]);
    setNewTodoText('');
    setEnteringId(item.id);
    setAnnouncement(t('noteEditor.todoAdded', { text }));
    newTodoRef.current?.focus();
  };

  const startEdit = (item: TodoEntry) => {
    setEditingId(item.id);
    setEditingText(item.text);
  };

  const commitEdit = () => {
    if (editingId === null) return;
    const id = editingId;
    const text = editingText.trim();
    setEditingId(null);
    setEditingText('');
    if (!text) {
      deleteTodo(id);
      return;
    }
    setTodos((prev) => prev.map((item) => (item.id === id ? { ...item, text } : item)));
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditingText('');
  };

  // ── 统计 / 展示条目 ─────────────────────────────────────────────────────────

  const doneCount = effectiveTodos.filter((item) => item.done).length;
  const pendingCount = effectiveTodos.length - doneCount;
  const visibleTodos = todos.filter((item) => !hideCompleted || !item.done);
  if (
    (pendingDeletion?.phase === 'staged' || pendingDeletion?.phase === 'exiting')
    && (!hideCompleted || !pendingDeletion.item.done)
  ) {
    const deletionVisibleIndex = todos
      .slice(0, pendingDeletion.index)
      .filter((item) => !hideCompleted || !item.done)
      .length;
    visibleTodos.splice(deletionVisibleIndex, 0, pendingDeletion.item);
  }

  // ── Loading ────────────────────────────────────────────────────────────────

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="flex items-center gap-2 text-spore-muted text-sm">
          <svg aria-hidden="true" className="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          {t('common.loading')}
        </div>
      </div>
    );
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  const focusRing = 'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-spore-highlight/70';
  const handleViewTabKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    let nextView: ViewMode | null = null;
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      nextView = view === 'note' ? 'todo' : 'note';
    } else if (e.key === 'Home') {
      nextView = 'note';
    } else if (e.key === 'End') {
      nextView = 'todo';
    }
    if (!nextView) return;
    e.preventDefault();
    setView(nextView);
    requestAnimationFrame(() => document.getElementById(`${nextView}-view-tab`)?.focus());
  };

  return (
    <div className="h-full flex flex-col">
      <span className="sr-only" aria-live="polite">{announcement}</span>

      {/* ── 工具栏 ── */}
      <div className="flex items-center justify-between gap-2 px-3 py-2 border-b border-spore-border/30">
        <div className="flex items-center gap-2 min-w-0">
          <div role="tablist" aria-label={t('noteEditor.viewTabsLabel')} className="flex items-center bg-spore-accent/40 rounded-lg p-0.5 gap-0.5 flex-shrink-0">
            <button
              type="button"
              role="tab"
              id="note-view-tab"
              aria-controls="note-view-panel"
              aria-selected={view === 'note'}
              tabIndex={view === 'note' ? 0 : -1}
              onClick={() => setView('note')}
              onKeyDown={handleViewTabKeyDown}
              className={`flex items-center gap-1 px-2 py-1 text-xs rounded-md transition-all duration-200 motion-reduce:transition-none ${focusRing} ${
                view === 'note'
                  ? 'bg-spore-card text-spore-highlight shadow-sm'
                  : 'text-spore-muted hover:text-spore-text'
              }`}
            >
              <svg aria-hidden="true" className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
              </svg>
              {t('noteEditor.viewNote')}
            </button>
            <button
              type="button"
              role="tab"
              id="todo-view-tab"
              aria-controls="todo-view-panel"
              aria-selected={view === 'todo'}
              tabIndex={view === 'todo' ? 0 : -1}
              onClick={() => setView('todo')}
              onKeyDown={handleViewTabKeyDown}
              className={`flex items-center gap-1 px-2 py-1 text-xs rounded-md transition-all duration-200 motion-reduce:transition-none ${focusRing} ${
                view === 'todo'
                  ? 'bg-spore-card text-spore-highlight shadow-sm'
                  : 'text-spore-muted hover:text-spore-text'
              }`}
            >
              <svg aria-hidden="true" className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
              </svg>
              {t('noteEditor.viewTodo')}
              {pendingCount > 0 && (
                <span className="bg-spore-highlight text-white text-[10px] px-1 min-w-[14px] text-center rounded-full leading-[14px]">
                  {pendingCount}
                </span>
              )}
            </button>
          </div>

          <div className="flex items-center gap-1 text-xs text-spore-muted min-w-0">
            <span className="truncate">note.txt</span>
            {hasChanges && <span className="text-spore-warning" title={t('noteEditor.unsavedChanges')}>●</span>}
          </div>
        </div>

        <div className="flex items-center gap-1.5 flex-shrink-0">
          {error && <span className="text-xs text-spore-error max-w-24 truncate" title={error}>{error}</span>}
          <button
            type="button"
            onClick={saveNote}
            disabled={!hasChanges || isSaving}
            className={`px-2.5 py-1 text-xs rounded-lg transition-colors duration-200 motion-reduce:transition-none ${focusRing} ${
              hasChanges && !isSaving
                ? 'bg-spore-highlight hover:bg-spore-highlight-hover text-white'
                : 'bg-spore-accent/30 text-spore-muted cursor-not-allowed'
            }`}
          >
            {isSaving ? t('noteEditor.saving') : t('common.save')}
          </button>
          <button
            type="button"
            onClick={handleRefresh}
            disabled={isSaving}
            aria-label={t('common.refresh')}
            title={t('common.refresh')}
            className={`p-1.5 hover:bg-spore-accent rounded-lg transition-colors duration-200 motion-reduce:transition-none disabled:opacity-40 ${focusRing}`}
          >
            <svg aria-hidden="true" className="w-4 h-4 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
        </div>
      </div>

      {/* ── 内容 ── */}
      <div className="flex-1 overflow-hidden">
        <div
          id="note-view-panel"
          role="tabpanel"
          aria-labelledby="note-view-tab"
          hidden={view !== 'note'}
          className="h-full p-2"
        >
          <textarea
            value={noteText}
            onChange={handleNoteChange}
            placeholder={t('noteEditor.placeholder')}
            className={`w-full h-full bg-spore-bg/50 border border-spore-border/30 rounded-lg p-3 text-sm text-spore-text resize-none focus:border-spore-highlight/50 font-mono ${focusRing}`}
            spellCheck={false}
          />
        </div>

        <div
          id="todo-view-panel"
          role="tabpanel"
          aria-labelledby="todo-view-tab"
          hidden={view !== 'todo'}
          className="h-full flex flex-col overflow-hidden"
        >
          {effectiveTodos.length > 0 && (
            <div className="flex items-center gap-2 px-3 py-1.5 border-b border-spore-border/20 animate-fade-in motion-reduce:animate-none">
              <div
                role="progressbar"
                aria-label={t('noteEditor.todoProgress')}
                aria-valuemin={0}
                aria-valuemax={effectiveTodos.length}
                aria-valuenow={doneCount}
                className="flex-1 h-1 bg-spore-border/30 rounded-full overflow-hidden"
              >
                <div
                  className="h-full bg-spore-highlight/70 transition-[width] duration-300 ease-out motion-reduce:transition-none"
                  style={{ width: `${effectiveTodos.length ? (doneCount / effectiveTodos.length) * 100 : 0}%` }}
                />
              </div>
              <span className="text-xs text-spore-muted flex-shrink-0">
                {t('noteEditor.todoStats', { done: doneCount, total: effectiveTodos.length })}
              </span>
              <button
                type="button"
                aria-pressed={hideCompleted}
                disabled={doneCount === 0}
                onClick={() => setHideCompleted((hidden) => !hidden)}
                title={t(hideCompleted ? 'noteEditor.todoShowCompleted' : 'noteEditor.todoHideCompleted')}
                className={`flex items-center gap-1 flex-shrink-0 px-1.5 py-0.5 rounded text-xs transition-colors duration-200 motion-reduce:transition-none ${focusRing} ${
                  doneCount > 0
                    ? 'text-spore-muted hover:text-spore-text hover:bg-spore-accent/40'
                    : 'text-spore-muted/30 cursor-not-allowed'
                }`}
              >
                <svg aria-hidden="true" className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  {hideCompleted ? (
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 3l18 18M10.6 10.7a2 2 0 002.7 2.7M9.9 4.2A10.8 10.8 0 0112 4c5.5 0 9 5 9 5a16.2 16.2 0 01-2.1 2.5M6.6 6.6C4.4 8.1 3 10 3 10s3.5 5 9 5c1 0 1.9-.2 2.7-.5" />
                  ) : (
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10s3.5-5 9-5 9 5 9 5-3.5 5-9 5-9-5-9-5zm9 2a2 2 0 100-4 2 2 0 000 4z" />
                  )}
                </svg>
                {t(hideCompleted ? 'noteEditor.todoShowCompleted' : 'noteEditor.todoHideCompleted')}
              </button>
            </div>
          )}

          <div className="flex-1 overflow-y-auto py-1">
            {visibleTodos.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full text-spore-muted gap-2 pt-8 animate-fade-in motion-reduce:animate-none">
                <svg aria-hidden="true" className="w-10 h-10 opacity-20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
                <span className="text-sm opacity-40">
                  {hideCompleted && todos.length > 0
                    ? t('noteEditor.todoCompletedHidden')
                    : t('noteEditor.todoEmpty')}
                </span>
              </div>
            )}

            {visibleTodos.map((item) => {
              const isDeleting = (pendingDeletion?.phase === 'staged' || pendingDeletion?.phase === 'exiting') && pendingDeletion.item.id === item.id;
              const isExiting = pendingDeletion?.phase === 'exiting' && pendingDeletion.item.id === item.id;
              return (
                <div
                  key={item.id}
                  data-todo-id={item.id}
                  onPointerDown={(event) => handleTodoPointerDown(event, item.id)}
                  onPointerMove={handleTodoPointerMove}
                  onPointerUp={(event) => finishTodoPointerDrag(event, true)}
                  onPointerCancel={(event) => finishTodoPointerDrag(event, false)}
                  onPointerLeave={handleTodoPointerLeave}
                  onClickCapture={handleTodoClickCapture}
                  className={`group select-none overflow-hidden border-spore-highlight transition-[max-height,opacity,transform,margin,border-color] duration-200 ease-out motion-reduce:transition-none motion-reduce:transform-none ${
                    isExiting
                      ? 'max-h-0 opacity-0 -translate-y-1 my-0 pointer-events-none'
                      : 'max-h-20 opacity-100 translate-y-0 my-0.5'
                  } ${enteringId === item.id ? 'animate-fade-in motion-reduce:animate-none' : ''} ${
                    dropTarget?.id === item.id
                      ? dropTarget.position === 'before'
                        ? 'border-t-2'
                        : 'border-b-2'
                      : 'border-y-0'
                  }`}
                >
                  <div
                    title={t('noteEditor.todoDragHint')}
                    className={`flex items-center gap-2 mx-2 px-2 py-1.5 rounded-lg transition-[background-color,opacity,box-shadow] duration-200 hover:bg-spore-accent/20 motion-reduce:transition-none ${item.done ? 'opacity-50' : ''} ${
                      draggedTodoId === item.id
                        ? 'opacity-40 shadow-glow cursor-grabbing'
                        : 'cursor-grab'
                    }`}
                  >
                    <button
                      type="button"
                      role="checkbox"
                      aria-checked={item.done}
                      aria-label={t(item.done ? 'noteEditor.todoToggleIncomplete' : 'noteEditor.todoToggleComplete', { text: item.text })}
                      onClick={() => toggleTodo(item.id)}
                      disabled={isDeleting}
                      className={`flex-shrink-0 w-4 h-4 rounded border-[1.5px] transition-all duration-200 flex items-center justify-center motion-reduce:transition-none ${focusRing} ${
                        item.done
                          ? 'bg-spore-highlight border-spore-highlight scale-100'
                          : 'border-spore-border/60 hover:border-spore-highlight/60'
                      }`}
                    >
                      {item.done && (
                        <svg aria-hidden="true" className="w-2.5 h-2.5 text-white animate-fade-in motion-reduce:animate-none" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                        </svg>
                      )}
                    </button>

                    {editingId === item.id ? (
                      <input
                        ref={editRef}
                        value={editingText}
                        aria-label={t('noteEditor.todoEditLabel', { text: item.text })}
                        onChange={(e) => setEditingText(e.target.value)}
                        onBlur={commitEdit}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') commitEdit();
                          if (e.key === 'Escape') cancelEdit();
                        }}
                        className={`flex-1 min-w-0 bg-transparent text-sm text-spore-text border-b border-spore-highlight/50 py-0.5 ${focusRing}`}
                      />
                    ) : (
                      <button
                        type="button"
                        onDoubleClick={() => startEdit(item)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === 'F2') {
                            e.preventDefault();
                            startEdit(item);
                          }
                        }}
                        className={`flex-1 min-w-0 text-left text-sm text-spore-text truncate rounded-sm transition-[opacity,text-decoration-color] duration-200 motion-reduce:transition-none ${focusRing} ${
                          item.done ? 'line-through decoration-spore-muted/70' : ''
                        }`}
                        title={t('noteEditor.todoEditHint')}
                      >
                        {item.text}
                      </button>
                    )}

                    <button
                      type="button"
                      onClick={() => deleteTodo(item.id)}
                      disabled={isDeleting || pendingDeletion?.phase === 'staged' || pendingDeletion?.phase === 'exiting'}
                      aria-label={t('noteEditor.todoDeleteLabel', { text: item.text })}
                      title={t('common.delete')}
                      className={`flex-shrink-0 opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 focus-visible:opacity-100 p-0.5 rounded text-spore-muted hover:text-spore-error transition-all duration-200 motion-reduce:transition-none ${focusRing}`}
                    >
                      <svg aria-hidden="true" className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          {pendingDeletion?.phase === 'undoable' && (
            <div className="mx-3 mb-1.5 flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-spore-card border border-spore-border/40 shadow-card animate-slide-up motion-reduce:animate-none">
              <svg aria-hidden="true" className="w-3.5 h-3.5 flex-shrink-0 text-spore-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 6h18M8 6V4h8v2m-9 0 1 14h8l1-14M10 10v6m4-6v6" />
              </svg>
              <span className="flex-1 min-w-0 truncate text-xs text-spore-muted">
                {t('noteEditor.todoDeletedShort')}
              </span>
              <button
                ref={undoButtonRef}
                type="button"
                onClick={undoDelete}
                className={`text-xs font-medium text-spore-highlight hover:text-spore-highlight-hover rounded px-1 py-0.5 transition-colors motion-reduce:transition-none ${focusRing}`}
              >
                {t('noteEditor.todoUndo')}
              </button>
            </div>
          )}

          <form onSubmit={addTodo} className="px-3 py-2 border-t border-spore-border/20">
            <div className="flex items-center gap-2 px-2 py-1.5 rounded-lg bg-spore-accent/20 border border-spore-border/20 focus-within:border-spore-highlight/40 focus-within:shadow-glow transition-[border-color,box-shadow] duration-200 motion-reduce:transition-none">
              <svg aria-hidden="true" className="w-3.5 h-3.5 text-spore-muted/60 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              <input
                ref={newTodoRef}
                value={newTodoText}
                aria-label={t('noteEditor.todoInputLabel')}
                onChange={(e) => setNewTodoText(e.target.value)}
                placeholder={t('noteEditor.todoAddPlaceholder')}
                className={`flex-1 min-w-0 bg-transparent text-sm text-spore-text placeholder:text-spore-muted/40 ${focusRing}`}
              />
              <button
                type="submit"
                disabled={!newTodoText.trim()}
                className={`flex-shrink-0 text-xs transition-all duration-200 font-medium rounded px-1 py-0.5 motion-reduce:transition-none ${focusRing} ${
                  newTodoText.trim()
                    ? 'text-spore-highlight hover:text-spore-highlight-hover opacity-100'
                    : 'text-spore-muted opacity-40 cursor-not-allowed'
                }`}
              >
                {t('noteEditor.todoAdd')}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};
