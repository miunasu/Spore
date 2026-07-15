/**
 * 聊天状态管理 - 多后端实例架构
 * 每个对话对应一个独立的后端实例
 */
import { create } from 'zustand';
import type { Message, Conversation, HistoryFile, WSTaskEvent } from '../types';
import {
  createChatApi,
  createCommandsApi,
  createTaskApi,
  commandsApi,
} from '../services/api';
import { useLogStore } from './logStore';
import { useTodoStore } from './todoStore';

// 前端日志辅助函数
const frontendLog = (message: string) => {
  useLogStore.getState().addFrontendLog(message);
};

const isStopReasonLine = (trimmed: string): boolean =>
  /^@SPORE:STOP_REASON\s*=/.test(trimmed || '');

const isHiddenProtocolLine = (trimmed: string): boolean =>
  isStopReasonLine(trimmed) ||
  [
    '@SPORE:REPLY_START',
    '@SPORE:REPLY_END',
    '@SPORE:CONTENT_START',
    '@SPORE:CONTENT_END',
    '@SPORE:RESULT',
  ].includes(trimmed);


const extractStopReasonContent = (content: string): string | null => {
  if (!content) return null;
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/^[ \t]*@SPORE:STOP_REASON[ \t]*=[ \t]*(.*?)[ \t]*$/);
    if (!match) continue;
    const value = (match[1] || '').trim();
    if (value.startsWith('@SPORE:CONTENT_START')) {
      let body = value.slice('@SPORE:CONTENT_START'.length);
      // same-line end
      const sameEnd = body.indexOf('@SPORE:CONTENT_END');
      if (sameEnd >= 0) {
        return body.slice(0, sameEnd).replace(/^\r?\n/, '').replace(/\s+$/, '');
      }
      const parts: string[] = [];
      if (body) parts.push(body.replace(/^\r?\n/, ''));
      for (let j = i + 1; j < lines.length; j++) {
        const endIdx = lines[j].indexOf('@SPORE:CONTENT_END');
        if (endIdx >= 0) {
          const before = lines[j].slice(0, endIdx);
          if (before) parts.push(before);
          return parts.join('\n').replace(/^\r?\n/, '').replace(/\s+$/, '');
        }
        parts.push(lines[j]);
      }
      return parts.join('\n').trim() || null;
    }
    return value || null;
  }
  return null;
};

// 提取消息的显示内容（处理新协议 @SPORE: 标记）
// 结束轮优先级：有 REPLY 只显示 REPLY；仅有 STOP_REASON 时显示 STOP_REASON
const extractDisplayContent = (content: string): string => {
  if (!content) return '';

  const lines = content.split('\n');
  const replyStart = '@SPORE:REPLY_START';
  const replyEnd = '@SPORE:REPLY_END';

  // 收集所有 REPLY 块（标记必须独占一行，块可出现多次），按顺序拼接展示
  const replySegments: string[] = [];
  let currentSegment: string[] | null = null;
  let hasReplyBlock = false;

  for (const line of lines) {
    const trimmed = line.trim();

    if (currentSegment === null) {
      if (trimmed === replyStart) {
        hasReplyBlock = true;
        currentSegment = [];
      }
      continue;
    }

    if (trimmed === replyEnd || isStopReasonLine(trimmed)) {
      replySegments.push(currentSegment.join('\n').trim());
      currentSegment = null;
      continue;
    }

    if (isHiddenProtocolLine(trimmed)) {
      continue;
    }

    currentSegment.push(line);
  }

  if (currentSegment !== null) {
    replySegments.push(currentSegment.join('\n').trim());
  }

  // 有 REPLY 块时优先只展示 REPLY（同时存在 STOP_REASON 时不显示原因文本）
  if (hasReplyBlock) {
    return replySegments.filter(Boolean).join('\n\n');
  }

  // 无 REPLY 时，展示 STOP_REASON 内容
  const stopReason = extractStopReasonContent(content);
  if (stopReason) {
    return stopReason;
  }

  // 没有 REPLY/STOP_REASON，过滤掉所有协议标记
  const filteredLines: string[] = [];
  let inProtocolBlock = false;

  for (const line of lines) {
    const trimmed = line.trim();

    if (/^@SPORE:(TODO|ACTION_SINGLE|ACTION_SEQUENCE|ACTION_PARALLEL)_START$/.test(trimmed)) {
      inProtocolBlock = true;
      continue;
    }

    if (/^@SPORE:(TODO|ACTION_SINGLE|ACTION_SEQUENCE|ACTION_PARALLEL)_END$/.test(trimmed)) {
      inProtocolBlock = false;
      continue;
    }

    if (isHiddenProtocolLine(trimmed)) {
      if (isStopReasonLine(trimmed)) {
        break;
      }
      continue;
    }

    if (inProtocolBlock) {
      continue;
    }

    filteredLines.push(line);
  }

  return filteredLines.join('\n').trim();
};

// 生成唯一 ID
const generateId = () =>
  `conv_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

const generateSubmissionId = () =>
  `submission_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;

// 从后端拉取会话历史快照并转换为前端 Message 列表
// （切换会话 / 重连恢复 / 手动刷新共用的唯一实现）
interface ActiveTaskIdentity {
  submissionId: string;
  taskId?: string;
}

interface SubmitOutcome {
  submitted: boolean;
  success: boolean;
  taskId?: string;
  error?: string;
}

const activeTasksByConversation: Record<string, ActiveTaskIdentity | undefined> = {};
const pendingSubmits: Record<string, Promise<SubmitOutcome> | undefined> = {};
const interruptBarriers: Record<string, Promise<boolean> | undefined> = {};
const taskStateVersions: Record<string, number> = {};
const discardedSubmissions: Record<string, string[] | undefined> = {};

const bumpTaskStateVersion = (conversationId: string): void => {
  taskStateVersions[conversationId] = (taskStateVersions[conversationId] || 0) + 1;
};

const discardSubmission = (conversationId: string, submissionId?: string): void => {
  if (!submissionId) return;
  const discarded = discardedSubmissions[conversationId] || [];
  if (!discarded.includes(submissionId)) {
    discarded.push(submissionId);
  }
  discardedSubmissions[conversationId] = discarded.slice(-20);
};

const isDiscardedSubmission = (
  conversationId: string,
  submissionId: string
): boolean => discardedSubmissions[conversationId]?.includes(submissionId) === true;

const fetchSessionMessages = async (
  port: number,
  sessionId: string
): Promise<Message[]> => {
  const chatApi = createChatApi(port);
  const historyResponse = await chatApi.history(true, sessionId);

  const allMessages = historyResponse.messages.filter((msg) => (
    msg.role === 'user' || msg.role === 'assistant'
  ));

  return allMessages
    .map((msg, index) => {
      const baseMessage = {
        id: index.toString(),
        role: msg.role as 'user' | 'assistant',
        timestamp: Date.now(),
      };

      if (msg.role === 'assistant') {
        const prevMsg = index > 0 ? allMessages[index - 1] : null;
        const sent_messages = prevMsg ? [{ role: prevMsg.role, content: prevMsg.content }] : [];

        return {
          ...baseMessage,
          content: extractDisplayContent(msg.content),
          sent_messages,
          raw_response: msg.content,
        };
      }

      // 工具结果消息：不在对话中显示
      if (msg.content?.trim().startsWith('@SPORE:RESULT')) {
        return null;
      }

      return {
        ...baseMessage,
        content: msg.content,
      };
    })
    .filter((msg): msg is Message => msg !== null && msg.content.trim() !== '');
};

// 扩展 Conversation 类型，添加后端端口
interface ConversationWithBackend extends Conversation {
  backendPort: number | null; // null 表示使用主后端或尚未分配
  backendStatus: 'none' | 'starting' | 'running' | 'stopped' | 'error';
}

// 创建新对话
const createConversation = (
  name?: string,
  historyFile?: string
): ConversationWithBackend => ({
  id: generateId(),
  name:
    name ||
    `对话 ${new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })}`,
  messages: [],
  createdAt: Date.now(),
  updatedAt: Date.now(),
  historyFile,
  backendPort: null,
  backendStatus: 'none',
});

interface ChatStore {
  // 多对话状态
  conversations: ConversationWithBackend[];
  activeConversationId: string | null;

  // 按对话的生成状态
  generatingConversations: Set<string>;

  // UI 状态
  inputValue: string;
  historyFiles: HistoryFile[];

  // Getters
  activeConversation: () => ConversationWithBackend | null;
  activeMessages: () => Message[];
  isGenerating: () => boolean;
  isAnyGenerating: () => boolean;

  // 对话管理
  newConversation: (name?: string) => Promise<void>;
  switchConversation: (id: string) => Promise<void>;
  closeConversation: (id: string) => Promise<void>;
  renameConversation: (id: string, name: string) => void;

  // 消息操作
  setInputValue: (value: string) => void;
  addMessage: (conversationId: string, message: Message) => void;
  setMessages: (messages: Message[], targetConversationId?: string) => void;
  clearMessages: () => void;

  // UI 操作
  setGenerating: (conversationId: string, value: boolean) => void;

  // 后端管理
  ensureBackend: (conversationId: string) => Promise<number | null>;
  updateBackendStatus: (
    conversationId: string,
    status: ConversationWithBackend['backendStatus'],
    port?: number
  ) => void;

  // API 操作
  sendMessage: (content: string) => Promise<void>;
  interrupt: () => Promise<void>;

  // 任务事件流（阶段②：前端纯浏览，渲染由 WS task_event 驱动）
  handleTaskEvent: (event: WSTaskEvent) => void;
  syncGeneratingState: (conversationId: string) => Promise<boolean>;
  resumeConversationState: (conversationId: string) => Promise<void>;
  resumeAllConversations: () => void;

  loadHistory: () => Promise<void>;
  loadHistoryFile: (filename: string) => Promise<void>;
  fetchHistoryFiles: () => Promise<void>;
  renameHistoryFile: (oldName: string, newName: string) => Promise<void>;
  deleteHistoryFile: (filename: string) => Promise<void>;
  saveConversation: () => Promise<void>;
}

// 主后端端口
const MAIN_PORT = 8765;

export const useChatStore = create<ChatStore>((set, get) => {
  // 初始化默认对话（使用主后端）
  // 使用固定 ID "default" 以匹配后端的默认 session
  const defaultConv = createConversation('Default');
  defaultConv.id = 'default';  // 覆盖为固定 ID
  defaultConv.backendPort = MAIN_PORT;
  defaultConv.backendStatus = 'running';

  // 确保后端切换到默认 session
  const chatApi = createChatApi(MAIN_PORT);
  chatApi.switchSession('default').catch((e) => {
    frontendLog(`[错误] 初始化默认会话失败: ${e}`);
  });

  return {
    conversations: [defaultConv],
    activeConversationId: defaultConv.id,
    generatingConversations: new Set<string>(),
    inputValue: '',
    historyFiles: [],

    // Getters
    activeConversation: () => {
      const { conversations, activeConversationId } = get();
      return conversations.find((c) => c.id === activeConversationId) || null;
    },

    activeMessages: () => {
      const conv = get().activeConversation();
      return conv?.messages || [];
    },

    isGenerating: () => {
      const { activeConversationId, generatingConversations } = get();
      return activeConversationId
        ? generatingConversations.has(activeConversationId)
        : false;
    },

    isAnyGenerating: () => {
      return get().generatingConversations.size > 0;
    },

    // 后端管理
    updateBackendStatus: (conversationId, status, port) => {
      set((state) => ({
        conversations: state.conversations.map((c) =>
          c.id === conversationId
            ? { ...c, backendStatus: status, backendPort: port ?? c.backendPort }
            : c
        ),
      }));
    },

    ensureBackend: async (conversationId) => {
      const { conversations } = get();
      const conv = conversations.find((c) => c.id === conversationId);

      if (!conv) return null;

      // 现在所有对话都使用主后端，直接返回主端口
      if (conv.backendStatus === 'running' && conv.backendPort) {
        return conv.backendPort;
      }

      // 默认使用主后端
      return MAIN_PORT;
    },

    // 对话管理
    newConversation: async (name) => {
      const newConv = createConversation(name);
      // 新对话直接使用主后端
      newConv.backendPort = MAIN_PORT;
      newConv.backendStatus = 'running';

      set((state) => ({
        conversations: [...state.conversations, newConv],
        activeConversationId: newConv.id,
        inputValue: '',
      }));

      // 在后端创建新会话
      try {
        const chatApi = createChatApi(MAIN_PORT);
        await chatApi.createSession(newConv.id);
        frontendLog(`[新建] ${newConv.name} (${newConv.id.slice(0, 16)}...)`);
      } catch (e) {
        frontendLog(`[错误] 创建对话失败: ${e}`);
      }
    },

    switchConversation: async (id) => {
      const { conversations, activeConversationId } = get();
      if (id === activeConversationId) return;

      const conv = conversations.find((c) => c.id === id);
      if (conv) {
        set({ activeConversationId: id, inputValue: '' });

        // 通知后端切换会话并加载历史
        const chatApi = createChatApi(MAIN_PORT);
        try {
          await chatApi.switchSession(id);

          // 从后端加载该会话的消息历史快照
          const messages = await fetchSessionMessages(MAIN_PORT, id);

          // 更新该对话的消息
          get().setMessages(messages, id);

          // 进入会话时向后端核对是否有 running 任务，恢复 generating 状态
          void get().syncGeneratingState(id);
        } catch (e) {
          const errorMsg = e instanceof Error ? e.message : String(e);
          frontendLog(`[错误] 切换会话失败: ${errorMsg}`);
        }
      }
    },

    closeConversation: async (id) => {
      const { conversations, activeConversationId, generatingConversations } =
        get();
      if (conversations.length <= 1) return;

      const conv = conversations.find((c) => c.id === id);

      // 如果正在生成，先中断（后端任务循环靠 epoch 感知，轮间生效）
      if (generatingConversations.has(id) && conv?.backendPort) {
        try {
          const chatApi = createChatApi(conv.backendPort);
          await chatApi.interrupt(id);
        } catch (e) {
          frontendLog(`[错误] 关闭对话时中断失败: ${e}`);
        }
      }

      // 删除后端会话
      try {
        const chatApi = createChatApi(MAIN_PORT);
        await chatApi.deleteSession(id);
      } catch (e) {
        frontendLog(`[错误] 删除后端会话失败: ${e}`);
      }

      // 清除该会话的todos
      const { clearTodos } = useTodoStore.getState();
      clearTodos(id);

      const newConversations = conversations.filter((c) => c.id !== id);
      const newActiveId =
        id === activeConversationId
          ? newConversations[newConversations.length - 1].id
          : activeConversationId;

      const newGenerating = new Set(generatingConversations);
      newGenerating.delete(id);
      delete activeTasksByConversation[id];
      delete pendingSubmits[id];
      delete interruptBarriers[id];
      delete taskStateVersions[id];
      delete discardedSubmissions[id];

      set({
        conversations: newConversations,
        activeConversationId: newActiveId,
        generatingConversations: newGenerating,
      });

      // 切换到新的活动会话
      if (id === activeConversationId && newActiveId) {
        const chatApi = createChatApi(MAIN_PORT);
        chatApi.switchSession(newActiveId).catch((e) => {
          frontendLog(`[错误] 关闭对话后切换会话失败: ${e}`);
        });
      }
    },

    renameConversation: (id, name) => {
      set((state) => ({
        conversations: state.conversations.map((c) =>
          c.id === id ? { ...c, name, updatedAt: Date.now() } : c
        ),
      }));
    },

    // 消息操作
    setInputValue: (value) => set({ inputValue: value }),

    addMessage: (conversationId, message) => {
      set((state) => ({
        conversations: state.conversations.map((c) =>
          c.id === conversationId
            ? {
                ...c,
                messages: [...c.messages, message],
                updatedAt: Date.now(),
              }
            : c
        ),
      }));
    },

    setMessages: (messages, targetConversationId?) => {
      set((state) => {
        const { activeConversationId, conversations } = state;
        const targetId = targetConversationId || activeConversationId;
        return {
          conversations: conversations.map((c) =>
            c.id === targetId
              ? { ...c, messages, updatedAt: Date.now() }
              : c
          ),
        };
      });
    },

    clearMessages: () => {
      set((state) => {
        const { activeConversationId, conversations } = state;
        return {
          conversations: conversations.map((c) =>
            c.id === activeConversationId
              ? { ...c, messages: [], updatedAt: Date.now() }
              : c
          ),
        };
      });
    },

    // UI 操作
    setGenerating: (conversationId, value) => {
      set((state) => {
        const newGenerating = new Set(state.generatingConversations);
        if (value) {
          newGenerating.add(conversationId);
        } else {
          newGenerating.delete(conversationId);
        }
        return { generatingConversations: newGenerating };
      });
    },

    // API 操作
    // 阶段②：前端纯浏览——只提交任务（POST /api/task/submit），
    // 循环由后端自驱，逐轮渲染由 WS task_event 事件驱动（见 handleTaskEvent）
    sendMessage: async (content) => {
      const { activeConversationId, addMessage, setGenerating, ensureBackend } = get();
      if (!activeConversationId) return;

      const conversationId = activeConversationId;
      if (get().generatingConversations.has(conversationId)) {
        frontendLog(`[提示] 当前会话已有运行中的任务，请先中断`);
        return;
      }

      const port = await ensureBackend(conversationId);
      if (!port) {
        frontendLog(`[错误] 后端未就绪`);
        return;
      }

      const submissionId = generateSubmissionId();
      activeTasksByConversation[conversationId] = { submissionId };
      bumpTaskStateVersion(conversationId);

      const userMessageId = Date.now().toString();
      addMessage(conversationId, {
        id: userMessageId,
        role: 'user',
        content,
        timestamp: Date.now(),
      });
      set({ inputValue: '' });
      setGenerating(conversationId, true);

      const submitPromise = (async (): Promise<SubmitOutcome> => {
        const barrier = interruptBarriers[conversationId];
        if (barrier) {
          const interrupted = await barrier;
          if (!interrupted) {
            return {
              submitted: false,
              success: false,
              error: '上一请求中断失败，请重试',
            };
          }
        }

        // 等待期间该 submission 可能已经被 Stop 作废。
        if (activeTasksByConversation[conversationId]?.submissionId !== submissionId) {
          return { submitted: false, success: false };
        }

        try {
          const taskApi = createTaskApi(port);
          const response = await taskApi.submit(conversationId, submissionId, content);
          if (!response.success) {
            return {
              submitted: true,
              success: false,
              error: response.error || '未知错误',
            };
          }
          return {
            submitted: true,
            success: true,
            taskId: response.task_id,
          };
        } catch (error) {
          return {
            submitted: true,
            success: false,
            error: String(error),
          };
        }
      })();
      pendingSubmits[conversationId] = submitPromise;

      const outcome = await submitPromise;
      if (pendingSubmits[conversationId] === submitPromise) {
        delete pendingSubmits[conversationId];
      }

      const identity = activeTasksByConversation[conversationId];
      if (identity?.submissionId !== submissionId) {
        return;
      }

      if (!outcome.success) {
        delete activeTasksByConversation[conversationId];
        bumpTaskStateVersion(conversationId);
        setGenerating(conversationId, false);
        if (!outcome.submitted && outcome.error) {
          set((state) => ({
            inputValue: state.activeConversationId === conversationId ? content : state.inputValue,
            conversations: state.conversations.map((conversation) =>
              conversation.id === conversationId
                ? {
                    ...conversation,
                    messages: conversation.messages.filter(
                      (message) => message.id !== userMessageId
                    ),
                  }
                : conversation
            ),
          }));
          frontendLog(`[错误] ${outcome.error}`);
        } else if (outcome.submitted) {
          frontendLog(`[错误] 任务提交失败: ${outcome.error || '未知错误'}`);
          void get().syncGeneratingState(conversationId);
        }
        return;
      }

      identity.taskId = outcome.taskId;
      frontendLog(`[任务] 已提交: ${outcome.taskId}`);
    },

    interrupt: async () => {
      const { activeConversationId, activeConversation, setGenerating } = get();
      if (!activeConversationId) return;

      const conversationId = activeConversationId;
      const conv = activeConversation();
      if (!conv?.backendPort) return;

      const interruptedIdentity = activeTasksByConversation[conversationId];
      const pendingSubmit = pendingSubmits[conversationId];

      // UI 立即解锁；从这一行起旧 submission 的任何事件都不再有效。
      discardSubmission(conversationId, interruptedIdentity?.submissionId);
      delete activeTasksByConversation[conversationId];
      bumpTaskStateVersion(conversationId);
      setGenerating(conversationId, false);
      frontendLog(`[中断] 已停止等待，旧请求回复将被丢弃`);

      const previousBarrier = interruptBarriers[conversationId];
      const barrier = (async (): Promise<boolean> => {
        try {
          if (previousBarrier && !(await previousBarrier)) {
            return false;
          }
          let taskId = interruptedIdentity?.taskId;
          if (pendingSubmit) {
            const outcome = await pendingSubmit;
            if (outcome.success) {
              taskId = outcome.taskId;
            }
          }

          // submit 尚未入网就被取消时，后端没有 task 可退役。
          if (!taskId) {
            return true;
          }

          const chatApi = createChatApi(conv.backendPort!);
          await chatApi.interrupt(conversationId);
          return true;
        } catch (error) {
          frontendLog(`[错误] 中断请求失败: ${error}`);
          void get().syncGeneratingState(conversationId);
          return false;
        }
      })();
      interruptBarriers[conversationId] = barrier;

      try {
        await barrier;
      } finally {
        if (interruptBarriers[conversationId] === barrier) {
          delete interruptBarriers[conversationId];
        }
      }
    },

    // 处理 WS task_event（后端广播、无路由：必须按 session_id 过滤到对应会话）
    handleTaskEvent: (event) => {
      const sessionId = event.session_id;
      if (!sessionId) return;

      // 只处理本窗口已知会话的事件（含非活跃标签页，支持多标签并发生成）；
      // 其他消费者（如流水线会话）的事件直接忽略
      const conv = get().conversations.find((c) => c.id === sessionId);
      if (!conv) return;

      if (isDiscardedSubmission(sessionId, event.submission_id)) {
        return;
      }
      const identity = activeTasksByConversation[sessionId];
      if (!identity || identity.submissionId !== event.submission_id) {
        return;
      }
      if (identity.taskId && identity.taskId !== event.task_id) {
        return;
      }
      identity.taskId = event.task_id;

      switch (event.event) {
        case 'task_started':
          get().setGenerating(sessionId, true);
          break;

        case 'round_reply': {
          const content = (event.data.content || '').trim();
          if (content) {
            get().addMessage(sessionId, {
              id: `${event.task_id}_r${event.round}`,
              role: 'assistant',
              content,
              timestamp: Date.now(),
              raw_response: event.data.raw_response,
              sent_messages: event.data.sent_messages,
            });
          }
          break;
        }

        case 'todo_update':
          // TODO 面板仍由既有带 conversation_id 的 todo_update 通道驱动。
          break;

        case 'tool_call':
        case 'tool_result':
          break;

        case 'task_finished': {
          delete activeTasksByConversation[sessionId];
          bumpTaskStateVersion(sessionId);
          get().setGenerating(sessionId, false);
          const { status, rounds, error } = event.data;
          const roundText = `共${rounds ?? event.round}轮`;
          if (status === 'interrupted') {
            frontendLog(`[中断] 任务已中断（${roundText}）`);
          } else if (status === 'timeout') {
            frontendLog(`[错误] 任务超时: ${error || '未知错误'}（${roundText}）`);
          } else if (status === 'failed') {
            frontendLog(`[错误] 任务失败: ${error || '未知错误'}（${roundText}）`);
          } else {
            frontendLog(`[完成] ${roundText}`);
          }
          break;
        }
      }
    },

    // 向后端核对该会话是否有 running 任务，恢复 generating 状态；返回是否 running
    syncGeneratingState: async (conversationId) => {
      try {
        const port = await get().ensureBackend(conversationId);
        if (!port) return false;

        const requestVersion = taskStateVersions[conversationId] || 0;
        const taskApi = createTaskApi(port);
        const response = await taskApi.statusBySession(conversationId);
        if (!response.success) return false;

        // Stop/send 在 status 请求期间发生时，旧快照不得重新锁住 UI。
        if ((taskStateVersions[conversationId] || 0) !== requestVersion) {
          return get().generatingConversations.has(conversationId);
        }

        const activeTask = response.active_task;
        const localIdentity = activeTasksByConversation[conversationId];
        if (localIdentity) {
          if (
            activeTask?.status === 'running'
            && activeTask.submission_id === localIdentity.submissionId
          ) {
            localIdentity.taskId = activeTask.task_id;
          }
          return get().generatingConversations.has(conversationId);
        }

        if (
          activeTask?.status === 'running'
          && !isDiscardedSubmission(conversationId, activeTask.submission_id)
        ) {
          activeTasksByConversation[conversationId] = {
            submissionId: activeTask.submission_id,
            taskId: activeTask.task_id,
          };
          get().setGenerating(conversationId, true);
          return true;
        }

        delete activeTasksByConversation[conversationId];
        get().setGenerating(conversationId, false);
        return false;
      } catch (error) {
        frontendLog(`[错误] 恢复任务状态失败: ${error}`);
        return false;
      }
    },

    // WS 连接（含重连）后恢复单个会话：核对 generating；
    // 有 running 任务（页面刷新场景）或本地此前认为在生成（断线期间可能漏事件）
    // 时，拉 history 快照补齐丢失的消息，之后靠增量事件
    resumeConversationState: async (conversationId) => {
      const recoveryVersion = taskStateVersions[conversationId] || 0;
      const wasGenerating = get().generatingConversations.has(conversationId);
      const hasRunning = await get().syncGeneratingState(conversationId);

      // 恢复期间发生过 Send/Stop 时，调用开始时的 status/history 语义已经过期。
      if ((taskStateVersions[conversationId] || 0) !== recoveryVersion) {
        return;
      }

      const currentIdentity = activeTasksByConversation[conversationId];
      if (currentIdentity && !currentIdentity.taskId) {
        return;
      }

      if (hasRunning || wasGenerating) {
        try {
          const messages = await fetchSessionMessages(MAIN_PORT, conversationId);
          if ((taskStateVersions[conversationId] || 0) !== recoveryVersion) {
            return;
          }
          get().setMessages(messages, conversationId);
          frontendLog(`[恢复] 会话 ${conversationId.slice(0, 16)} 快照: ${messages.length}条消息`);
        } catch (error) {
          frontendLog(`[错误] 恢复会话快照失败: ${error}`);
        }
      }
    },

    resumeAllConversations: () => {
      const { conversations } = get();
      for (const conv of conversations) {
        void get().resumeConversationState(conv.id);
      }
    },

    loadHistory: async () => {
      const conv = get().activeConversation();
      if (!conv?.backendPort){ 
        frontendLog(`[错误] loadHistory: 没有活动对话或后端端口`);
        return;
      }
      try {
        const messages = await fetchSessionMessages(conv.backendPort, conv.id);
        get().setMessages(messages);
      } catch (error) {
        frontendLog(`[错误] 加载历史失败: ${error}`);
      }
    },

    loadHistoryFile: async (filename) => {
      // 创建新对话并加载历史文件
      try {
        frontendLog(`[加载] 历史文件: ${filename}`);
        const base = (filename.split('/').pop() ?? filename).replace('.mem', '');
        // 短记忆标签名：优先会话 ID，兼容旧时间戳快照
        const sessionMatch = base.match(/^session_(.+)$/);
        const autoMatch = base.match(/^auto_\d{4}-(\d{2})-(\d{2})_(\d{2})(\d{2})\d{2}_/);
        const name = sessionMatch
          ? `短记忆 ${sessionMatch[1].slice(0, 24)}`
          : autoMatch
            ? `短记忆 ${autoMatch[1]}-${autoMatch[2]} ${autoMatch[3]}:${autoMatch[4]}`
            : base.slice(0, 20);
        const newConv = createConversation(name, filename);
        newConv.backendPort = MAIN_PORT;
        newConv.backendStatus = 'running';

        const chatApi = createChatApi(MAIN_PORT);

        // 1. 创建新会话
        await chatApi.createSession(newConv.id);

        // 2. 切换到新会话（确保后端当前会话是新创建的）
        await chatApi.switchSession(newConv.id);

        // 3. 加载历史文件到当前会话
        const loadResponse = await commandsApi.load(filename, newConv.id);
        
        if (loadResponse.success) {
          // 4. 获取加载后的历史消息（使用 raw=true 获取原始内容）
          const historyResponse = await chatApi.history(true, newConv.id);
          
          // 先过滤消息，保留所有消息用于构建上下文
          const allMessages = historyResponse.messages.filter((msg) => {
            // 只保留 user 和 assistant 消息
            return msg.role === 'user' || msg.role === 'assistant';
          });

          const messages: Message[] = allMessages
            .map((msg, index) => {
              const baseMessage = {
                id: index.toString(),
                role: msg.role as 'user' | 'assistant',
                timestamp: Date.now(),
              };

              if (msg.role === 'assistant') {
                // assistant 消息：提取显示内容，保存原始内容用于"查看详情"
                // 查找前一条消息作为"发送给LLM的消息"
                const prevMsg = index > 0 ? allMessages[index - 1] : null;
                const sent_messages = prevMsg ? [{ role: prevMsg.role, content: prevMsg.content }] : [];
                
                return {
                  ...baseMessage,
                  content: extractDisplayContent(msg.content),
                  sent_messages, // 前一条消息（用户输入或工具结果）
                  raw_response: msg.content, // 原始响应（包含协议标记）
                };
              } else {
                // user 消息：区分用户输入和工具结果
                const isToolResult = msg.content?.trim().startsWith('@SPORE:RESULT');
                
                if (isToolResult) {
                  // 工具结果消息：不在对话中显示，但会被 assistant 消息引用
                  return null;
                } else {
                  // 用户输入消息：正常显示
                  return {
                    ...baseMessage,
                    content: msg.content,
                  };
                }
              }
            })
            .filter((msg): msg is Message => msg !== null && msg.content.trim() !== ''); // 过滤掉 null 和空内容

          newConv.messages = messages;
          frontendLog(`[加载] 完成: ${messages.length}条消息`);

          set((state) => ({
            conversations: [...state.conversations, newConv],
            activeConversationId: newConv.id,
          }));
          // 加载会刷新该会话短记忆，同步更新列表
          void get().fetchHistoryFiles();
        } else {
          frontendLog(`[错误] 加载失败: ${loadResponse.message_count}`);
        }
      } catch (error) {
        frontendLog(`[错误] 加载历史文件失败: ${error}`);
      }
    },

    fetchHistoryFiles: async () => {
      try {
        const response = await commandsApi.listHistory();
        set({ historyFiles: response.files });
      } catch (error) {
        frontendLog(`[错误] 获取历史文件列表失败: ${error}`);
      }
    },

    renameHistoryFile: async (oldName, newName) => {
      try {
        await commandsApi.renameHistory(oldName, newName);
        await get().fetchHistoryFiles();
        frontendLog(`[历史] 已重命名: ${oldName} -> ${newName}`);
      } catch (error) {
        frontendLog(`[错误] 重命名历史文件失败: ${error}`);
      }
    },

    deleteHistoryFile: async (filename) => {
      try {
        await commandsApi.deleteHistory(filename);
        await get().fetchHistoryFiles();
        frontendLog(`[历史] 已删除: ${filename}`);
      } catch (error) {
        frontendLog(`[错误] 删除历史文件失败: ${error}`);
      }
    },

    saveConversation: async () => {
      const conv = get().activeConversation();
      if (!conv?.backendPort) return;

      try {
        const cmdApi = createCommandsApi(conv.backendPort);
        await cmdApi.save(conv.id);
      } catch (error) {
        frontendLog(`[错误] 保存对话失败: ${error}`);
      }
    },
  };
});
