/**
 * 聊天状态管理 - 多后端实例架构
 * 每个对话对应一个独立的后端实例
 */
import { create } from 'zustand';
import type { Message, Conversation, HistoryFile, WSTaskEvent, AgentActivity, CommandIntent } from '../types';
import {
  createChatApi,
  createCommandsApi,
  createTaskApi,
  commandsApi,
} from '../services/api';
import { useLogStore } from './logStore';
import { useTodoStore } from './todoStore';
import { useSecurityStore } from './securityStore';

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

// ---------------------------------------------------------------------------
// 命令意图持久化（安全 Agent command_intent 事件）
//
// 意图事件与 round_reply 无固定先后：命令执行快于 LLM 分析时意图晚到，
// 反之早到。归属规则统一为"包含该命令的最近一条 assistant 消息"：
// - 早到：先入 pending 缓冲，round_reply 时按 raw_response 匹配挂载
// - 晚到：直接反查已有消息挂载
// intentLog 为会话级日志，切换会话/断线重连重拉历史快照后用它重新挂载。
// ---------------------------------------------------------------------------
const pendingIntentsBySession: Record<string, CommandIntent[] | undefined> = {};
const intentLogBySession: Record<string, CommandIntent[] | undefined> = {};
const INTENT_LOG_LIMIT = 200;

const recordIntent = (conversationId: string, ci: CommandIntent): void => {
  const log = intentLogBySession[conversationId] || [];
  const existing = log.find((e) => e.command === ci.command);
  if (existing) {
    existing.intent = ci.intent;
    existing.is_malicious = ci.is_malicious;
    existing.malicious_reason = ci.malicious_reason;
  } else {
    log.push(ci);
    if (log.length > INTENT_LOG_LIMIT) {
      log.splice(0, log.length - INTENT_LOG_LIMIT);
    }
  }
  intentLogBySession[conversationId] = log;
};

const messageContainsCommand = (msg: Message, command: string): boolean =>
  msg.role === 'assistant' && !!msg.raw_response && msg.raw_response.includes(command);

// 把意图日志重新挂载到历史快照消息上（按"包含命令的最后一条 assistant 消息"归属）
const attachIntentsToMessages = (
  messages: Message[],
  log: CommandIntent[] | undefined
): Message[] => {
  if (!log || log.length === 0) return messages;
  const result = messages.map((m) => ({ ...m }));
  for (const ci of log) {
    for (let i = result.length - 1; i >= 0; i--) {
      const msg = result[i];
      if (!messageContainsCommand(msg, ci.command)) continue;
      const list = msg.command_intents || [];
      if (!list.some((e) => e.command === ci.command)) {
        msg.command_intents = [...list, ci];
      }
      break;
    }
  }
  return result;
};

const fetchSessionMessages = async (
  port: number,
  sessionId: string
): Promise<Message[]> => {
  const chatApi = createChatApi(port);
  const historyResponse = await chatApi.history(true, sessionId);

  const allMessages = historyResponse.messages.filter((msg) => (
    msg.role === 'user' || msg.role === 'assistant' || msg.role === 'system'
  ));

  const messages = allMessages
    .map((msg, index) => {
      const isSystemNotice =
        msg.role === 'system'
        || (msg.role === 'user' && msg.content?.trim().startsWith('[系统通知]'));
      const baseMessage = {
        id: index.toString(),
        role: (isSystemNotice ? 'system' : msg.role) as 'user' | 'assistant' | 'system',
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

  // 历史快照不含意图信息，用会话内存中的意图日志重新挂载
  return attachIntentsToMessages(messages, intentLogBySession[sessionId]);
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

  // 按对话的 Agent 当前活动（辅助代理意图 / 安全守卫扫描），非阻塞状态提示
  agentActivities: Record<string, AgentActivity | null>;

  // UI 状态
  inputValue: string;
  historyFiles: HistoryFile[];

  // Getters
  activeConversation: () => ConversationWithBackend | null;
  activeMessages: () => Message[];
  isGenerating: () => boolean;
  isAnyGenerating: () => boolean;
  activeAgentActivity: () => AgentActivity | null;

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

  // 安全熔断自动修复：新建会话，把安全 Agent 上下文作为用户输入交给 Spore 处置
  startSecurityAutoFix: (autoFixPrompt: string) => Promise<void>;

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
    agentActivities: {},
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

    activeAgentActivity: () => {
      const { activeConversationId, agentActivities } = get();
      return activeConversationId ? (agentActivities[activeConversationId] || null) : null;
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
      delete pendingIntentsBySession[id];
      delete intentLogBySession[id];

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

    // 安全熔断自动修复：新建会话 + 把安全 Agent 上下文作为用户输入提交任务
    startSecurityAutoFix: async (autoFixPrompt) => {
      if (!autoFixPrompt || !autoFixPrompt.trim()) return;

      const time = new Date().toLocaleTimeString('zh-CN', {
        hour: '2-digit',
        minute: '2-digit',
      });
      const newConv = createConversation(`安全修复 ${time}`);
      newConv.backendPort = MAIN_PORT;
      newConv.backendStatus = 'running';
      const conversationId = newConv.id;

      // 先建标签页并切换（GUI 同步），后端会话随 createSession 建立
      set((state) => ({
        conversations: [...state.conversations, newConv],
        activeConversationId: conversationId,
        inputValue: '',
      }));

      try {
        const chatApi = createChatApi(MAIN_PORT);
        await chatApi.createSession(conversationId);
      } catch (e) {
        // /api/task/submit 对不存在的会话会自动创建，创建失败不阻断修复流程
        frontendLog(`[错误] 创建修复会话失败（提交任务时将自动创建）: ${e}`);
      }

      // 新会话无并发任务/中断屏障，直接走任务提交
      const submissionId = generateSubmissionId();
      activeTasksByConversation[conversationId] = { submissionId };
      bumpTaskStateVersion(conversationId);

      get().addMessage(conversationId, {
        id: Date.now().toString(),
        role: 'user',
        content: autoFixPrompt,
        timestamp: Date.now(),
      });
      get().setGenerating(conversationId, true);

      try {
        const taskApi = createTaskApi(MAIN_PORT);
        const response = await taskApi.submit(
          conversationId,
          submissionId,
          autoFixPrompt
        );
        if (!response.success) {
          throw new Error(response.error || '未知错误');
        }
        const identity = activeTasksByConversation[conversationId];
        if (identity?.submissionId === submissionId) {
          identity.taskId = response.task_id;
        }
        frontendLog(`[安全] 已创建自动修复会话并提交处置任务`);
      } catch (e) {
        if (
          activeTasksByConversation[conversationId]?.submissionId === submissionId
        ) {
          delete activeTasksByConversation[conversationId];
          bumpTaskStateVersion(conversationId);
          get().setGenerating(conversationId, false);
        }
        frontendLog(`[错误] 自动修复任务提交失败: ${e}`);
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

      // 更新/清除该会话的 Agent 活动提示（非阻塞）
      const setActivity = (activity: AgentActivity | null) => {
        set((state) => ({
          agentActivities: { ...state.agentActivities, [sessionId]: activity },
        }));
      };

      // 安全 Agent：命令意图解释（"Agent 正在做什么"）
      // 异步旁路事件，分析可能晚于任务终态到达——不走活跃任务门，
      // 迟到的意图仍按"包含该命令的 assistant 消息"持久化归属。
      if (event.event === 'command_intent') {
        const intent = (event.data.intent || '').trim();
        const command = event.data.command || '';
        if (!intent || !command) return;

        const isMalicious = event.data.is_malicious === true;
        const maliciousReason = event.data.malicious_reason || '';

        const identity = activeTasksByConversation[sessionId];
        const isCurrentTask =
          identity?.submissionId === event.submission_id
          && !isDiscardedSubmission(sessionId, event.submission_id);

        // 活动栏临时提示只在任务仍在跑时更新；恶意由 security_malicious 事件负责告警
        if (isCurrentTask && !isMalicious) {
          setActivity({ kind: 'intent', text: intent, command });
        }

        const ci: CommandIntent = {
          command,
          intent,
          is_malicious: isMalicious,
          malicious_reason: isMalicious ? maliciousReason : undefined,
        };
        recordIntent(sessionId, ci);

        // 消息已存在（意图晚到）→ 直接挂载
        let attached = false;
        set((state) => ({
          conversations: state.conversations.map((c) => {
            if (c.id !== sessionId) return c;
            for (let i = c.messages.length - 1; i >= 0; i--) {
              const msg = c.messages[i];
              if (!messageContainsCommand(msg, command)) continue;
              // 最近的匹配消息已有该命令的意图（如重复命令）→ 转入缓冲，归属下一轮回复
              if ((msg.command_intents || []).some((e) => e.command === command)) break;
              attached = true;
              const messages = c.messages.slice();
              messages[i] = {
                ...msg,
                command_intents: [...(msg.command_intents || []), ci],
              };
              return { ...c, messages, updatedAt: Date.now() };
            }
            return c;
          }),
        }));

        // 尚未到达（意图早到）→ 缓冲等 round_reply；任务已结束则丢弃（日志里留有备份）
        if (!attached && isCurrentTask) {
          const pending = pendingIntentsBySession[sessionId] || [];
          if (!pending.some((e) => e.command === command)) {
            pending.push(ci);
          }
          pendingIntentsBySession[sessionId] = pending;
        }
        return;
      }

      // 安全 Agent：检测到恶意命令（后端已中断本轮会话）。异步旁路，此时
      // task 必然已被中断退役，故与 command_intent 同区、在 active 门之前处理。
      if (event.event === 'security_malicious') {
        const command = event.data.command || '';
        const reason = event.data.malicious_reason || '';
        const intent = event.data.intent || command;
        setActivity({
          kind: 'security_malicious',
          text: `检测到恶意命令：${intent}${reason ? `（${reason}）` : ''}`,
          riskLevel: 'high',
          command,
        });
        frontendLog(`[安全] 检测到恶意命令，已中断本轮会话: ${command}`);
        // 登记安全事件 → 弹出熔断弹窗（处置建议由 security_remediation 事件补充）
        useSecurityStore.getState().addIncident({
          sessionId,
          command,
          intent,
          maliciousReason: reason,
          interrupted: event.data.interrupted !== false,
        });
        // 会话末尾追加一条本地提示（命令已执行无法撤销 + 会话已中断）。
        // 注意：此消息不在后端 history 中，切会话重拉快照后会消失（审计日志有据可查）。
        get().addMessage(sessionId, {
          id: `malicious_${event.task_id}_${Date.now()}`,
          role: 'assistant',
          content:
            `🚨 安全 Agent 检测到恶意命令，已中断本轮会话。\n` +
            `命令：${command}\n` +
            `原因：${reason || '未提供'}\n` +
            `注意：该命令在研判完成前已执行，无法自动撤销。安全 Agent 正在生成处置建议…`,
          timestamp: Date.now(),
        });
        return;
      }

      // 安全 Agent：熔断后的处置建议（二次研判产出）。同为异步旁路事件，
      // 在 active 门之前处理；挂载到熔断弹窗供用户选择手动/自动修复。
      if (event.event === 'security_remediation') {
        const command = event.data.command || '';
        useSecurityStore.getState().attachAdvice(sessionId, command, {
          summary: event.data.summary || '',
          impact: event.data.impact || '',
          manualSteps: event.data.manual_steps || [],
          autoFixPrompt: event.data.auto_fix_prompt || '',
          aiGenerated: event.data.ai_generated === true,
        });
        frontendLog(`[安全] 恶意命令处置建议已生成`);
        return;
      }

      // 后端自发的子Agent完成通知没有本地 submission identity；先收养任务，
      // 后续 round_reply/task_finished 即可沿用普通任务事件通路。
      if (
        event.event === 'task_started'
        && event.data.source === 'agent_notification'
      ) {
        if (isDiscardedSubmission(sessionId, event.submission_id)) return;
        const currentIdentity = activeTasksByConversation[sessionId];
        if (
          currentIdentity
          && currentIdentity.submissionId !== event.submission_id
        ) {
          return;
        }
        const isNewNotificationTask = !currentIdentity;
        activeTasksByConversation[sessionId] = {
          submissionId: event.submission_id,
          taskId: event.task_id,
        };
        bumpTaskStateVersion(sessionId);
        setActivity(null);
        pendingIntentsBySession[sessionId] = [];
        get().setGenerating(sessionId, true);

        const notice = event.data.notice;
        if (notice && isNewNotificationTask) {
          const taskNames = notice.agents.map((agent) => agent.task_id).join('、');
          get().addMessage(sessionId, {
            id: `subagent_notice_${event.task_id}`,
            role: 'system',
            content: `子Agent ${taskNames} 已完成 (${notice.done}/${notice.total})`,
            timestamp: Date.now(),
          });
        }
        return;
      }

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
          setActivity(null);
          pendingIntentsBySession[sessionId] = [];
          get().setGenerating(sessionId, true);
          break;

        // 安全守卫：正在进行 AI 风险评估
        case 'security_checking':
          setActivity({
            kind: 'security_checking',
            text: `正在评估${event.data.description || '高危操作'}的风险…`,
            command: event.data.command,
          });
          break;

        // 安全守卫：风险评估结果
        case 'security_alert':
          if (event.data.auto_allow) {
            // 自动放行：一行信息提示
            setActivity({
              kind: 'security_alert',
              text: event.data.action || '已放行系统操作',
              riskLevel: event.data.risk_level,
              command: event.data.command,
            });
          } else {
            // 需要用户确认：由阻塞式 ConfirmBar 接管，清除"正在评估"提示避免重复
            setActivity(null);
          }
          break;

        // 安全守卫：用户确认结果 —— 清除扫描提示
        case 'security_result':
          setActivity(null);
          break;

        case 'round_reply': {
          setActivity(null);
          const content = (event.data.content || '').trim();
          if (content) {
            // 挂载本轮缓冲的命令意图（按 raw_response 是否包含该命令归属）
            const raw = event.data.raw_response || '';
            const pending = pendingIntentsBySession[sessionId] || [];
            const matched = pending.filter((ci) => raw.includes(ci.command));
            pendingIntentsBySession[sessionId] = pending.filter(
              (ci) => !raw.includes(ci.command)
            );
            get().addMessage(sessionId, {
              id: `${event.task_id}_r${event.round}`,
              role: 'assistant',
              content,
              timestamp: Date.now(),
              raw_response: event.data.raw_response,
              sent_messages: event.data.sent_messages,
              command_intents: matched.length > 0 ? matched : undefined,
            });
          }
          break;
        }

        case 'todo_update':
          // TODO 面板仍由既有带 conversation_id 的 todo_update 通道驱动。
          break;

        case 'tool_call':
          break;
        case 'tool_result':
          // 工具执行完成，清除意图/放行提示
          setActivity(null);
          break;

        case 'task_finished': {
          setActivity(null);
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
        // 会话短记忆（session_*.mem）恢复时沿用原会话 ID：
        // checkpoint / 文件备份等会话绑定数据随之恢复，无需迁移
        if (sessionMatch) {
          const originalId = sessionMatch[1];
          const existing = get().conversations.find((c) => c.id === originalId);
          if (existing) {
            // 该会话仍在打开状态（内存里的状态比短记忆快照更新），直接切换过去
            await get().switchConversation(originalId);
            return;
          }
          newConv.id = originalId;
        }
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
            // 保留用户、assistant 与系统通知消息
            return msg.role === 'user' || msg.role === 'assistant' || msg.role === 'system';
          });

          const messages: Message[] = allMessages
            .map((msg, index) => {
              const isSystemNotice =
                msg.role === 'system'
                || (msg.role === 'user' && msg.content?.trim().startsWith('[系统通知]'));
              const baseMessage = {
                id: index.toString(),
                role: (isSystemNotice ? 'system' : msg.role) as 'user' | 'assistant' | 'system',
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
