/**
 * 聊天状态管理 - 多后端实例架构
 * 每个对话对应一个独立的后端实例
 */
import { create } from 'zustand';
import type { Message, Conversation, HistoryFile } from '../types';
import {
  createChatApi,
  createCommandsApi,
  commandsApi,
} from '../services/api';
import { useLogStore } from './logStore';
import { useTodoStore } from './todoStore';

// 前端日志辅助函数
const frontendLog = (message: string) => {
  useLogStore.getState().addFrontendLog(message);
};

const isHiddenProtocolLine = (trimmed: string): boolean =>
  [
    '@SPORE:REPLY_START',
    '@SPORE:REPLY_END',
    '@SPORE:FINAL@',
    '@SPORE:CONTENT_START',
    '@SPORE:CONTENT_END',
    '@SPORE:RESULT',
  ].includes(trimmed);

// 提取消息的显示内容（处理新协议 @SPORE: 标记）
const extractDisplayContent = (content: string): string => {
  if (!content) return '';
  
  const lines = content.split('\n');
  const replyStart = '@SPORE:REPLY_START';
  const replyEnd = '@SPORE:REPLY_END';

  // 查找 REPLY 块（必须独占一行）
  let replyPos = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim() === replyStart) {
      replyPos = i;
      break;
    }
  }
  
  if (replyPos >= 0) {
    // 找到 REPLY 块，提取其内容
    const replyLines: string[] = [];
    
    for (let i = replyPos + 1; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      
      // 遇到结束标记，停止提取
      if (trimmed === replyEnd || trimmed === '@SPORE:FINAL@') {
        break;
      }

      if (isHiddenProtocolLine(trimmed)) {
        continue;
      }
      
      replyLines.push(line);
    }
    
    return replyLines.join('\n').trim();
  }
  
  // 没有 REPLY 块，过滤掉所有协议标记
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
      if (trimmed === '@SPORE:FINAL@') {
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

// 请求 token（按对话 ID）。用于丢弃中断后迟到的旧响应。
const activeRequestTokens: Record<string, string> = {};
const cancelledRequestTokens = new Set<string>();

// 生成唯一 ID
const generateId = () =>
  `conv_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

const generateRequestToken = () =>
  `req_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;

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
          
          // 从后端加载该会话的消息历史
          const historyResponse = await chatApi.history(true, id);
          
          const allMessages = historyResponse.messages.filter((msg) => (
            msg.role === 'user' || msg.role === 'assistant'
          ));

          const messages: Message[] = allMessages
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

              if (msg.content?.trim().startsWith('@SPORE:RESULT')) {
                return null;
              }

              return {
                ...baseMessage,
                content: msg.content,
              };
            })
            .filter((msg): msg is Message => msg !== null && msg.content.trim() !== '');
          
          // 更新该对话的消息
          get().setMessages(messages, id);
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

      // 如果正在生成，先中断
      if (generatingConversations.has(id) && conv?.backendPort) {
        const token = activeRequestTokens[id];
        if (token) {
          cancelledRequestTokens.add(token);
          delete activeRequestTokens[id];
        }
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
    sendMessage: async (content) => {
      const { activeConversationId, addMessage, setGenerating, ensureBackend } =
        get();

      if (!activeConversationId) return;

      const conversationId = activeConversationId;

      // 确保后端已启动
      const port = await ensureBackend(conversationId);
      if (!port) {
        frontendLog(`[错误] 后端未就绪`);
        return;
      }

      const chatApi = createChatApi(port);
      const requestToken = generateRequestToken();
      const previousToken = activeRequestTokens[conversationId];
      if (previousToken) {
        cancelledRequestTokens.add(previousToken);
      }
      activeRequestTokens[conversationId] = requestToken;

      const userMessage: Message = {
        id: Date.now().toString(),
        role: 'user',
        content,
        timestamp: Date.now(),
      };
      // 使用 addMessage 添加到指定的对话
      addMessage(conversationId, userMessage);
      set({ inputValue: '' });

      setGenerating(conversationId, true);
      const startTime = Date.now();
      let roundCount = 0;

      try {
        let shouldContinue = true;
        let isFirstRequest = true;

        while (
          shouldContinue &&
          activeRequestTokens[conversationId] === requestToken &&
          !cancelledRequestTokens.has(requestToken)
        ) {
          roundCount++;
          const response = await chatApi.send(
            isFirstRequest ? content : '', 
            conversationId
          );
          isFirstRequest = false;

          if (
            activeRequestTokens[conversationId] !== requestToken ||
            cancelledRequestTokens.has(requestToken)
          ) {
            frontendLog(`[中断] 第${roundCount}轮被用户中断`);
            break;
          }
          if (response.status === 'interrupted') {
            frontendLog(`[中断] 第${roundCount}轮被系统中断`);
            break;
          }
          if (response.status === 'error') {
            frontendLog(`[错误] 第${roundCount}轮: ${response.message}`);
            break;
          }

          if (response.status === 'success' && response.content) {
            const assistantMessage: Message = {
              id: (Date.now() + Math.random()).toString(),
              role: 'assistant',
              content: response.content,
              timestamp: Date.now(),
              sent_messages: response.sent_messages,
              raw_response: response.raw_response,
            };
            // 使用 addMessage 添加到指定的对话（即使用户已切换标签页）
            addMessage(conversationId, assistantMessage);
          }

          shouldContinue = response.should_continue === true;
          if (shouldContinue) {
            frontendLog(`[继续] 第${roundCount}轮完成，继续执行...`);
          }
        }

        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        frontendLog(`[完成] 共${roundCount}轮，耗时${elapsed}秒`);
        
        // 不需要最后的 setMessages 同步，因为 addMessage 已经实时更新了
        // 如果需要同步（比如确保一致性），应该使用 conversationId 而不是 activeConversationId
      } catch (error) {
        frontendLog(`[错误] 发送失败: ${error}`);
      } finally {
        if (activeRequestTokens[conversationId] === requestToken) {
          setGenerating(conversationId, false);
          delete activeRequestTokens[conversationId];
        }
        cancelledRequestTokens.delete(requestToken);
      }
    },

    interrupt: async () => {
      const { activeConversationId, setGenerating, activeConversation } = get();
      if (!activeConversationId) return;

      const conv = activeConversation();
      if (!conv?.backendPort) return;

      frontendLog(`[中断] 请求中断...`);
      const requestToken = activeRequestTokens[activeConversationId];
      if (requestToken) {
        cancelledRequestTokens.add(requestToken);
        delete activeRequestTokens[activeConversationId];
      }
      
      // 立即更新 UI 状态
      setGenerating(activeConversationId, false);
      
      try {
        const chatApi = createChatApi(conv.backendPort);
        await chatApi.interrupt(activeConversationId);
        frontendLog(`[中断] 成功`);
      } catch (error) {
        frontendLog(`[错误] 中断失败: ${error}`);
      }
    },

    loadHistory: async () => {
      const conv = get().activeConversation();
      if (!conv?.backendPort){ 
        frontendLog(`[错误] loadHistory: 没有活动对话或后端端口`);
        return;
      }
      try {
        const chatApi = createChatApi(conv.backendPort);
        const response = await chatApi.history(true, conv.id);
        const allMessages = response.messages.filter((msg) => (
          msg.role === 'user' || msg.role === 'assistant'
        ));

        const messages: Message[] = allMessages
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

            if (msg.content?.trim().startsWith('@SPORE:RESULT')) {
              return null;
            }

            return {
              ...baseMessage,
              content: msg.content,
            };
          })
          .filter((msg): msg is Message => msg !== null && msg.content.trim() !== '');
        get().setMessages(messages);
      } catch (error) {
        frontendLog(`[错误] 加载历史失败: ${error}`);
      }
    },

    loadHistoryFile: async (filename) => {
      // 创建新对话并加载历史文件
      try {
        frontendLog(`[加载] 历史文件: ${filename}`);
        const name = filename.replace('memsave/', '').replace('.mem', '').slice(0, 20);
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
