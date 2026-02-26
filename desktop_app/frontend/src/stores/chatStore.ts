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

// 前端日志辅助函数
const frontendLog = (message: string) => {
  useLogStore.getState().addFrontendLog(message);
};

// 提取消息的显示内容（处理新协议 @SPORE: 标记）
const extractDisplayContent = (content: string): string => {
  if (!content) return '';
  
  const lines = content.split('\n');
  const replyMarker = '@SPORE:REPLY';
  
  // 查找 @SPORE:REPLY 标记（必须独占一行）
  let replyPos = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim() === replyMarker) {
      replyPos = i;
      break;
    }
  }
  
  if (replyPos >= 0) {
    // 找到 REPLY 块，提取其内容
    const replyLines: string[] = [];
    const endMarkers = ['@SPORE:ACTION', '@SPORE:TODO', '@SPORE:RESULT', '@SPORE:FINAL@'];
    
    for (let i = replyPos + 1; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      
      // 遇到结束标记，停止提取
      if (endMarkers.some(marker => trimmed === marker || trimmed.startsWith(marker))) {
        break;
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
    
    // 检查是否是协议标记
    if (trimmed === '@SPORE:ACTION' || 
        trimmed === '@SPORE:TODO' || 
        trimmed === '@SPORE:RESULT' || 
        trimmed === '@SPORE:FINAL@') {
      inProtocolBlock = true;
      continue;
    }
    
    // 如果在协议块中，检查是否遇到下一个标记或空行后的内容
    if (inProtocolBlock) {
      if (trimmed === '') {
        // 空行可能表示协议块结束
        continue;
      }
      // 继续跳过协议块内容
      continue;
    }
    
    filteredLines.push(line);
  }
  
  return filteredLines.join('\n').trim();
};

// 中断标志（按对话 ID）
const interruptFlags: Record<string, boolean> = {};

// 生成唯一 ID
const generateId = () =>
  `conv_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

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
  switchConversation: (id: string) => void;
  closeConversation: (id: string) => Promise<void>;
  renameConversation: (id: string, name: string) => void;

  // 消息操作
  setInputValue: (value: string) => void;
  addMessage: (conversationId: string, message: Message) => void;
  setMessages: (messages: Message[]) => void;
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
  saveConversation: () => Promise<void>;
}

// 主后端端口
const MAIN_PORT = 8765;

export const useChatStore = create<ChatStore>((set, get) => {
  // 初始化默认对话（使用主后端）
  const defaultConv = createConversation('Default');
  defaultConv.backendPort = MAIN_PORT;
  defaultConv.backendStatus = 'running';

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
        console.error('创建新对话失败:', e);
      }
    },

    switchConversation: (id) => {
      const { conversations, activeConversationId } = get();
      if (id === activeConversationId) return;

      const conv = conversations.find((c) => c.id === id);
      if (conv) {
        set({ activeConversationId: id, inputValue: '' });
        frontendLog(`[切换] -> ${conv.name} (${conv.messages.length}条消息)`);

        // 通知后端切换会话
        const chatApi = createChatApi(MAIN_PORT);
        chatApi.switchSession(id).catch((e) => {
          frontendLog(`[错误] 切换会话失败: ${e}`);
          console.error('切换会话失败:', e);
        });
      }
    },

    closeConversation: async (id) => {
      const { conversations, activeConversationId, generatingConversations } =
        get();
      if (conversations.length <= 1) return;

      const conv = conversations.find((c) => c.id === id);

      // 如果正在生成，先中断
      if (generatingConversations.has(id) && conv?.backendPort) {
        interruptFlags[id] = true;
        try {
          const chatApi = createChatApi(conv.backendPort);
          await chatApi.interrupt();
        } catch (e) {
          console.error('中断失败:', e);
        }
      }

      // 删除后端会话
      try {
        const chatApi = createChatApi(MAIN_PORT);
        await chatApi.deleteSession(id);
      } catch (e) {
        console.error('删除会话失败:', e);
      }

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
          console.error('切换会话失败:', e);
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

    setMessages: (messages) => {
      set((state) => {
        const { activeConversationId, conversations } = state;
        return {
          conversations: conversations.map((c) =>
            c.id === activeConversationId
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
      const { activeConversationId, addMessage, setGenerating, ensureBackend, setMessages } =
        get();

      if (!activeConversationId) return;

      const conversationId = activeConversationId;

      // 确保后端已启动
      const port = await ensureBackend(conversationId);
      if (!port) {
        console.error('后端未就绪');
        return;
      }

      const chatApi = createChatApi(port);
      interruptFlags[conversationId] = false;

      const userMessage: Message = {
        id: Date.now().toString(),
        role: 'user',
        content,
        timestamp: Date.now(),
      };
      addMessage(conversationId, userMessage);
      set({ inputValue: '' });

      // 日志：用户发送消息
      const contentPreview = content.length > 50 ? content.slice(0, 50) + '...' : content;
      frontendLog(`[发送] ${contentPreview}`);

      setGenerating(conversationId, true);
      const startTime = Date.now();
      let roundCount = 0;

      try {
        let shouldContinue = true;
        let isFirstRequest = true;

        while (shouldContinue && !interruptFlags[conversationId]) {
          roundCount++;
          const response = await chatApi.send(isFirstRequest ? content : '');
          isFirstRequest = false;

          if (interruptFlags[conversationId]) {
            frontendLog(`[中断] 第${roundCount}轮被用户中断`);
            break;
          }
          if (response.status === 'interrupted') {
            frontendLog(`[中断] 第${roundCount}轮被系统中断`);
            break;
          }
          if (response.status === 'error') {
            frontendLog(`[错误] 第${roundCount}轮: ${response.message}`);
            console.error('对话错误:', response.message);
            break;
          }

          if (response.status === 'success' && response.content) {
            const assistantMessage: Message = {
              id: (Date.now() + Math.random()).toString(),
              role: 'assistant',
              content: response.content,
              timestamp: Date.now(),
              sent_messages: response.sent_messages,  // 保存实际发送的消息
              raw_response: response.raw_response,  // 保存原始响应
            };
            addMessage(conversationId, assistantMessage);
            
            // 日志：AI回复
            const replyPreview = response.content.length > 80 
              ? response.content.slice(0, 80).replace(/\n/g, ' ') + '...' 
              : response.content.replace(/\n/g, ' ');
            frontendLog(`[回复] R${roundCount} (${response.content.length}字): ${replyPreview}`);
          }

          shouldContinue = response.should_continue === true;
          if (shouldContinue) {
            frontendLog(`[继续] 第${roundCount}轮完成，继续执行...`);
          }
        }

        // 对话结束后，从后端同步完整的消息历史
        // 确保前端显示和后端存储一致
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        frontendLog(`[完成] 共${roundCount}轮，耗时${elapsed}秒`);
        
        try {
          const historyResponse = await chatApi.history();
          
          // 保存当前消息的详情数据（sent_messages 和 raw_response）
          const currentMessages = get().activeMessages();
          const detailsMap = new Map<string, { sent_messages?: any[]; raw_response?: string }>();
          currentMessages.forEach(msg => {
            if (msg.sent_messages || msg.raw_response) {
              // 使用消息内容作为key（因为同步后id会变）
              const key = `${msg.role}:${msg.content}`;
              detailsMap.set(key, {
                sent_messages: msg.sent_messages,
                raw_response: msg.raw_response
              });
            }
          });
          
          const messages: Message[] = historyResponse.messages
            .filter((msg) => {
              // 只保留 user 和 assistant 消息
              if (msg.role !== 'user' && msg.role !== 'assistant') return false;
              // 过滤掉工具结果消息（以 @SPORE:RESULT 开头）
              if (msg.role === 'user' && msg.content?.trim().startsWith('@SPORE:RESULT')) return false;
              return true;
            })
            .map((msg, index) => {
              const displayContent = msg.role === 'assistant' ? extractDisplayContent(msg.content) : msg.content;
              const key = `${msg.role}:${displayContent}`;
              const details = detailsMap.get(key);
              
              return {
                id: index.toString(),
                role: msg.role as 'user' | 'assistant',
                content: displayContent,
                timestamp: Date.now(),
                // 恢复详情数据
                ...(details?.sent_messages && { sent_messages: details.sent_messages }),
                ...(details?.raw_response && { raw_response: details.raw_response }),
              };
            })
            .filter((msg) => msg.content.trim() !== ''); // 过滤掉空内容
          setMessages(messages);
        } catch (syncError) {
          console.error('同步消息历史失败:', syncError);
        }
      } catch (error) {
        frontendLog(`[错误] 发送失败: ${error}`);
        console.error('发送消息失败:', error);
      } finally {
        setGenerating(conversationId, false);
        delete interruptFlags[conversationId];
      }
    },

    interrupt: async () => {
      const { activeConversationId, setGenerating, activeConversation } = get();
      if (!activeConversationId) return;

      const conv = activeConversation();
      if (!conv?.backendPort) return;

      frontendLog(`[中断] 请求中断...`);
      interruptFlags[activeConversationId] = true;
      
      // 立即更新 UI 状态
      setGenerating(activeConversationId, false);
      
      try {
        const chatApi = createChatApi(conv.backendPort);
        await chatApi.interrupt();
        frontendLog(`[中断] 成功`);
      } catch (error) {
        frontendLog(`[错误] 中断失败: ${error}`);
        console.error('中断失败:', error);
      }
    },

    loadHistory: async () => {
      const conv = get().activeConversation();
      if (!conv?.backendPort) return;

      try {
        const chatApi = createChatApi(conv.backendPort);
        const response = await chatApi.history();
        const messages: Message[] = response.messages
          .filter((msg) => {
            // 只保留 user 和 assistant 消息
            if (msg.role !== 'user' && msg.role !== 'assistant') return false;
            // 过滤掉工具结果消息（以 @SPORE:RESULT 开头）
            if (msg.role === 'user' && msg.content?.trim().startsWith('@SPORE:RESULT')) return false;
            return true;
          })
          .map((msg, index) => ({
            id: index.toString(),
            role: msg.role as 'user' | 'assistant',
            // assistant 消息提取显示内容
            content: msg.role === 'assistant' ? extractDisplayContent(msg.content) : msg.content,
            timestamp: Date.now(),
          }))
          .filter((msg) => msg.content.trim() !== ''); // 过滤掉空内容
        get().setMessages(messages);
      } catch (error) {
        console.error('加载历史失败:', error);
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
        const loadResponse = await commandsApi.load(filename);
        
        if (loadResponse.success) {
          // 4. 获取加载后的历史消息（使用 raw=true 获取原始内容）
          const historyResponse = await chatApi.history(true);
          
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
        console.error('加载历史文件失败:', error);
      }
    },

    fetchHistoryFiles: async () => {
      try {
        const response = await commandsApi.listHistory();
        set({ historyFiles: response.files });
      } catch (error) {
        console.error('获取历史文件列表失败:', error);
      }
    },

    saveConversation: async () => {
      const conv = get().activeConversation();
      if (!conv?.backendPort) return;

      try {
        const cmdApi = createCommandsApi(conv.backendPort);
        await cmdApi.save();
      } catch (error) {
        console.error('保存对话失败:', error);
      }
    },
  };
});
