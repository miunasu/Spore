/**
 * Spore Desktop 主应用
 */
import { useEffect, useCallback } from 'react';
import { TitleBar } from './components/layout/TitleBar';
import { MainLayout } from './components/layout/MainLayout';
import { MiniModeView } from './components/layout/MiniModeView';
import { useMiniModeStore } from './stores/miniModeStore';
import { LogPanel } from './components/log-panel/LogPanel';
import { ChatPanel } from './components/chat-panel/ChatPanel';
import { SidePanel } from './components/side-panel/SidePanel';
import { SecurityRemediationModal } from './components/chat-panel/SecurityRemediationModal';
import { wsService } from './services/websocket';
import { useLogStore } from './stores/logStore';
import { useAgentStore } from './stores/agentStore';
import { useChatStore } from './stores/chatStore';
import { useTodoStore } from './stores/todoStore';
import { useConfirmStore } from './stores/confirmStore';
import { useSettingsStore } from './stores/settingsStore';
import type { WSEvent, LogType, AgentStatus, OldLogType } from './types';

const PRELOADED_THEME_VAR_KEYS = [
  '--spore-bg-rgb',
  '--spore-panel-rgb',
  '--spore-card-rgb',
  '--spore-accent-rgb',
  '--spore-border-rgb',
  '--spore-highlight-rgb',
  '--spore-highlight-hover-rgb',
  '--spore-text-rgb',
  '--spore-muted-rgb',
  '--spore-error-rgb',
  '--spore-warning-rgb',
  '--spore-info-rgb',
  '--spore-success-rgb',
  '--spore-scrollbar-rgb',
  '--spore-scrollbar-hover-rgb',
  '--spore-glass-rgb',
  '--spore-card-hover-rgb',
] as const;

function App() {
  const { addLog, setActiveConversation } = useLogStore();
  const { addAgent, updateAgentStatus, addAgentLog } = useAgentStore();
  const activeConversationId = useChatStore((state) => state.activeConversationId);
  const { setTodos } = useTodoStore();
  const { enqueueRequest, removeRequest } = useConfirmStore();
  const theme = useSettingsStore((state) => state.theme);
  const miniMode = useMiniModeStore((state) => state.miniMode);

  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute('data-theme', theme);
    root.style.colorScheme = theme;

    if (root.getAttribute('data-theme-preloaded') === '1') {
      PRELOADED_THEME_VAR_KEYS.forEach((key) => root.style.removeProperty(key));
      root.removeAttribute('data-theme-preloaded');
      document.getElementById('spore-theme-preload-style')?.remove();
    }
  }, [theme]);

  // 同步活跃对话到日志 store
  useEffect(() => {
    setActiveConversation(activeConversationId);
  }, [activeConversationId, setActiveConversation]);

  // 批量处理 WebSocket 事件
  const handleWSEvents = useCallback((events: WSEvent[]) => {
    const currentActiveConversationId = useChatStore.getState().activeConversationId;
    for (const event of events) {
      // 注意：不在这里过滤 conversation_id
      // 让各个 store 自己决定如何处理消息
      // 这样可以确保消息被正确路由到对应的标签页
      
      switch (event.type) {
        case 'log': {
          // 映射旧日志类型到新类型
          const oldType = event.data.log_type as OldLogType;
          let newType: LogType;
          if (oldType === 'error' || oldType === 'llm_validation' || oldType === 'tool_execution' || oldType === 'error_validation') {
            newType = 'system';
          } else {
            newType = oldType as LogType;
          }
          // 保存原始的 conversation_id，让 logStore 处理
          const logEntry = { 
            ...event.data, 
            log_type: newType,
            conversationId: event.data.conversation_id 
          };
          addLog(newType, logEntry);
          break;
        }
        case 'agent_register':
          // Agent 注册消息 - 只处理当前活跃对话的 Agent
          if (!event.data.conversation_id || event.data.conversation_id === currentActiveConversationId) {
            addAgent({
              id: event.data.agent_id,
              name: event.data.agent_name,
              status: event.data.status,
              logs: [],
            });
          }
          break;
        case 'agent_output':
          // 只处理当前活跃对话的 Agent 输出
          if (!event.data.conversation_id || event.data.conversation_id === currentActiveConversationId) {
            // 确保 Agent 存在
            addAgent({
              id: event.data.agent_id,
              name: event.data.agent_name,
              status: 'running',
              logs: [],
            });
            // 添加日志
            addAgentLog(event.data.agent_id, {
              message: event.data.message,
              level: event.data.level as 'INFO' | 'WARNING' | 'ERROR' | 'SUCCESS',
              timestamp: event.data.timestamp,
            });
          }
          break;
        case 'agent_status':
          // 只处理当前活跃对话的 Agent 状态更新
          if (!event.data.conversation_id || event.data.conversation_id === currentActiveConversationId) {
            updateAgentStatus(event.data.agent_id, event.data.status as AgentStatus);
          }
          break;
        case 'todo_update':
          // 更新指定会话的 Todo；缺少 conversation_id 的事件会被丢弃
          if (event.data.conversation_id) {
            setTodos(event.data.conversation_id, event.data.todos);
          } else {
            console.warn('[WebSocket] Dropped unscoped todo_update event', event);
          }
          break;
        case 'confirm_request':
          // 只处理当前活跃对话的确认请求（并发时入队排队确认）
          if (!event.data.conversation_id || event.data.conversation_id === currentActiveConversationId) {
            enqueueRequest(event.data);
          }
          break;
        case 'confirm_cancel':
          // 按 request_id 精确移除（超时取消不误伤队列中其他请求）
          removeRequest(event.data.request_id);
          break;
        case 'task_event':
          // 任务事件流（后端任务自驱）：chatStore 内部按顶层 session_id 路由到对应会话
          useChatStore.getState().handleTaskEvent(event);
          break;
      }
    }
  }, [addLog, addAgent, updateAgentStatus, addAgentLog, setTodos, enqueueRequest, removeRequest]);

  useEffect(() => {
    // 订阅 WebSocket 事件
    const unsubscribe = wsService.subscribe(handleWSEvents);

    // 连接建立（含重连、页面刷新后的首连）时拉快照恢复各会话的任务状态
    // （后端 WS 为广播推送，断线期间的 task_event 会丢失，需要补状态）
    const unsubscribeOpen = wsService.subscribeOpen(() => {
      useChatStore.getState().resumeAllConversations();
    });

    // 连接 WebSocket（在订阅之后，确保首连的 open 事件不被漏掉）
    wsService.connect();

    return () => {
      unsubscribe();
      unsubscribeOpen();
      wsService.disconnect();
    };
  }, [handleWSEvents]);

  return (
    <div className="h-screen flex flex-col bg-spore-bg">
      <TitleBar />
      <div className="flex-1 overflow-hidden">
        {miniMode ? (
          <MiniModeView />
        ) : (
          <MainLayout
            leftPanel={<LogPanel />}
            centerPanel={<ChatPanel />}
            rightPanel={<SidePanel />}
          />
        )}
      </div>
      {/* 安全熔断弹窗：全局挂载，普通/Mini 模式均生效 */}
      <SecurityRemediationModal />
    </div>
  );
}

export default App;
