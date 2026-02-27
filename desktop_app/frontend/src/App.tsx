/**
 * Spore Desktop 主应用
 */
import { useEffect, useCallback } from 'react';
import { TitleBar } from './components/layout/TitleBar';
import { MainLayout } from './components/layout/MainLayout';
import { LogPanel } from './components/log-panel/LogPanel';
import { ChatPanel } from './components/chat-panel/ChatPanel';
import { SidePanel } from './components/side-panel/SidePanel';
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
  const { loadHistory, activeConversationId } = useChatStore();
  const { setTodos } = useTodoStore();
  const { setPendingRequest, clearRequest } = useConfirmStore();
  const theme = useSettingsStore((state) => state.theme);

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
    for (const event of events) {
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
          addLog(newType, { ...event.data, log_type: newType });
          break;
        }
        case 'agent_register':
          // Agent 注册消息 - 立即创建 Agent
          addAgent({
            id: event.data.agent_id,
            name: event.data.agent_name,
            status: event.data.status,
            logs: [],
          });
          break;
        case 'agent_output':
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
          break;
        case 'agent_status':
          updateAgentStatus(event.data.agent_id, event.data.status as AgentStatus);
          break;
        case 'todo_update':
          setTodos(event.data.todos);
          break;
        case 'confirm_request':
          setPendingRequest(event.data);
          break;
        case 'confirm_cancel':
          clearRequest();
          break;
      }
    }
  }, [addLog, addAgent, updateAgentStatus, addAgentLog, setTodos, setPendingRequest, clearRequest]);

  useEffect(() => {
    // 连接 WebSocket
    wsService.connect();

    // 订阅 WebSocket 事件（批量处理）
    const unsubscribe = wsService.subscribe(handleWSEvents);

    // 加载对话历史
    loadHistory();

    return () => {
      unsubscribe();
      wsService.disconnect();
    };
  }, [handleWSEvents, loadHistory]);

  return (
    <div className="h-screen flex flex-col bg-spore-bg">
      <TitleBar />
      <div className="flex-1 overflow-hidden">
        <MainLayout
          leftPanel={<LogPanel />}
          centerPanel={<ChatPanel />}
          rightPanel={<SidePanel />}
        />
      </div>
    </div>
  );
}

export default App;
