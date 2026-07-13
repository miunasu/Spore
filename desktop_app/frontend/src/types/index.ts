// 消息类型
export interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
  sent_messages?: Array<{role: string; content: string}>;  // 实际发送给LLM的消息（用于详细显示）
  raw_response?: string;  // LLM返回的原始响应（包含协议标记）
}

// 对话类型
export interface Conversation {
  id: string;
  name: string;
  messages: Message[];
  createdAt: number;
  updatedAt: number;
  historyFile?: string;  // 关联的 history 文件名
  backendPort?: number | null;  // 后端端口
  backendStatus?: 'none' | 'starting' | 'running' | 'stopped' | 'error';
}

// 日志类型 - system 合并了 error_validation 和 tool_execution
export type LogType = 'system' | 'general' | 'frontend';

export interface LogEntry {
  log_type: LogType;
  content: string;
  timestamp: number;
  conversationId?: string;  // 关联的对话 ID
}

// 旧日志类型映射到新类型
export type OldLogType = 'error' | 'llm_validation' | 'tool_execution' | 'general' | 'error_validation';
export const mapOldLogType = (oldType: OldLogType): LogType => {
  if (oldType === 'error' || oldType === 'llm_validation' || oldType === 'tool_execution' || oldType === 'error_validation') {
    return 'system';
  }
  return oldType as LogType;
};

// 文件类型
export interface FileItem {
  name: string;
  type: 'file' | 'folder';
  path: string;
  size?: number;
  modified?: number;
}

// Agent 类型
export type AgentStatus = 'running' | 'completed' | 'interrupted' | 'error';

export interface AgentLog {
  message: string;
  level: 'INFO' | 'WARNING' | 'ERROR' | 'SUCCESS';
  timestamp: number;
}

export interface Agent {
  id: string;
  name: string;
  status: AgentStatus;
  logs: AgentLog[];
}

// WebSocket 事件类型
export interface WSLogEvent {
  type: 'log';
  data: LogEntry & {
    conversation_id?: string;  // 会话 ID，用于多标签页过滤
  };
}

export interface WSAgentOutputEvent {
  type: 'agent_output';
  data: {
    agent_id: string;
    agent_name: string;
    message: string;
    level: string;
    timestamp: number;
    conversation_id?: string;  // 会话 ID，用于多标签页过滤
  };
}

export interface WSAgentStatusEvent {
  type: 'agent_status';
  data: {
    agent_id: string;
    status: AgentStatus;
    conversation_id?: string;  // 会话 ID，用于多标签页过滤
  };
}

export interface WSAgentRegisterEvent {
  type: 'agent_register';
  data: {
    agent_id: string;
    agent_name: string;
    status: AgentStatus;
    conversation_id?: string;  // 会话 ID，用于多标签页过滤
  };
}

export interface WSChatChunkEvent {
  type: 'chat_chunk';
  data: {
    content: string;
    is_final: boolean;
    conversation_id?: string;  // 会话 ID，用于多标签页过滤
  };
}

// Todo 类型
export type TodoStatus = 'pending' | 'completed' | 'failed';

export interface TodoItem {
  id: string;
  content: string;
  status: TodoStatus;
  updated_at: string;
}

export interface WSTodoUpdateEvent {
  type: 'todo_update';
  data: {
    todos: TodoItem[];
    timestamp: number;
    conversation_id?: string;  // 会话 ID，用于多标签页过滤
  };
}

// 确认请求类型
export interface ConfirmRequestData {
  request_id: string;
  action_type: string;
  title: string;
  message: string;
  details: string[];
  timestamp: number;
  conversation_id?: string;  // 会话 ID，用于多标签页过滤
}

export interface WSConfirmRequestEvent {
  type: 'confirm_request';
  data: ConfirmRequestData;
}

export interface WSConfirmCancelEvent {
  type: 'confirm_cancel';
  data: {
    request_id: string;
    reason: string;
    conversation_id?: string;  // 会话 ID，用于多标签页过滤
  };
}

export interface WSConfirmResultEvent {
  type: 'confirm_result';
  data: {
    request_id: string;
    confirmed: boolean;
    result: any;
    conversation_id?: string;  // 会话 ID，用于多标签页过滤
  };
}

// 任务事件（阶段②：后端任务自驱 + 事件流，见 PLAN_spore_task_api.md 3.9/4）
// 后端 WS 通道为广播、无路由，事件必须按顶层 session_id 过滤到对应会话
export type TaskStatus = 'running' | 'succeeded' | 'failed' | 'interrupted' | 'timeout';

export type TaskEventName =
  | 'task_started'
  | 'round_reply'
  | 'tool_call'
  | 'tool_result'
  | 'todo_update'
  | 'task_finished';

export interface WSTaskEvent {
  type: 'task_event';
  event: TaskEventName;
  session_id: string;
  task_id: string;
  submission_id: string;
  round: number;
  ts: string;
  data: {
    // task_started
    message?: string;
    // round_reply（字符串字段最多 8KB）
    content?: string;
    raw_response?: string;
    sent_messages?: Array<{ role: string; content: string }>;
    // tool_call / tool_result
    tool_name?: string;
    tool_names?: string[];
    mode?: string;
    status?: TaskStatus | string; // task_finished 时为 TaskStatus；tool_result 时为工具状态
    // todo_update
    tasks?: Array<{ content: string; status: string }>;
    // task_finished
    rounds?: number;
    error?: string;
  };
}

// GET /api/task/status 返回的任务注册表条目
export interface TaskInfo {
  task_id: string;
  submission_id: string;
  session_id: string;
  status: TaskStatus;
  rounds: number;
  started_at: string;
  finished_at: string | null;
  last_content: string;
  error: string | null;
  interrupt_epoch: number;
  cancel_requested: boolean;
  worker_done: boolean;
}

export type WSEvent = WSLogEvent | WSAgentOutputEvent | WSAgentStatusEvent | WSAgentRegisterEvent | WSChatChunkEvent | WSTodoUpdateEvent | WSConfirmRequestEvent | WSConfirmCancelEvent | WSConfirmResultEvent | WSTaskEvent;

// Tab 类型
export type TabType = 'output' | 'skills' | 'prompt' | 'history' | 'agents' | 'note' | 'characters';

// API 响应类型
export interface ApiResponse<T = unknown> {
  success?: boolean;
  message?: string;
  data?: T;
  error?: string;
}

export interface ChatResponse {
  status: 'success' | 'error' | 'interrupted';
  content?: string;
  message?: string;
  should_continue?: boolean;
  sent_messages?: Array<{role: string; content: string}>;  // 实际发送给LLM的消息
  raw_response?: string;  // LLM返回的原始响应（包含协议标记）
}

// History 文件类型
export interface HistoryFile {
  name: string;
  size: number;
  modified: number;
}
