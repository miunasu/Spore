/**
 * API 服务层
 * 封装所有后端 API 调用，支持多后端实例
 */

const MAIN_API_BASE = 'http://127.0.0.1:8765';

class ApiError extends Error {
  constructor(
    public status: number,
    public data: unknown
  ) {
    super(`API Error: ${status}`);
    this.name = 'ApiError';
  }
}

// 通用请求函数（主后端）
async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${MAIN_API_BASE}${endpoint}`;

  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new ApiError(response.status, data);
  }

  return response.json();
}

// 指定端口的请求函数（用于子实例）
async function requestToPort<T>(
  port: number,
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `http://127.0.0.1:${port}${endpoint}`;

  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new ApiError(response.status, data);
  }

  return response.json();
}

// 创建针对特定端口的 Chat API
export const createChatApi = (port: number) => ({
  send: (message: string) =>
    requestToPort<{
      status: string;
      content?: string;
      message?: string;
      should_continue?: boolean;
      sent_messages?: Array<{role: string; content: string}>;
      raw_response?: string;
    }>(port, '/api/chat/send', {
      method: 'POST',
      body: JSON.stringify({ message }),
    }),

  interrupt: () =>
    requestToPort<{ success: boolean }>(port, '/api/chat/interrupt', {
      method: 'POST',
    }),

  history: (raw: boolean = false) =>
    requestToPort<{ messages: Array<{ role: string; content: string }> }>(
      port,
      `/api/chat/history${raw ? '?raw=true' : ''}`
    ),

  newConversation: () =>
    requestToPort<{ success: boolean }>(port, '/api/chat/new', {
      method: 'POST',
    }),

  // 会话管理
  switchSession: (sessionId: string) =>
    requestToPort<{ success: boolean; session_id: string; message_count?: number }>(
      port,
      '/api/chat/session/switch',
      { method: 'POST', body: JSON.stringify({ session_id: sessionId }) }
    ),

  createSession: (sessionId: string) =>
    requestToPort<{ success: boolean; session_id: string }>(
      port,
      '/api/chat/session/create',
      { method: 'POST', body: JSON.stringify({ session_id: sessionId }) }
    ),

  deleteSession: (sessionId: string) =>
    requestToPort<{ success: boolean }>(
      port,
      '/api/chat/session/delete',
      { method: 'POST', body: JSON.stringify({ session_id: sessionId }) }
    ),

  listSessions: () =>
    requestToPort<{ sessions: string[]; current: string }>(
      port,
      '/api/chat/session/list'
    ),
});

// 创建针对特定端口的 Commands API
export const createCommandsApi = (port: number) => ({
  getPrompt: () =>
    requestToPort<{ prompt: string; token_count: number }>(
      port,
      '/api/commands/prompt'
    ),

  getContext: (full = false) =>
    requestToPort<{ messages: unknown[]; message_count?: number }>(
      port,
      `/api/commands/context?full=${full}`
    ),

  clearMemory: () =>
    requestToPort<{ success: boolean }>(port, '/api/commands/memory/clear', {
      method: 'POST',
    }),

  getSkills: () =>
    requestToPort<{ skills: string }>(port, '/api/commands/skills'),

  toggleSaveMode: () =>
    requestToPort<{ save_mode: boolean }>(port, '/api/commands/savemode', {
      method: 'POST',
    }),

  save: () =>
    requestToPort<{ success: boolean }>(port, '/api/commands/save', {
      method: 'POST',
    }),

  load: (filename: string) =>
    requestToPort<{ success: boolean; message_count: number }>(
      port,
      '/api/commands/load',
      { method: 'POST', body: JSON.stringify({ filename }) }
    ),

  continueRecent: () =>
    requestToPort<{
      success: boolean;
      filename: string;
      message_count: number;
    }>(port, '/api/commands/continue', { method: 'POST' }),

  getTokens: (conversationId?: string) =>
    requestToPort<{ token_count: number }>(
      port,
      `/api/commands/tokens${conversationId ? `?conversation_id=${conversationId}` : ''}`
    ),

  setActiveConversation: (conversationId: string) =>
    requestToPort<{ success: boolean }>(port, '/api/commands/tokens/set-conversation', {
      method: 'POST',
      body: JSON.stringify({ conversation_id: conversationId }),
    }),

  triggerCharacter: () =>
    requestToPort<{ success: boolean }>(port, '/api/commands/character', {
      method: 'POST',
    }),

  listHistory: () =>
    requestToPort<{
      files: Array<{ name: string; size: number; modified: number }>;
    }>(port, '/api/commands/history/list'),

  clearLogs: () =>
    requestToPort<{
      success: boolean;
      cleared_count: number;
      skipped_current?: string;
      errors?: string[];
    }>(port, '/api/commands/logs/clear', { method: 'POST' }),

  autoCleanShortLogs: (minLines = 10) =>
    requestToPort<{
      success: boolean;
      cleaned_count: number;
      cleaned_dirs?: string[];
      min_lines: number;
      skipped_current?: string;
      errors?: string[];
    }>(port, `/api/commands/logs/auto-clean?min_lines=${minLines}`, { method: 'POST' }),

  // 上下文模式管理
  getMode: () =>
    requestToPort<{
      mode: string;
      description: string;
      available_modes: Array<{
        value: string;
        label: string;
        description: string;
      }>;
    }>(port, '/api/commands/mode'),

  setMode: (mode: string) =>
    requestToPort<{
      success: boolean;
      mode: string;
      description: string;
      message: string;
    }>(port, '/api/commands/mode', {
      method: 'POST',
      body: JSON.stringify({ mode }),
    }),
});

// 主后端 Chat API（默认端口）
export const chatApi = createChatApi(8765);

// 主后端 Commands API（默认端口）
export const commandsApi = createCommandsApi(8765);

// Files API（只在主后端）
export const filesApi = {
  list: (path: string) =>
    request<{
      path: string;
      items: Array<{
        name: string;
        type: string;
        path: string;
        size?: number;
        modified?: number;
      }>;
    }>(`/api/files/list?path=${encodeURIComponent(path)}`),

  read: (path: string) =>
    request<{ path: string; content: string; size: number }>(
      `/api/files/read?path=${encodeURIComponent(path)}`
    ),

  write: (path: string, content: string) =>
    request<{ success: boolean; path: string; size: number }>(
      '/api/files/write',
      { method: 'POST', body: JSON.stringify({ path, content }) }
    ),

  delete: (path: string) =>
    request<{ success: boolean }>(
      `/api/files/delete?path=${encodeURIComponent(path)}`,
      { method: 'DELETE' }
    ),

  rename: (oldPath: string, newPath: string) =>
    request<{ success: boolean; old_path: string; new_path: string }>(
      '/api/files/rename',
      {
        method: 'POST',
        body: JSON.stringify({ old_path: oldPath, new_path: newPath }),
      }
    ),

  create: (path: string, type: 'file' | 'folder', content = '') =>
    request<{ success: boolean; path: string; type: string }>(
      '/api/files/create',
      { method: 'POST', body: JSON.stringify({ path, type, content }) }
    ),
};

// Agents API（只在主后端）
export const agentsApi = {
  list: () =>
    request<{ agents: Array<{ id: string; name: string; status: string }> }>(
      '/api/agents/list'
    ),

  // 轮询获取所有活跃 Agent 的状态和日志
  poll: () =>
    request<{
      agents: Array<{
        id: string;
        name: string;
        status: string;
        logs: Array<{ message: string; level: string; timestamp: number }>;
      }>;
    }>('/api/agents/poll'),

  getLogs: (agentId: string, limit = 100) =>
    request<{ agent_id: string; logs: unknown[]; total: number }>(
      `/api/agents/${agentId}/logs?limit=${limit}`
    ),

  getStatus: (agentId: string) =>
    request<{ agent_id: string; status: string }>(
      `/api/agents/${agentId}/status`
    ),

  getRecentLogs: (limit = 50) =>
    request<{ logs: unknown[] }>(`/api/agents/logs/recent?limit=${limit}`),
};

// Instances API（多后端实例管理，只在主后端）
export const instancesApi = {
  create: (instanceId: string) =>
    request<{
      success: boolean;
      instance: { id: string; port: number; status: string };
    }>('/api/instances/create', {
      method: 'POST',
      body: JSON.stringify({ instance_id: instanceId }),
    }),

  stop: (instanceId: string) =>
    request<{ success: boolean; message: string }>('/api/instances/stop', {
      method: 'POST',
      body: JSON.stringify({ instance_id: instanceId }),
    }),

  list: () =>
    request<{
      instances: Array<{
        id: string;
        port: number;
        status: string;
        created_at: number;
      }>;
    }>('/api/instances/list'),

  get: (instanceId: string) =>
    request<{ id: string; port: number; status: string; created_at: number }>(
      `/api/instances/${instanceId}`
    ),
};

// Health check
export const healthCheck = (port = 8765) =>
  requestToPort<{ status: string; initialized: boolean }>(port, '/health');

export { ApiError, requestToPort };
