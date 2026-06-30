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
  send: (message: string, conversationId?: string) =>
    requestToPort<{
      status: string;
      content?: string;
      message?: string;
      should_continue?: boolean;
      sent_messages?: Array<{role: string; content: string}>;
      raw_response?: string;
    }>(port, '/api/chat/send', {
      method: 'POST',
      body: JSON.stringify({ message, conversation_id: conversationId }),
    }),

  interrupt: (conversationId?: string) =>
    requestToPort<{ success: boolean }>(port, '/api/chat/interrupt', {
      method: 'POST',
      body: JSON.stringify({ conversation_id: conversationId }),
    }),

  history: (raw: boolean = false, sessionId?: string) =>
    requestToPort<{ messages: Array<{ role: string; content: string }> }>(
      port,
      `/api/chat/history${raw ? '?raw=true' : ''}${sessionId ? (raw ? '&' : '?') + `session_id=${sessionId}` : ''}`
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
    requestToPort<{
      input: number;
      output: number;
      cumulative_input: number;
      cumulative_output: number;
      context: number;
    }>(
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

  renameHistory: (oldName: string, newName: string) =>
    requestToPort<{ success: boolean; old_name: string; new_name: string }>(
      port,
      '/api/commands/history/rename',
      { method: 'POST', body: JSON.stringify({ old_name: oldName, new_name: newName }) }
    ),

  deleteHistory: (filename: string) =>
    requestToPort<{ success: boolean; filename: string }>(
      port,
      '/api/commands/history/delete',
      { method: 'POST', body: JSON.stringify({ filename }) }
    ),

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

  copy: (sourcePath: string, targetPath: string) =>
    request<{ success: boolean; source_path: string; target_path: string }>(
      '/api/files/copy',
      {
        method: 'POST',
        body: JSON.stringify({ source_path: sourcePath, target_path: targetPath }),
      }
    ),

  move: (sourcePath: string, targetPath: string) =>
    request<{ success: boolean; source_path: string; target_path: string }>(
      '/api/files/move',
      {
        method: 'POST',
        body: JSON.stringify({ source_path: sourcePath, target_path: targetPath }),
      }
    ),

  openLocation: (path: string) =>
    request<{ success: boolean; path: string }>(
      '/api/files/open-location',
      { method: 'POST', body: JSON.stringify({ path }) }
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

// Settings API（设置管理，只在主后端）
export const settingsApi = {
  // 获取所有角色列表
  listCharacters: () =>
    request<{
      success: boolean;
      enabled: boolean;
      characters: Array<{ name: string; path: string }>;
      current: string | null;
      error?: string;
      debug?: {
        characters_root: string | null;
        characters_count: number;
        exists: boolean;
      };
    }>('/api/settings/characters/list'),

  // 选择角色
  selectCharacter: (characterName: string) =>
    request<{ success: boolean; message?: string; error?: string }>(
      '/api/settings/characters/select',
      {
        method: 'POST',
        body: JSON.stringify({ character_name: characterName }),
      }
    ),

  // 移除当前角色
  removeCharacter: () =>
    request<{ success: boolean; message?: string; error?: string }>(
      '/api/settings/characters/remove',
      {
        method: 'POST',
      }
    ),

  // 获取设置
  getSettings: () =>
    request<{
      success: boolean;
      settings: {
        enable_characters: boolean;
        default_character: string;
        character_recommend_interval: number;
        context_mode: string;
        max_output_tokens: number;
      };
      error?: string;
    }>('/api/settings/settings'),

  // 更新设置
  updateSettings: (settings: {
    enable_characters?: boolean;
    default_character?: string;
  }) =>
    request<{ success: boolean; message?: string; error?: string }>(
      '/api/settings/settings/update',
      {
        method: 'POST',
        body: JSON.stringify(settings),
      }
    ),

  openEnvFile: () =>
    request<{ success: boolean; path?: string; error?: string }>(
      '/api/settings/env/open',
      { method: 'POST' }
    ),

  applyEnvFile: () =>
    request<{
      success: boolean;
      context_mode?: string;
      tool_names?: string[];
      restarted_chat_process?: boolean;
      message?: string;
      error?: string;
    }>('/api/settings/env/apply', { method: 'POST' }),

  listConfigProfiles: () =>
    request<{
      success: boolean;
      profiles: Array<{
        id: string;
        name: string;
        description?: string;
        values: Record<string, string>;
        keys: string[];
        is_active: boolean;
        created_at: number;
        updated_at: number;
      }>;
      active_profile_id: string | null;
      storage_path?: string;
      env_keys?: string[];
      error?: string;
    }>('/api/settings/profiles/list'),

  saveConfigProfile: (profile: {
    name: string;
    values: Record<string, string>;
    profile_id?: string;
    description?: string;
  }) =>
    request<{
      success: boolean;
      profile?: {
        id: string;
        name: string;
        description?: string;
        values: Record<string, string>;
        created_at: number;
        updated_at: number;
      };
      error?: string;
    }>('/api/settings/profiles/save', {
      method: 'POST',
      body: JSON.stringify(profile),
    }),

  applyConfigProfile: (profileId: string) =>
    request<{
      success: boolean;
      profile?: {
        id: string;
        name: string;
        description?: string;
        values: Record<string, string>;
      };
      env_values?: Record<string, string>;
      context_mode?: string;
      tool_names?: string[];
      restarted_chat_process?: boolean;
      message?: string;
      error?: string;
    }>('/api/settings/profiles/apply', {
      method: 'POST',
      body: JSON.stringify({ profile_id: profileId }),
    }),

  deleteConfigProfile: (profileId: string) =>
    request<{ success: boolean; error?: string }>(
      `/api/settings/profiles/${encodeURIComponent(profileId)}`,
      { method: 'DELETE' }
    ),
};

// Health check
export const healthCheck = (port = 8765) =>
  requestToPort<{ status: string; initialized: boolean }>(port, '/health');

export { ApiError, requestToPort };
