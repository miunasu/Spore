/**
 * 命令菜单组件 - 现代化设计
 */
import React, { useState, useEffect } from 'react';
import { useChatStore } from '../../stores/chatStore';
import { useSettingsStore } from '../../stores/settingsStore';
import { commandsApi, filesApi, settingsApi, backupApi, ApiError } from '../../services/api';
import { useT } from '../../i18n';

interface MenuItem {
  id: string;
  label: string;
  icon: string;
  action: () => Promise<void>;
}

interface CommandMenuProps {
  vertical?: boolean;
  /** mini 模式：窗口窄小，菜单右对齐弹出并限制高度（可滚动） */
  mini?: boolean;
}

// ENV 配置项定义
interface EnvConfigItem {
  key: string;
  label: string;
  type: 'text' | 'select' | 'number' | 'boolean';
  options?: { value: string; label: string }[];
  placeholder?: string;
  description?: string;
}

interface ConfigProfile {
  id: string;
  name: string;
  description?: string;
  values: Record<string, string>;
  keys: string[];
  is_active: boolean;
  created_at: number;
  updated_at: number;
}

// 备份回滚：对话点快照
interface CheckpointInfo {
  id: string;
  ts: string;
  kind?: 'user_message' | 'action' | string;
  message_count: number;
  llm_reply_count: number;
  reply_preview?: string;
  files: Record<string, number>;
}

// 备份回滚：文件版本历史
interface FileBackupVersion {
  id: number;
  ts: string;
  op: string;
  store: string;
  size: number;
}

interface FileBackupHistory {
  path: string;
  has_baseline: boolean;
  versions: FileBackupVersion[];
}

const MAIN_SDK_PROFILE_KEYS = {
  openai: [
    'OPENAI_API_KEY',
    'OPENAI_API_URL',
    'OPENAI_MODEL',
    'USE_RESPONSES_API',
    'OPENAI_REASONING_EFFORT',
  ],
  anthropic: [
    'ANTHROPIC_API_KEY',
    'ANTHROPIC_API_URL',
    'ANTHROPIC_MODEL',
    'ANTHROPIC_EFFORT',
    'ANTHROPIC_THINKING_MODE',
    'ANTHROPIC_THINKING_BUDGET_TOKENS',
  ],
} as const;

const SUB_AGENT_SDK_PROFILE_KEYS = {
  openai: [
    'SUB_AGENT_OPENAI_API_KEY',
    'SUB_AGENT_OPENAI_API_URL',
    'SUB_AGENT_OPENAI_MODEL',
  ],
  anthropic: [
    'SUB_AGENT_ANTHROPIC_API_KEY',
    'SUB_AGENT_ANTHROPIC_API_URL',
    'SUB_AGENT_ANTHROPIC_MODEL',
  ],
} as const;

const COMMON_PROFILE_KEYS = [
  'LLM_STREAM_ENABLED',
  'CLEAN_SDK_HEADERS',
  'SYSTEM_AS_USER',
  'SYSTEM_PROMPT_FILE',
  'MAX_OUTPUT_TOKENS',
  'CONTEXT_MAX_TOKENS',
  'CONTEXT_WARNING_THRESHOLD',
  'MAX_SINGLE_MESSAGE_RATIO',
  'API_TIMEOUT',
] as const;

const ANTHROPIC_COMPAT_PROFILE_KEYS = [
  'CLEAN_AUTH_HEADER',
] as const;

// AutoAgent 颗粒化基座的全部 env key（子 Agent + 4 个 AutoAgent，openai/anthropic 两套）
// appendValue 会跳过空值，所以两套变体全列出是安全的
const AGENT_BASE_PROFILE_KEYS = (() => {
  const prefixes = ['SUB_AGENT', 'AGENT_SUPERVISOR', 'AGENT_MODE_SELECTOR', 'AGENT_SECURITY'];
  const suffixes = [
    'LLM_SDK',
    'OPENAI_API_KEY', 'OPENAI_API_URL', 'OPENAI_MODEL',
    'ANTHROPIC_API_KEY', 'ANTHROPIC_API_URL', 'ANTHROPIC_MODEL',
    // 高级参数
    'USE_RESPONSES_API', 'OPENAI_REASONING_EFFORT',
    'ANTHROPIC_EFFORT', 'ANTHROPIC_THINKING_MODE', 'ANTHROPIC_THINKING_BUDGET_TOKENS',
  ];
  return prefixes.flatMap((p) => suffixes.map((s) => `${p}_${s}`));
})();

// ENV 配置分组
// basic: 最小可用配置（能连上模型即可跑）
// advanced: 其余调优/兼容/资源/路径等，UI 中默认折叠
type EnvConfigGroup = { title: string; items: EnvConfigItem[] };

// 注：数据中的 label/description/placeholder/option.label 存 i18n key，渲染处用 t() 翻译；
// title 保持中文（同时用作 React key、语义过滤逻辑的标识符，见 _advGroupsByTitle / startsWith）。
// 纯技术字面量（如 'OpenAI SDK'、'low'）直接保留，t() 找不到 key 时会原样回退。
const ENV_BASIC_CONFIG_GROUPS: EnvConfigGroup[] = [
  {
    title: 'LLM SDK 选择',
    items: [
      {
        key: 'LLM_SDK',
        label: 'commandMenu.env.LLM_SDK.label',
        type: 'select',
        options: [
          { value: 'openai', label: 'OpenAI SDK' },
          { value: 'anthropic', label: 'Anthropic SDK' },
        ],
        description: 'commandMenu.env.LLM_SDK.desc',
        placeholder: 'commandMenu.env.LLM_SDK.ph',
      },
    ],
  },
  {
    title: 'OpenAI API',
    items: [
      { key: 'OPENAI_API_KEY', label: 'API Key', type: 'text', placeholder: 'commandMenu.env.OPENAI_API_KEY.ph' },
      {
        key: 'OPENAI_API_URL',
        label: 'API URL',
        type: 'text',
        placeholder: 'commandMenu.env.OPENAI_API_URL.ph',
      },
      { key: 'OPENAI_MODEL', label: 'commandMenu.env.OPENAI_MODEL.label', type: 'text', placeholder: 'commandMenu.env.OPENAI_MODEL.ph' },
    ],
  },
  {
    title: 'Anthropic API',
    items: [
      { key: 'ANTHROPIC_API_KEY', label: 'API Key', type: 'text', placeholder: 'commandMenu.env.ANTHROPIC_API_KEY.ph' },
      {
        key: 'ANTHROPIC_API_URL',
        label: 'API URL',
        type: 'text',
        placeholder: 'commandMenu.env.ANTHROPIC_API_URL.ph',
      },
      {
        key: 'ANTHROPIC_MODEL',
        label: 'commandMenu.env.ANTHROPIC_MODEL.label',
        type: 'text',
        placeholder: 'commandMenu.env.ANTHROPIC_MODEL.ph',
      },
    ],
  },
  {
    title: 'OpenAI 高级',
    items: [
      {
        key: 'USE_RESPONSES_API',
        label: 'commandMenu.env.USE_RESPONSES_API.label',
        type: 'select',
        options: [
          { value: 'true', label: 'common.yes' },
          { value: 'false', label: 'common.no' },
        ],
        placeholder: 'commandMenu.env.USE_RESPONSES_API.ph',
      },
      {
        key: 'OPENAI_REASONING_EFFORT',
        label: 'Reasoning Effort',
        type: 'select',
        options: [
          { value: 'low', label: 'low' },
          { value: 'medium', label: 'medium' },
          { value: 'high', label: 'high' },
          { value: 'xhigh', label: 'xhigh' },
        ],
        placeholder: 'commandMenu.env.OPENAI_REASONING_EFFORT.ph',
      },
    ],
  },
  {
    title: 'Anthropic 高级',
    items: [
      {
        key: 'ANTHROPIC_EFFORT',
        label: 'Thinking Effort',
        type: 'select',
        options: [
          { value: 'low', label: 'low' },
          { value: 'medium', label: 'medium' },
          { value: 'high', label: 'high' },
          { value: 'xhigh', label: 'xhigh' },
          { value: 'max', label: 'max' },
        ],
        placeholder: 'commandMenu.env.ANTHROPIC_EFFORT.ph',
        description: 'commandMenu.env.ANTHROPIC_EFFORT.desc',
      },
      {
        key: 'ANTHROPIC_THINKING_MODE',
        label: 'Thinking Mode',
        type: 'select',
        options: [
          { value: 'adaptive', label: 'commandMenu.opts.adaptiveRecommended' },
          { value: 'enabled', label: 'commandMenu.opts.enabledManual' },
          { value: 'disabled', label: 'disabled' },
        ],
        placeholder: 'commandMenu.env.ANTHROPIC_THINKING_MODE.ph',
        description: 'commandMenu.env.ANTHROPIC_THINKING_MODE.desc',
      },
      {
        key: 'ANTHROPIC_THINKING_BUDGET_TOKENS',
        label: 'Thinking Budget Tokens',
        type: 'text',
        placeholder: 'commandMenu.env.ANTHROPIC_THINKING_BUDGET_TOKENS.ph',
        description: 'commandMenu.env.ANTHROPIC_THINKING_BUDGET_TOKENS.desc',
      },
    ],
  },
];

const ENV_ADVANCED_CONFIG_GROUPS: EnvConfigGroup[] = [
  {
    title: 'LLM 参数',
    items: [
      {
        key: 'LLM_STREAM_ENABLED',
        label: 'commandMenu.env.LLM_STREAM_ENABLED.label',
        type: 'select',
        options: [
          { value: 'true', label: 'common.yes' },
          { value: 'false', label: 'common.no' },
        ],
        placeholder: 'commandMenu.env.LLM_STREAM_ENABLED.ph',
        description: 'commandMenu.env.LLM_STREAM_ENABLED.desc',
      },
      {
        key: 'MAX_OUTPUT_TOKENS',
        label: 'commandMenu.env.MAX_OUTPUT_TOKENS.label',
        type: 'text',
        placeholder: 'commandMenu.env.MAX_OUTPUT_TOKENS.ph',
        description: 'commandMenu.env.MAX_OUTPUT_TOKENS.desc',
      },
      {
        key: 'CONTEXT_MAX_TOKENS',
        label: 'commandMenu.env.CONTEXT_MAX_TOKENS.label',
        type: 'text',
        placeholder: 'commandMenu.env.CONTEXT_MAX_TOKENS.ph',
      },
      {
        key: 'CONTEXT_WARNING_THRESHOLD',
        label: 'commandMenu.env.CONTEXT_WARNING_THRESHOLD.label',
        type: 'text',
        placeholder: 'commandMenu.env.CONTEXT_WARNING_THRESHOLD.ph',
        description: 'commandMenu.env.CONTEXT_WARNING_THRESHOLD.desc',
      },
      {
        key: 'MAX_SINGLE_MESSAGE_RATIO',
        label: 'commandMenu.env.MAX_SINGLE_MESSAGE_RATIO.label',
        type: 'text',
        placeholder: 'commandMenu.env.MAX_SINGLE_MESSAGE_RATIO.ph',
        description: 'commandMenu.env.MAX_SINGLE_MESSAGE_RATIO.desc',
      },
      {
        key: 'API_TIMEOUT',
        label: 'commandMenu.env.API_TIMEOUT.label',
        type: 'text',
        placeholder: 'commandMenu.env.API_TIMEOUT.ph',
      },
    ],
  },
  {
    title: 'SDK 兼容性',
    items: [
      {
        key: 'CLEAN_SDK_HEADERS',
        label: 'commandMenu.env.CLEAN_SDK_HEADERS.label',
        type: 'select',
        options: [
          { value: 'true', label: 'common.yes' },
          { value: 'false', label: 'common.no' },
        ],
        description: 'commandMenu.env.CLEAN_SDK_HEADERS.desc',
        placeholder: 'commandMenu.env.CLEAN_SDK_HEADERS.ph',
      },
      {
        key: 'CLEAN_AUTH_HEADER',
        label: 'commandMenu.env.CLEAN_AUTH_HEADER.label',
        type: 'select',
        options: [
          { value: 'true', label: 'common.yes' },
          { value: 'false', label: 'common.no' },
        ],
        description: 'commandMenu.env.CLEAN_AUTH_HEADER.desc',
        placeholder: 'commandMenu.env.CLEAN_AUTH_HEADER.ph',
      },
      {
        key: 'SYSTEM_AS_USER',
        label: 'commandMenu.env.SYSTEM_AS_USER.label',
        type: 'select',
        options: [
          { value: 'true', label: 'common.yes' },
          { value: 'false', label: 'common.no' },
        ],
        description: 'commandMenu.env.SYSTEM_AS_USER.desc',
        placeholder: 'commandMenu.env.SYSTEM_AS_USER.ph',
      },
      {
        key: 'SYSTEM_PROMPT_FILE',
        label: 'commandMenu.env.SYSTEM_PROMPT_FILE.label',
        type: 'text',
        placeholder: 'commandMenu.env.SYSTEM_PROMPT_FILE.ph',
        description: 'commandMenu.env.SYSTEM_PROMPT_FILE.desc',
      },
    ],
  },
  {
    title: '对话管理',
    items: [
      {
        key: 'CONTEXT_MODE',
        label: 'commandMenu.env.CONTEXT_MODE.label',
        type: 'select',
        options: [
          { value: 'strong_context', label: 'commandMenu.env.CONTEXT_MODE.opts.strong' },
          { value: 'long_context', label: 'commandMenu.env.CONTEXT_MODE.opts.long' },
          { value: 'auto', label: 'commandMenu.env.CONTEXT_MODE.opts.auto' },
        ],
        placeholder: 'commandMenu.env.CONTEXT_MODE.ph',
        description: 'commandMenu.env.CONTEXT_MODE.desc',
      },
      {
        key: 'DEFAULT_CHARACTER',
        label: 'commandMenu.env.DEFAULT_CHARACTER.label',
        type: 'text',
        placeholder: 'commandMenu.env.DEFAULT_CHARACTER.ph',
      },
      {
        key: 'RULE_REMINDER_INTERVAL',
        label: 'commandMenu.env.RULE_REMINDER_INTERVAL.label',
        type: 'text',
        placeholder: 'commandMenu.env.RULE_REMINDER_INTERVAL.ph',
        description: 'commandMenu.env.RULE_REMINDER_INTERVAL.desc',
      },
      {
        key: 'RULE_REMINDER_SHORT',
        label: 'commandMenu.env.RULE_REMINDER_SHORT.label',
        type: 'select',
        options: [
          { value: 'true', label: 'common.yes' },
          { value: 'false', label: 'common.no' },
        ],
        placeholder: 'commandMenu.env.RULE_REMINDER_SHORT.ph',
        description: 'commandMenu.env.RULE_REMINDER_SHORT.desc',
      },
      {
        key: 'LIMIT_WRITE_TOOL_RETURN',
        label: 'commandMenu.env.LIMIT_WRITE_TOOL_RETURN.label',
        type: 'select',
        options: [
          { value: 'true', label: 'common.yes' },
          { value: 'false', label: 'common.no' },
        ],
        placeholder: 'commandMenu.env.LIMIT_WRITE_TOOL_RETURN.ph',
        description: 'commandMenu.env.LIMIT_WRITE_TOOL_RETURN.desc',
      },
    ],
  },
  {
    title: '日志配置',
    items: [
      {
        key: 'LOG_TO_FILE',
        label: 'commandMenu.env.LOG_TO_FILE.label',
        type: 'select',
        options: [
          { value: 'true', label: 'common.yes' },
          { value: 'false', label: 'common.no' },
        ],
        placeholder: 'commandMenu.env.LOG_TO_FILE.ph',
      },
      {
        key: 'LOG_FILE_MAX_SIZE',
        label: 'commandMenu.env.LOG_FILE_MAX_SIZE.label',
        type: 'text',
        placeholder: 'commandMenu.env.LOG_FILE_MAX_SIZE.ph',
      },
      {
        key: 'LOG_BACKUP_COUNT',
        label: 'commandMenu.env.LOG_BACKUP_COUNT.label',
        type: 'text',
        placeholder: 'commandMenu.env.LOG_BACKUP_COUNT.ph',
      },
      {
        key: 'LOG_MONITOR_MAX_LINE_LENGTH',
        label: 'commandMenu.env.LOG_MONITOR_MAX_LINE_LENGTH.label',
        type: 'text',
        placeholder: 'commandMenu.env.LOG_MONITOR_MAX_LINE_LENGTH.ph',
      },
      { key: 'LOG_ERROR_FILENAME', label: 'commandMenu.env.LOG_ERROR_FILENAME.label', type: 'text', placeholder: 'commandMenu.env.LOG_ERROR_FILENAME.ph' },
      { key: 'LOG_LLM_VALIDATION_FILENAME', label: 'commandMenu.env.LOG_LLM_VALIDATION_FILENAME.label', type: 'text', placeholder: 'commandMenu.env.LOG_LLM_VALIDATION_FILENAME.ph' },
      { key: 'LOG_TOOL_EXECUTION_FILENAME', label: 'commandMenu.env.LOG_TOOL_EXECUTION_FILENAME.label', type: 'text', placeholder: 'commandMenu.env.LOG_TOOL_EXECUTION_FILENAME.ph' },
      { key: 'LOG_GENERAL_FILENAME', label: 'commandMenu.env.LOG_GENERAL_FILENAME.label', type: 'text', placeholder: 'commandMenu.env.LOG_GENERAL_FILENAME.ph' },
      {
        key: 'LOG_RAW_ENABLED',
        label: 'commandMenu.env.LOG_RAW_ENABLED.label',
        type: 'select',
        options: [
          { value: 'true', label: 'common.yes' },
          { value: 'false', label: 'common.no' },
        ],
        placeholder: 'commandMenu.env.LOG_RAW_ENABLED.ph',
        description: 'commandMenu.env.LOG_RAW_ENABLED.desc',
      },
      { key: 'LOG_RAW_FILENAME', label: 'commandMenu.env.LOG_RAW_FILENAME.label', type: 'text', placeholder: 'commandMenu.env.LOG_RAW_FILENAME.ph' },
      { key: 'LOG_MONITOR_LOCK_FILENAME', label: 'commandMenu.env.LOG_MONITOR_LOCK_FILENAME.label', type: 'text', placeholder: 'commandMenu.env.LOG_MONITOR_LOCK_FILENAME.ph' },
      { key: 'LOG_MONITOR_CHECK_INTERVAL', label: 'commandMenu.env.LOG_MONITOR_CHECK_INTERVAL.label', type: 'text', placeholder: 'commandMenu.env.LOG_MONITOR_CHECK_INTERVAL.ph' },
      {
        key: 'LOG_MONITOR_TYPES',
        label: 'commandMenu.env.LOG_MONITOR_TYPES.label',
        type: 'text',
        placeholder: 'commandMenu.env.LOG_MONITOR_TYPES.ph',
      },
    ],
  },
  {
    title: '工具配置',
    items: [
      {
        key: 'WEB_BROWSER_TIMEOUT',
        label: 'commandMenu.env.WEB_BROWSER_TIMEOUT.label',
        type: 'text',
        placeholder: 'commandMenu.env.WEB_BROWSER_TIMEOUT.ph',
      },
      {
        key: 'WEB_PROXY_PORT',
        label: 'commandMenu.env.WEB_PROXY_PORT.label',
        type: 'text',
        placeholder: 'commandMenu.env.WEB_PROXY_PORT.ph',
      },
      {
        key: 'WEB_MAX_CONTENT_LENGTH',
        label: 'commandMenu.env.WEB_MAX_CONTENT_LENGTH.label',
        type: 'text',
        placeholder: 'commandMenu.env.WEB_MAX_CONTENT_LENGTH.ph',
      },
      {
        key: 'TOOL_EXECUTION_TIMEOUT',
        label: 'commandMenu.env.TOOL_EXECUTION_TIMEOUT.label',
        type: 'text',
        placeholder: 'commandMenu.env.TOOL_EXECUTION_TIMEOUT.ph',
      },
      {
        key: 'SHELL_COMMAND_TIMEOUT',
        label: 'commandMenu.env.SHELL_COMMAND_TIMEOUT.label',
        type: 'text',
        placeholder: 'commandMenu.env.SHELL_COMMAND_TIMEOUT.ph',
      },
    ],
  },
  {
    title: '多 Agent 配置',
    items: [
      {
        key: 'MULTI_AGENT_MAX_COUNT',
        label: 'commandMenu.env.MULTI_AGENT_MAX_COUNT.label',
        type: 'text',
        placeholder: 'commandMenu.env.MULTI_AGENT_MAX_COUNT.ph',
      },
      {
        key: 'SUB_AGENT_MAX_ITERATIONS',
        label: 'commandMenu.env.SUB_AGENT_MAX_ITERATIONS.label',
        type: 'text',
        placeholder: 'commandMenu.env.SUB_AGENT_MAX_ITERATIONS.ph',
      },
      {
        key: 'CODER_MAX_ITERATIONS',
        label: 'commandMenu.env.CODER_MAX_ITERATIONS.label',
        type: 'text',
        placeholder: 'commandMenu.env.CODER_MAX_ITERATIONS.ph',
      },
      {
        key: 'MULTI_AGENT_TIMEOUT',
        label: 'commandMenu.env.MULTI_AGENT_TIMEOUT.label',
        type: 'text',
        placeholder: 'commandMenu.env.MULTI_AGENT_TIMEOUT.ph',
        description: 'commandMenu.env.MULTI_AGENT_TIMEOUT.desc',
      },
      {
        key: 'MULTI_AGENT_JOIN_INTERVAL',
        label: 'commandMenu.env.MULTI_AGENT_JOIN_INTERVAL.label',
        type: 'text',
        placeholder: 'commandMenu.env.MULTI_AGENT_JOIN_INTERVAL.ph',
        description: 'commandMenu.env.MULTI_AGENT_JOIN_INTERVAL.desc',
      },
      {
        key: 'MULTI_AGENT_MONITOR_ENABLED',
        label: 'commandMenu.env.MULTI_AGENT_MONITOR_ENABLED.label',
        type: 'select',
        options: [
          { value: 'true', label: 'common.yes' },
          { value: 'false', label: 'common.no' },
        ],
        placeholder: 'commandMenu.env.MULTI_AGENT_MONITOR_ENABLED.ph',
      },
    ],
  },
  {
    title: 'Chat 进程配置',
    items: [
      {
        key: 'CHAT_MAX_WORKERS',
        label: 'commandMenu.env.CHAT_MAX_WORKERS.label',
        type: 'text',
        placeholder: 'commandMenu.env.CHAT_MAX_WORKERS.ph',
      },
      {
        key: 'CHAT_RESPONSE_EXPIRE',
        label: 'commandMenu.env.CHAT_RESPONSE_EXPIRE.label',
        type: 'text',
        placeholder: 'commandMenu.env.CHAT_RESPONSE_EXPIRE.ph',
      },
      {
        key: 'CHAT_RESPONSE_CLEANUP_INTERVAL',
        label: 'commandMenu.env.CHAT_RESPONSE_CLEANUP_INTERVAL.label',
        type: 'text',
        placeholder: 'commandMenu.env.CHAT_RESPONSE_CLEANUP_INTERVAL.ph',
      },
      {
        key: 'IPC_CHECK_INTERVAL',
        label: 'commandMenu.env.IPC_CHECK_INTERVAL.label',
        type: 'text',
        placeholder: 'commandMenu.env.IPC_CHECK_INTERVAL.ph',
      },
    ],
  },
  {
    title: '路径配置',
    items: [
      { key: 'SKILLS_DIR', label: 'commandMenu.env.SKILLS_DIR.label', type: 'text', placeholder: 'commandMenu.env.SKILLS_DIR.ph' },
      { key: 'CHARACTERS_DIR', label: 'commandMenu.env.CHARACTERS_DIR.label', type: 'text', placeholder: 'commandMenu.env.CHARACTERS_DIR.ph' },
      { key: 'PROMPT_DIR', label: 'commandMenu.env.PROMPT_DIR.label', type: 'text', placeholder: 'commandMenu.env.PROMPT_DIR.ph' },
      { key: 'LOG_DIR', label: 'commandMenu.env.LOG_DIR.label', type: 'text', placeholder: 'commandMenu.env.LOG_DIR.ph' },
      { key: 'OUTPUT_DIR', label: 'commandMenu.env.OUTPUT_DIR.label', type: 'text', placeholder: 'commandMenu.env.OUTPUT_DIR.ph' },
      { key: 'UPLOAD_DIR', label: 'commandMenu.env.UPLOAD_DIR.label', type: 'text', placeholder: 'commandMenu.env.UPLOAD_DIR.ph' },
    ],
  },
  {
    title: 'Desktop 启动配置',
    items: [
      {
        key: 'LAUNCH_MODE',
        label: 'commandMenu.env.LAUNCH_MODE.label',
        type: 'select',
        options: [
          { value: 'cli', label: 'CLI' },
          { value: 'desktop', label: 'Desktop' },
        ],
        placeholder: 'commandMenu.env.LAUNCH_MODE.ph',
      },
      { key: 'DESKTOP_API_HOST', label: 'API Host', type: 'text', placeholder: 'commandMenu.env.DESKTOP_API_HOST.ph' },
      { key: 'DESKTOP_API_PORT', label: 'API Port', type: 'text', placeholder: 'commandMenu.env.DESKTOP_API_PORT.ph' },
    ],
  },
  {
    title: '拦截开关',
    items: [
      {
        key: 'COMMAND_INTERCEPT',
        label: 'commandMenu.env.COMMAND_INTERCEPT.label',
        type: 'select',
        options: [
          { value: 'true', label: 'commandMenu.env.COMMAND_INTERCEPT.opts.onRecommended' },
          { value: 'false', label: 'commandMenu.env.COMMAND_INTERCEPT.opts.off' },
        ],
        description: 'commandMenu.env.COMMAND_INTERCEPT.desc',
        placeholder: 'commandMenu.env.COMMAND_INTERCEPT.ph',
      },
      {
        key: 'INTERCEPT_SHELL_DELETE',
        label: 'commandMenu.env.INTERCEPT_SHELL_DELETE.label',
        type: 'select',
        options: [
          { value: 'true', label: 'commandMenu.env.INTERCEPT_SHELL_DELETE.opts.on' },
          { value: 'false', label: 'commandMenu.env.INTERCEPT_SHELL_DELETE.opts.off' },
        ],
        description: 'commandMenu.env.INTERCEPT_SHELL_DELETE.desc',
        placeholder: 'commandMenu.env.INTERCEPT_SHELL_DELETE.ph',
      },
      {
        key: 'INTERCEPT_SHELL_WRITE',
        label: 'commandMenu.env.INTERCEPT_SHELL_WRITE.label',
        type: 'select',
        options: [
          { value: 'true', label: 'commandMenu.env.INTERCEPT_SHELL_WRITE.opts.on' },
          { value: 'false', label: 'commandMenu.env.INTERCEPT_SHELL_WRITE.opts.off' },
        ],
        description: 'commandMenu.env.INTERCEPT_SHELL_WRITE.desc',
        placeholder: 'commandMenu.env.INTERCEPT_SHELL_WRITE.ph',
      },
    ],
  },
  {
    title: '备份恢复',
    items: [
      {
        key: 'BACKUP_ENABLED',
        label: 'commandMenu.env.BACKUP_ENABLED.label',
        type: 'select',
        options: [
          { value: 'true', label: 'commandMenu.env.BACKUP_ENABLED.opts.onRecommended' },
          { value: 'false', label: 'commandMenu.env.BACKUP_ENABLED.opts.off' },
        ],
        description: 'commandMenu.env.BACKUP_ENABLED.desc',
        placeholder: 'commandMenu.env.BACKUP_ENABLED.ph',
      },
      {
        key: 'BACKUP_DIR',
        label: 'commandMenu.env.BACKUP_DIR.label',
        type: 'text',
        description: 'commandMenu.env.BACKUP_DIR.desc',
        placeholder: 'commandMenu.env.BACKUP_DIR.ph',
      },
      {
        key: 'BACKUP_MAX_FILE_BYTES',
        label: 'commandMenu.env.BACKUP_MAX_FILE_BYTES.label',
        type: 'number',
        description: 'commandMenu.env.BACKUP_MAX_FILE_BYTES.desc',
        placeholder: 'commandMenu.env.BACKUP_MAX_FILE_BYTES.ph',
      },
      {
        key: 'BACKUP_MAX_DELETE_FILES',
        label: 'commandMenu.env.BACKUP_MAX_DELETE_FILES.label',
        type: 'number',
        description: 'commandMenu.env.BACKUP_MAX_DELETE_FILES.desc',
        placeholder: 'commandMenu.env.BACKUP_MAX_DELETE_FILES.ph',
      },
    ],
  },
  {
    title: '安全 Agent',
    items: [
      {
        key: 'SECURITY_AGENT_MODE',
        label: 'commandMenu.env.SECURITY_AGENT_MODE.label',
        type: 'select',
        options: [
          { value: 'off', label: 'commandMenu.env.SECURITY_AGENT_MODE.opts.off' },
          { value: 'basic', label: 'commandMenu.env.SECURITY_AGENT_MODE.opts.basic' },
          { value: 'full', label: 'commandMenu.env.SECURITY_AGENT_MODE.opts.full' },
        ],
        description: 'commandMenu.env.SECURITY_AGENT_MODE.desc',
        placeholder: 'commandMenu.env.SECURITY_AGENT_MODE.ph',
      },
      {
        key: 'SECURITY_GUARD_MODE',
        label: 'commandMenu.env.SECURITY_GUARD_MODE.label',
        type: 'select',
        options: [
          { value: 'strict', label: 'commandMenu.env.SECURITY_GUARD_MODE.opts.strict' },
          { value: 'balanced', label: 'commandMenu.env.SECURITY_GUARD_MODE.opts.balanced' },
          { value: 'permissive', label: 'commandMenu.env.SECURITY_GUARD_MODE.opts.permissive' },
        ],
        description: 'commandMenu.env.SECURITY_GUARD_MODE.desc',
        placeholder: 'commandMenu.env.SECURITY_GUARD_MODE.ph',
      },
      {
        key: 'SECURITY_LLM_TIMEOUT',
        label: 'commandMenu.env.SECURITY_LLM_TIMEOUT.label',
        type: 'number',
        description: 'commandMenu.env.SECURITY_LLM_TIMEOUT.desc',
        placeholder: 'commandMenu.env.SECURITY_LLM_TIMEOUT.ph',
      },
      {
        key: 'SECURITY_INTENT_TIMEOUT',
        label: 'commandMenu.env.SECURITY_INTENT_TIMEOUT.label',
        type: 'number',
        description: 'commandMenu.env.SECURITY_INTENT_TIMEOUT.desc',
        placeholder: 'commandMenu.env.SECURITY_INTENT_TIMEOUT.ph',
      },
      {
        key: 'SECURITY_AGENT_SESSION_CONTEXT',
        label: 'commandMenu.env.SECURITY_AGENT_SESSION_CONTEXT.label',
        type: 'select',
        options: [
          { value: 'true', label: 'commandMenu.env.SECURITY_AGENT_SESSION_CONTEXT.opts.on' },
          { value: 'false', label: 'commandMenu.env.SECURITY_AGENT_SESSION_CONTEXT.opts.off' },
        ],
        description: 'commandMenu.env.SECURITY_AGENT_SESSION_CONTEXT.desc',
        placeholder: 'commandMenu.env.SECURITY_AGENT_SESSION_CONTEXT.ph',
      },
      {
        key: 'SECURITY_SESSION_CONTEXT_MAX_COMMANDS',
        label: 'commandMenu.env.SECURITY_SESSION_CONTEXT_MAX_COMMANDS.label',
        type: 'number',
        description: 'commandMenu.env.SECURITY_SESSION_CONTEXT_MAX_COMMANDS.desc',
        placeholder: 'commandMenu.env.SECURITY_SESSION_CONTEXT_MAX_COMMANDS.ph',
      },
    ],
  },
];

// 分组标题 → i18n key 映射（title 本身仍是逻辑标识符，渲染时经此翻译）
const GROUP_TITLE_I18N: Record<string, string> = {
  'LLM SDK 选择': 'commandMenu.groups.llmSdk',
  'OpenAI API': 'commandMenu.groups.openaiApi',
  'Anthropic API': 'commandMenu.groups.anthropicApi',
  'OpenAI 高级': 'commandMenu.groups.openaiAdvanced',
  'Anthropic 高级': 'commandMenu.groups.anthropicAdvanced',
  'LLM 参数': 'commandMenu.groups.llmParams',
  'SDK 兼容性': 'commandMenu.groups.sdkCompat',
  '对话管理': 'commandMenu.groups.conversation',
  '日志配置': 'commandMenu.groups.logging',
  '工具配置': 'commandMenu.groups.tools',
  '多 Agent 配置': 'commandMenu.groups.multiAgent',
  'Chat 进程配置': 'commandMenu.groups.chatProcess',
  '路径配置': 'commandMenu.groups.paths',
  'Desktop 启动配置': 'commandMenu.groups.desktop',
  '拦截开关': 'commandMenu.groups.intercept',
  '备份恢复': 'commandMenu.groups.backup',
  '安全 Agent': 'commandMenu.groups.securityAgent',
};

// 环境配置分组按语义拆到三个设置标签（LLM / Agent / 系统）
const _advGroupsByTitle = (titles: string[]): EnvConfigGroup[] =>
  ENV_ADVANCED_CONFIG_GROUPS.filter((g) => titles.includes(g.title));

// LLM 标签的高级组（基础 SDK/API 组仍用 ENV_BASIC_CONFIG_GROUPS 单独渲染）
const LLM_ADVANCED_GROUPS = _advGroupsByTitle(['LLM 参数', 'SDK 兼容性']);
// Agent 标签的组（另有 Agent 基座颗粒化编辑器单独渲染）
const AGENT_ENV_GROUPS = _advGroupsByTitle(['对话管理', '多 Agent 配置', '安全 Agent', '拦截开关']);
// 系统标签的组（基础设施/环境）
const SYSTEM_ENV_GROUPS = _advGroupsByTitle([
  '工具配置', '日志配置', '路径配置', 'Chat 进程配置', 'Desktop 启动配置', '备份恢复',
]);

// 普通配置分组渲染（select/input），LLM 高级 / Agent / 系统三处共用
const EnvGroupFields: React.FC<{
  group: EnvConfigGroup;
  envValues: Record<string, string>;
  updateEnvValue: (key: string, value: string) => void;
}> = ({ group, envValues, updateEnvValue }) => {
  const t = useT();
  return (
  <div className="space-y-3">
    <h5 className="text-sm font-medium text-spore-highlight border-b border-spore-border/30 pb-2">
      {t(GROUP_TITLE_I18N[group.title] || group.title)}
    </h5>
    <div className="space-y-3">
      {group.items.map((item) => (
        <div key={item.key} className="space-y-1">
          <label className="flex items-center gap-2 text-xs text-spore-muted">
            <span>{t(item.label)}</span>
            {item.description && (
              <span className="text-spore-muted/60">({t(item.description)})</span>
            )}
          </label>
          {item.type === 'select' ? (
            <select
              value={envValues[item.key] || ''}
              onChange={(e) => updateEnvValue(item.key, e.target.value)}
              className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50"
            >
              <option value="">{item.placeholder ? t(item.placeholder) : t('commandMenu.env.notSet')}</option>
              {item.options?.map((opt) => (
                <option key={opt.value} value={opt.value}>{t(opt.label)}</option>
              ))}
            </select>
          ) : (
            <input
              type={item.type === 'number' ? 'number' : 'text'}
              value={envValues[item.key] || ''}
              onChange={(e) => updateEnvValue(item.key, e.target.value)}
              placeholder={item.placeholder ? t(item.placeholder) : undefined}
              className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50 font-mono"
            />
          )}
        </div>
      ))}
    </div>
  </div>
  );
};

// Agent 基座配置目标：子 Agent 是所有 AutoAgent 的默认基座，
// 其余 4 个 AutoAgent 可各自覆盖（字段留空则回退到子 Agent → 主 Agent）
type AgentBaseTarget = {
  id: string;
  label: string;
  prefix: string; // env key 前缀
  hint: string;
};

const AGENT_BASE_TARGETS: AgentBaseTarget[] = [
  { id: 'sub_agent', label: 'commandMenu.agentBase.targets.subAgentLabel', prefix: 'SUB_AGENT', hint: 'commandMenu.agentBase.targets.subAgentHint' },
  { id: 'supervisor', label: 'commandMenu.agentBase.targets.supervisorLabel', prefix: 'AGENT_SUPERVISOR', hint: 'commandMenu.agentBase.targets.supervisorHint' },
  { id: 'mode_selector', label: 'commandMenu.agentBase.targets.modeSelectorLabel', prefix: 'AGENT_MODE_SELECTOR', hint: 'commandMenu.agentBase.targets.modeSelectorHint' },
  { id: 'security', label: 'commandMenu.agentBase.targets.securityLabel', prefix: 'AGENT_SECURITY', hint: 'commandMenu.agentBase.targets.securityHint' },
];

// 给定配置目标前缀，返回该目标的 env key 集合（基础 + 高级）
const agentBaseKeys = (prefix: string) => ({
  sdk: `${prefix}_LLM_SDK`,
  openaiKey: `${prefix}_OPENAI_API_KEY`,
  openaiUrl: `${prefix}_OPENAI_API_URL`,
  openaiModel: `${prefix}_OPENAI_MODEL`,
  anthropicKey: `${prefix}_ANTHROPIC_API_KEY`,
  anthropicUrl: `${prefix}_ANTHROPIC_API_URL`,
  anthropicModel: `${prefix}_ANTHROPIC_MODEL`,
  // 高级参数
  useResponsesApi: `${prefix}_USE_RESPONSES_API`,
  openaiEffort: `${prefix}_OPENAI_REASONING_EFFORT`,
  anthropicEffort: `${prefix}_ANTHROPIC_EFFORT`,
  thinkingMode: `${prefix}_ANTHROPIC_THINKING_MODE`,
  thinkingBudget: `${prefix}_ANTHROPIC_THINKING_BUDGET_TOKENS`,
});

// Agent 基座（颗粒化）编辑器：下拉切换配置目标，字段按有效 SDK 动态映射
const AgentBaseEditor: React.FC<{
  agentBaseTarget: string;
  setAgentBaseTarget: (id: string) => void;
  envValues: Record<string, string>;
  updateEnvValue: (key: string, value: string) => void;
}> = ({ agentBaseTarget, setAgentBaseTarget, envValues, updateEnvValue }) => {
  const t = useT();
  const target =
    AGENT_BASE_TARGETS.find((tg) => tg.id === agentBaseTarget) || AGENT_BASE_TARGETS[0];
  const keys = agentBaseKeys(target.prefix);
  const targetSdk = (envValues[keys.sdk] || '').toLowerCase();
  const subSdk = (envValues['SUB_AGENT_LLM_SDK'] || '').toLowerCase();
  const mainSdk = (envValues['LLM_SDK'] || '').toLowerCase() || 'openai';
  // 有效 SDK：决定展示哪一套字段（该目标显式选择 → 子 Agent → 主 Agent）
  const effectiveSdk = targetSdk || (target.id !== 'sub_agent' ? subSdk : '') || mainSdk;
  const isAnthropic = effectiveSdk === 'anthropic';
  const inheritHint = target.id === 'sub_agent'
    ? t('commandMenu.agentBase.inheritMain')
    : t('commandMenu.agentBase.inheritSub');
  return (
    <div className="space-y-3">
      <h5 className="text-sm font-medium text-spore-highlight border-b border-spore-border/30 pb-2">
        {t('commandMenu.agentBase.title')}
      </h5>
      <p className="text-[11px] text-spore-muted/70 -mt-1">
        {t('commandMenu.agentBase.intro')}
      </p>
      {/* 配置目标下拉 */}
      <div className="space-y-1">
        <label className="text-xs text-spore-muted">{t('commandMenu.agentBase.target')}</label>
        <select
          value={agentBaseTarget}
          onChange={(e) => setAgentBaseTarget(e.target.value)}
          className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-highlight/40 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/60"
        >
          {AGENT_BASE_TARGETS.map((tg) => (
            <option key={tg.id} value={tg.id}>
              {t(tg.label)}
            </option>
          ))}
        </select>
        <p className="text-[11px] text-spore-muted/70">{t(target.hint)}</p>
      </div>
      {/* SDK 选择 */}
      <div className="space-y-1">
        <label className="text-xs text-spore-muted">{t('commandMenu.agentBase.sdkType')}</label>
        <select
          value={envValues[keys.sdk] || ''}
          onChange={(e) => updateEnvValue(keys.sdk, e.target.value)}
          className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50"
        >
          <option value="">{inheritHint}</option>
          <option value="openai">OpenAI SDK</option>
          <option value="anthropic">Anthropic SDK</option>
        </select>
      </div>
      {/* 按 SDK 动态显示 OpenAI / Anthropic 字段 */}
      {[
        { show: !isAnthropic, label: 'commandMenu.agentBase.openaiKey', k: keys.openaiKey },
        { show: !isAnthropic, label: 'commandMenu.agentBase.openaiUrl', k: keys.openaiUrl },
        { show: !isAnthropic, label: 'commandMenu.agentBase.openaiModel', k: keys.openaiModel },
        { show: isAnthropic, label: 'commandMenu.agentBase.anthropicKey', k: keys.anthropicKey },
        { show: isAnthropic, label: 'commandMenu.agentBase.anthropicUrl', k: keys.anthropicUrl },
        { show: isAnthropic, label: 'commandMenu.agentBase.anthropicModel', k: keys.anthropicModel },
      ]
        .filter((f) => f.show)
        .map((f) => (
          <div key={f.k} className="space-y-1">
            <label className="text-xs text-spore-muted">{t(f.label)}</label>
            <input
              type="text"
              value={envValues[f.k] || ''}
              onChange={(e) => updateEnvValue(f.k, e.target.value)}
              placeholder={inheritHint}
              className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50 font-mono"
            />
          </div>
        ))}
      {/* 高级参数（按有效 SDK 展示；每个目标独立，留空继承上层） */}
      <div className="space-y-3 pt-2 border-t border-spore-border/20">
        <p className="text-[11px] text-spore-muted/70">
          {t('commandMenu.agentBase.advancedParams', { sdk: isAnthropic ? 'Anthropic' : 'OpenAI' })}
        </p>
        {!isAnthropic && (
          <>
            <div className="space-y-1">
              <label className="text-xs text-spore-muted">{t('commandMenu.agentBase.useResponsesApi')}</label>
              <select
                value={envValues[keys.useResponsesApi] || ''}
                onChange={(e) => updateEnvValue(keys.useResponsesApi, e.target.value)}
                className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50"
              >
                <option value="">{inheritHint}</option>
                <option value="true">{t('common.yes')}</option>
                <option value="false">{t('common.no')}</option>
              </select>
            </div>
            <div className="space-y-1">
              <label className="text-xs text-spore-muted">Reasoning Effort</label>
              <select
                value={envValues[keys.openaiEffort] || ''}
                onChange={(e) => updateEnvValue(keys.openaiEffort, e.target.value)}
                className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50"
              >
                <option value="">{inheritHint}</option>
                <option value="none">{t('commandMenu.opts.noneExplicit')}</option>
                {['low', 'medium', 'high', 'xhigh'].map((o) => (
                  <option key={o} value={o}>{o}</option>
                ))}
              </select>
            </div>
          </>
        )}
        {isAnthropic && (
          <>
            <div className="space-y-1">
              <label className="text-xs text-spore-muted">Thinking Effort</label>
              <select
                value={envValues[keys.anthropicEffort] || ''}
                onChange={(e) => updateEnvValue(keys.anthropicEffort, e.target.value)}
                className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50"
              >
                <option value="">{inheritHint}</option>
                <option value="none">{t('commandMenu.opts.noneExplicit')}</option>
                {['low', 'medium', 'high', 'xhigh', 'max'].map((o) => (
                  <option key={o} value={o}>{o}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <label className="text-xs text-spore-muted">Thinking Mode</label>
              <select
                value={envValues[keys.thinkingMode] || ''}
                onChange={(e) => updateEnvValue(keys.thinkingMode, e.target.value)}
                className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50"
              >
                <option value="">{inheritHint}</option>
                <option value="adaptive">{t('commandMenu.opts.adaptiveRecommended')}</option>
                <option value="enabled">{t('commandMenu.opts.enabledManual')}</option>
                <option value="disabled">disabled</option>
              </select>
            </div>
            <div className="space-y-1">
              <label className="text-xs text-spore-muted">Thinking Budget Tokens</label>
              <input
                type="text"
                value={envValues[keys.thinkingBudget] || ''}
                onChange={(e) => updateEnvValue(keys.thinkingBudget, e.target.value)}
                placeholder={inheritHint}
                className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50 font-mono"
              />
            </div>
          </>
        )}
      </div>
    </div>
  );
};

// 解析 .env 内容为对象
const parseEnvContent = (content: string): Record<string, string> => {
  const result: Record<string, string> = {};
  content.split('\n').forEach((line) => {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const eqIndex = trimmed.indexOf('=');
      if (eqIndex > 0) {
        const key = trimmed.slice(0, eqIndex).trim();
        const value = trimmed.slice(eqIndex + 1).trim();
        result[key] = value;
      }
    }
  });
  return result;
};

// 将对象转换回 .env 内容（保留原有注释和结构）
const updateEnvContent = (
  originalContent: string,
  updates: Record<string, string>
): string => {
  const lines = originalContent.split('\n');
  const updatedKeys = new Set<string>();

  // 第一遍：更新已存在的键
  const newLines = lines.map((line) => {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const eqIndex = trimmed.indexOf('=');
      if (eqIndex > 0) {
        const key = trimmed.slice(0, eqIndex).trim();
        if (key in updates) {
          updatedKeys.add(key);
          return `${key}=${updates[key]}`;
        }
      }
    }
    return line;
  });

  // 第二遍：添加新的键（在文件末尾）
  const missingKeys = Object.keys(updates).filter(key => !updatedKeys.has(key));
  if (missingKeys.length > 0) {
    // 确保最后有空行
    if (newLines[newLines.length - 1] !== '') {
      newLines.push('');
    }
    // 添加缺失的键
    missingKeys.forEach(key => {
      newLines.push(`${key}=${updates[key]}`);
    });
  }

  return newLines.join('\n');
};

export const CommandMenu: React.FC<CommandMenuProps> = ({ vertical = false, mini = false }) => {
  const t = useT();
  const [isOpen, setIsOpen] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [settingsTab, setSettingsTab] = useState<'general' | 'llm' | 'agent' | 'system' | 'tools'>('general');
  const [showAdvancedEnv, setShowAdvancedEnv] = useState(false);
  // Agent 基座配置：当前正在编辑的配置目标（子 Agent / 4 个 AutoAgent）
  const [agentBaseTarget, setAgentBaseTarget] = useState<string>('sub_agent');
  const [envContent, setEnvContent] = useState('');
  const [envValues, setEnvValues] = useState<Record<string, string>>({});
  const [envLoading, setEnvLoading] = useState(false);
  const [envSaving, setEnvSaving] = useState(false);
  const [envOpening, setEnvOpening] = useState(false);
  const [envError, setEnvError] = useState<string | null>(null);
  const [configProfiles, setConfigProfiles] = useState<ConfigProfile[]>([]);
  const [activeProfileId, setActiveProfileId] = useState<string>('');
  const [profileBusy, setProfileBusy] = useState(false);
  const [modalContent, setModalContent] = useState<{ title: string; content: string } | null>(null);
  
  // Characters 系统状态
  const [characters, setCharacters] = useState<Array<{ name: string; path: string }>>([]);
  const [currentCharacter, setCurrentCharacter] = useState<string>('');
  const [charactersLoading, setCharactersLoading] = useState(false);

  // 备份回滚状态
  const [showBackup, setShowBackup] = useState(false);
  const [backupTab, setBackupTab] = useState<'checkpoints' | 'files'>('checkpoints');
  const [checkpoints, setCheckpoints] = useState<CheckpointInfo[]>([]);
  const [trackedFiles, setTrackedFiles] = useState<string[]>([]);
  const [fileHistory, setFileHistory] = useState<FileBackupHistory | null>(null);
  const [backupLoading, setBackupLoading] = useState(false);
  const [backupBusy, setBackupBusy] = useState(false);
  const [backupError, setBackupError] = useState<string | null>(null);

  // Session tool policy
  type ToolSubMeta = { id: string; label: string; description: string };
  type ToolCatalogItem = {
    id: string;
    label: string;
    description: string;
    subs: ToolSubMeta[] | null;
    sub_key?: string;
  };
  const [toolPolicyMode, setToolPolicyMode] = useState<string>('strong_context');
  const [toolContextMode, setToolContextMode] = useState<string>('strong_context');
  const [toolCatalog, setToolCatalog] = useState<ToolCatalogItem[]>([]);
  const [toolPolicy, setToolPolicy] = useState<Record<string, any>>({});
  const [toolEnabledList, setToolEnabledList] = useState<string[]>([]);
  const [toolPolicyLoading, setToolPolicyLoading] = useState(false);
  const [toolPolicySaving, setToolPolicySaving] = useState(false);
  const [toolPolicyError, setToolPolicyError] = useState<string | null>(null);
  const [toolPolicyDirty, setToolPolicyDirty] = useState(false);
  const [toolPolicyScope, setToolPolicyScope] = useState<'session' | 'global'>('session');
  // Conversation the current tools-tab editor snapshot belongs to (session scope save target).
  const [toolPolicyConversationId, setToolPolicyConversationId] = useState<string | null>(null);
  const [toolPolicyScopes, setToolPolicyScopes] = useState<
    Array<{ value: string; label: string; description?: string }>
  >([
    { value: 'session', label: 'commandMenu.tools.scopeSession', description: 'commandMenu.tools.scopeSessionDesc' },
    { value: 'global', label: 'commandMenu.tools.scopeGlobal', description: 'commandMenu.tools.scopeGlobalDesc' },
  ]);
  
  const { newConversation, activeConversationId, loadHistory } = useChatStore();
  const {
    autoCleanShortLogs,
    autoCleanMinLines,
    theme,
    setTheme,
    setAutoCleanShortLogs,
    setAutoCleanMinLines,
  } = useSettingsStore();

  // ESC 关闭菜单
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (modalContent) {
          setModalContent(null);
        } else if (showBackup) {
          setShowBackup(false);
        } else if (showSettings) {
          setShowSettings(false);
        } else if (isOpen) {
          setIsOpen(false);
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, showSettings, showBackup, modalContent]);

  // 加载 .env 文件
  const loadEnvFile = async () => {
    setEnvLoading(true);
    setEnvError(null);
    try {
      const data = await filesApi.read('.env');
      setEnvContent(data.content);
      setEnvValues(parseEnvContent(data.content));
    } catch (err) {
      setEnvError(t('commandMenu.env.loadFailed'));
    } finally {
      setEnvLoading(false);
    }
  };

  // 加载 API 配置套
  const loadConfigProfiles = async () => {
    try {
      const response = await settingsApi.listConfigProfiles();
      if (response.success) {
        setConfigProfiles(response.profiles || []);
        setActiveProfileId(response.active_profile_id || '');
      } else {
        setEnvError(response.error || t('commandMenu.err.loadProfiles'));
      }
    } catch {
      setEnvError(t('commandMenu.err.loadProfiles'));
    }
  };

  // 加载角色列表
  const loadCharacters = async () => {
    try {
      setCharactersLoading(true);
      const response = await settingsApi.listCharacters();
      console.log('[Characters] API Response:', response);
      if (response.success) {
        setCharacters(response.characters || []);
        setCurrentCharacter(response.current || '');
        console.log('[Characters] Loaded:', response.characters?.length || 0, 'characters');
        console.log('[Characters] Current:', response.current || 'none');
        if (response.debug) {
          console.log('[Characters] Debug:', response.debug);
        }
      } else {
        console.error('[Characters] Load failed:', response.error);
      }
    } catch (error) {
      console.error('[Characters] Load error:', error);
    } finally {
      setCharactersLoading(false);
    }
  };

  // 选择角色
  const handleSelectCharacter = async (characterName: string) => {
    try {
      if (characterName === '') {
        // 选择"无角色"，移除当前角色
        if (currentCharacter) {
          await settingsApi.removeCharacter();
          setCurrentCharacter('');
        }
      } else {
        // 选择具体角色
        const response = await settingsApi.selectCharacter(characterName);
        if (response.success) {
          setCurrentCharacter(characterName);
          // 同时更新默认角色配置
          await settingsApi.updateSettings({
            default_character: characterName,
          });
        }
      }
    } catch (error) {
      console.error('选择角色失败:', error);
    }
  };

  // 打开设置时加载 env 和角色列表
  const applyToolPolicyResponse = (response: any) => {
    if (!response?.success) {
      setToolPolicyError(response?.error || t('commandMenu.err.loadToolPolicy'));
      return;
    }
    setToolPolicyError(null);
    setToolContextMode(response.context_mode || 'strong_context');
    setToolPolicyMode(response.policy_mode || 'strong_context');
    setToolCatalog(response.catalog || []);
    setToolPolicy(response.policy || {});
    setToolEnabledList(response.enabled_tools || []);
    if (response.scope === 'global' || response.scope === 'session') {
      setToolPolicyScope(response.scope);
    }
    if (Array.isArray(response.available_scopes) && response.available_scopes.length) {
      setToolPolicyScopes(response.available_scopes);
    }
    if (typeof response.conversation_id === 'string' && response.conversation_id) {
      setToolPolicyConversationId(response.conversation_id);
    } else if (activeConversationId) {
      setToolPolicyConversationId(activeConversationId);
    }
    setToolPolicyDirty(false);
  };

  const loadToolPolicy = async (policyMode?: string) => {
    setToolPolicyLoading(true);
    setToolPolicyError(null);
    try {
      const response = await settingsApi.getToolPolicy(
        activeConversationId || undefined,
        policyMode
      );
      applyToolPolicyResponse(response);
    } catch (err) {
      setToolPolicyError(t('commandMenu.err.loadToolPolicy'));
    } finally {
      setToolPolicyLoading(false);
    }
  };

  const isToolEnabledInPolicy = (toolId: string, policy: Record<string, any>) => {
    const val = policy[toolId];
    if (val === undefined) return true;
    if (typeof val === 'boolean') return val;
    if (val && typeof val === 'object') {
      return Object.values(val).some(Boolean);
    }
    return true;
  };

  const isSubEnabledInPolicy = (
    toolId: string,
    subId: string,
    policy: Record<string, any>
  ) => {
    const val = policy[toolId];
    if (val === undefined) return true;
    if (typeof val === 'boolean') return val;
    if (val && typeof val === 'object') return Boolean(val[subId]);
    return true;
  };

  const setToolEnabled = (toolId: string, enabled: boolean) => {
    setToolPolicy((prev) => {
      const next = { ...prev };
      const current = next[toolId];
      if (current && typeof current === 'object' && !Array.isArray(current)) {
        const subs = { ...current } as Record<string, boolean>;
        Object.keys(subs).forEach((k) => {
          subs[k] = enabled;
        });
        next[toolId] = subs;
      } else {
        next[toolId] = enabled;
      }
      return next;
    });
    setToolPolicyDirty(true);
  };

  const setSubEnabled = (toolId: string, subId: string, enabled: boolean) => {
    setToolPolicy((prev) => {
      const next = { ...prev };
      const current = next[toolId];
      let subs: Record<string, boolean>;
      if (current && typeof current === 'object' && !Array.isArray(current)) {
        subs = { ...current };
      } else {
        // Seed from catalog so toggling one sub does not drop siblings.
        const meta = toolCatalog.find((t) => t.id === toolId);
        const defaultOn = current !== false;
        subs = {};
        (meta?.subs || []).forEach((s) => {
          subs[s.id] = defaultOn;
        });
      }
      subs[subId] = enabled;
      next[toolId] = subs;
      return next;
    });
    setToolPolicyDirty(true);
  };

  const saveToolPolicy = async () => {
    setToolPolicySaving(true);
    setToolPolicyError(null);
    try {
      const response = await settingsApi.updateToolPolicy({
        conversation_id: toolPolicyConversationId || activeConversationId || undefined,
        policy_mode: toolPolicyMode,
        policy: toolPolicy,
      });
      if (!response.success) {
        setToolPolicyError(response.error || t('commandMenu.err.saveFailed'));
        return;
      }
      applyToolPolicyResponse(response);
    } catch {
      setToolPolicyError(t('commandMenu.err.saveToolPolicy'));
    } finally {
      setToolPolicySaving(false);
    }
  };

  const resetToolPolicy = async () => {
    setToolPolicySaving(true);
    setToolPolicyError(null);
    try {
      const response = await settingsApi.resetToolPolicy(
        toolPolicyConversationId || activeConversationId || undefined,
        toolPolicyMode
      );
      if (!response.success) {
        setToolPolicyError(response.error || t('commandMenu.err.resetFailed'));
        return;
      }
      // reload full view to refresh catalog/policy consistently
      await loadToolPolicy(toolPolicyMode);
    } catch {
      setToolPolicyError(t('commandMenu.err.resetToolPolicy'));
    } finally {
      setToolPolicySaving(false);
    }
  };

  const changeToolPolicyScope = async (scope: 'session' | 'global') => {
    if (scope === toolPolicyScope) return;
    if (toolPolicyDirty) {
      const ok = window.confirm(t('commandMenu.confirm.discardScope'));
      if (!ok) return;
    }
    setToolPolicySaving(true);
    setToolPolicyError(null);
    try {
      const response = await settingsApi.setToolPolicyScope({
        scope,
        conversation_id: activeConversationId || undefined,
      });
      if (!response.success) {
        setToolPolicyError(response.error || t('commandMenu.err.switchScope'));
        return;
      }
      applyToolPolicyResponse(response);
    } catch {
      setToolPolicyError(t('commandMenu.err.switchScope'));
    } finally {
      setToolPolicySaving(false);
    }
  };

  // 会话切换时，若正在编辑工具策略则刷新当前作用域下的配置
  useEffect(() => {
    if (!(showSettings && settingsTab === 'tools')) {
      return;
    }
    // Global policy is shared across sessions; keep local edits unless user navigates away from tools tab.
    if (toolPolicyScope === 'global') {
      if (activeConversationId) {
        setToolPolicyConversationId(activeConversationId);
      }
      return;
    }
    if (toolPolicyDirty) {
      const ok = window.confirm(
        t('commandMenu.confirm.discardSession')
      );
      if (!ok) {
        // Keep editing the previous conversation's snapshot; save still targets toolPolicyConversationId.
        return;
      }
    }
    loadToolPolicy(toolPolicyMode);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeConversationId]);

  const openSettings = () => {
    setShowSettings(true);
    loadEnvFile();
    loadConfigProfiles();
    loadCharacters();
    loadToolPolicy();
  };

  // ---------- 备份回滚 ----------
  const extractApiError = (err: unknown, fallback: string): string => {
    if (err instanceof ApiError) {
      const detail = (err.data as { detail?: string } | null)?.detail;
      if (detail) return detail;
    }
    return err instanceof Error ? err.message : fallback;
  };

  const loadCheckpoints = async () => {
    setBackupLoading(true);
    setBackupError(null);
    try {
      const res = await backupApi.listCheckpoints(activeConversationId || undefined);
      // 后端按时间正序存储，展示时最新的在前
      setCheckpoints((res.checkpoints || []).slice().reverse());
    } catch (err) {
      setBackupError(extractApiError(err, t('commandMenu.err.loadCheckpoints')));
    } finally {
      setBackupLoading(false);
    }
  };

  const loadTrackedFiles = async () => {
    setBackupLoading(true);
    setBackupError(null);
    setFileHistory(null);
    try {
      const res = await backupApi.listTrackedFiles(activeConversationId || undefined);
      setTrackedFiles(res.files || []);
    } catch (err) {
      setBackupError(extractApiError(err, t('commandMenu.err.loadTrackedFiles')));
    } finally {
      setBackupLoading(false);
    }
  };

  const openBackup = () => {
    setShowBackup(true);
    setBackupTab('checkpoints');
    setFileHistory(null);
    loadCheckpoints();
  };

  const handleRewind = async (checkpointId: string) => {
    const ok = window.confirm(
      t('commandMenu.confirm.rewind', { id: checkpointId })
    );
    if (!ok) return;
    setBackupBusy(true);
    setBackupError(null);
    try {
      const res = await backupApi.rewind({
        conversation_id: activeConversationId || undefined,
        checkpoint_id: checkpointId,
      });
      await loadHistory();
      setShowBackup(false);
      const lines = [
        t('commandMenu.rewind.doneAt', { checkpoint: res.checkpoint, ts: res.ts }),
        t('commandMenu.rewind.truncated', { count: res.message_count }),
      ];
      if (res.restored.length) {
        lines.push(t('commandMenu.rewind.restored', { count: res.restored.length }), ...res.restored.map((p) => `  - ${p}`));
      }
      if (res.deleted.length) {
        lines.push(
          t('commandMenu.rewind.deleted', { count: res.deleted.length }),
          ...res.deleted.map((p) => `  - ${p}`)
        );
      }
      if (res.skipped.length) {
        lines.push(
          t('commandMenu.rewind.skipped', { count: res.skipped.length }),
          ...res.skipped.map((p) => `  - ${p}`)
        );
      }
      if (res.failed.length) {
        lines.push(
          t('commandMenu.rewind.failed', { count: res.failed.length }),
          ...res.failed.map((f) => `  - ${f.path}: ${f.error}`)
        );
      }
      setModalContent({
        title: res.success ? t('commandMenu.rewind.successTitle') : t('commandMenu.rewind.partialTitle'),
        content: lines.join('\n'),
      });
    } catch (err) {
      setBackupError(extractApiError(err, t('commandMenu.err.rewind')));
    } finally {
      setBackupBusy(false);
    }
  };

  const loadFileHistory = async (path: string) => {
    setBackupLoading(true);
    setBackupError(null);
    try {
      const res = await backupApi.getFileHistory(path, activeConversationId || undefined);
      setFileHistory({
        path: res.path,
        has_baseline: res.has_baseline,
        versions: res.versions || [],
      });
    } catch (err) {
      setBackupError(extractApiError(err, t('commandMenu.err.loadFileHistory')));
    } finally {
      setBackupLoading(false);
    }
  };

  const handleRestoreFile = async (path: string, versionId: number) => {
    const label = versionId === 0 ? t('commandMenu.restore.baselineLabel') : `v${versionId}`;
    if (!window.confirm(t('commandMenu.confirm.restore', { label, path }))) return;
    setBackupBusy(true);
    setBackupError(null);
    try {
      const res = await backupApi.restoreFile({
        path,
        version_id: versionId,
        conversation_id: activeConversationId || undefined,
      });
      await loadFileHistory(path);
      setModalContent({
        title: t('commandMenu.restore.successTitle'),
        content: res.deleted
          ? t('commandMenu.restore.doneDeleted', { path: res.path, version: res.restored_to_version })
          : t('commandMenu.restore.done', { path: res.path, version: res.restored_to_version }),
      });
    } catch (err) {
      setBackupError(extractApiError(err, t('commandMenu.err.restoreFile')));
    } finally {
      setBackupBusy(false);
    }
  };

  // 更新单个配置值
  const updateEnvValue = (key: string, value: string) => {
    setEnvValues((prev) => ({ ...prev, [key]: value }));
  };

  // 保存 .env 文件
  const collectProfileValues = () => {
    const values: Record<string, string> = {};
    const appendValue = (key: string) => {
      const value = (envValues[key] || '').trim();
      if (value) {
        values[key] = value;
      }
    };

    const mainSdk = (envValues['LLM_SDK'] || 'openai').trim().toLowerCase();
    if (mainSdk === 'openai' || mainSdk === 'anthropic') {
      values['LLM_SDK'] = mainSdk;
      MAIN_SDK_PROFILE_KEYS[mainSdk].forEach(appendValue);
    }

    const subAgentSdk = (envValues['SUB_AGENT_LLM_SDK'] || '').trim().toLowerCase();
    if (subAgentSdk === 'openai' || subAgentSdk === 'anthropic') {
      values['SUB_AGENT_LLM_SDK'] = subAgentSdk;
      SUB_AGENT_SDK_PROFILE_KEYS[subAgentSdk].forEach(appendValue);
    }

    COMMON_PROFILE_KEYS.forEach(appendValue);
    AGENT_BASE_PROFILE_KEYS.forEach(appendValue);

    if (mainSdk === 'anthropic' || subAgentSdk === 'anthropic') {
      ANTHROPIC_COMPAT_PROFILE_KEYS.forEach(appendValue);
    }

    return values;
  };

  const handleApplyConfigProfile = async (profileId: string) => {
    if (!profileId) {
      setActiveProfileId('');
      return;
    }

    setProfileBusy(true);
    setEnvError(null);
    try {
      const response = await settingsApi.applyConfigProfile(profileId);
      if (!response.success) {
        throw new Error(response.error || t('commandMenu.err.applyProfile'));
      }

      await loadEnvFile();
      await loadConfigProfiles();
      setActiveProfileId(profileId);
      setModalContent({
        title: t('common.success'),
        content: response.message || t('commandMenu.profile.applied'),
      });
    } catch (err) {
      setEnvError(err instanceof Error ? err.message : t('commandMenu.err.applyProfile'));
    } finally {
      setProfileBusy(false);
    }
  };

  const handleSaveConfigProfile = async () => {
    const currentProfile = activeProfileId
      ? configProfiles.find((profile) => profile.id === activeProfileId)
      : undefined;
    const name = window.prompt(
      t('commandMenu.profile.namePrompt'),
      currentProfile?.name || ''
    );
    if (!name) {
      return;
    }
    const trimmedName = name.trim();
    if (!trimmedName) {
      return;
    }

    setProfileBusy(true);
    setEnvError(null);
    try {
      const values = collectProfileValues();
      if (Object.keys(values).length === 0) {
        throw new Error(t('commandMenu.profile.emptyValues'));
      }
      const response = await settingsApi.saveConfigProfile({
        name: trimmedName,
        profile_id: currentProfile?.name === trimmedName ? activeProfileId : undefined,
        values,
      });
      if (!response.success || !response.profile) {
        throw new Error(response.error || t('commandMenu.err.saveProfile'));
      }

      await loadConfigProfiles();
      setActiveProfileId(response.profile.id);
      setModalContent({
        title: t('common.success'),
        content: t('commandMenu.profile.saved', { name: response.profile.name }),
      });
    } catch (err) {
      setEnvError(err instanceof Error ? err.message : t('commandMenu.err.saveProfile'));
    } finally {
      setProfileBusy(false);
    }
  };

  const handleDeleteConfigProfile = async () => {
    if (!activeProfileId) {
      return;
    }

    const profile = configProfiles.find((item) => item.id === activeProfileId);
    if (!window.confirm(t('commandMenu.confirm.deleteProfile', { name: profile?.name || activeProfileId }))) {
      return;
    }

    setProfileBusy(true);
    setEnvError(null);
    try {
      const response = await settingsApi.deleteConfigProfile(activeProfileId);
      if (!response.success) {
        throw new Error(response.error || t('commandMenu.err.deleteProfile'));
      }
      setActiveProfileId('');
      await loadConfigProfiles();
    } catch (err) {
      setEnvError(err instanceof Error ? err.message : t('commandMenu.err.deleteProfile'));
    } finally {
      setProfileBusy(false);
    }
  };

  const saveEnvFile = async () => {
    setEnvSaving(true);
    setEnvError(null);
    try {
      const newContent = updateEnvContent(envContent, envValues);
      await filesApi.write('.env', newContent);
      const applyResponse = await settingsApi.applyEnvFile();
      if (!applyResponse.success) {
        throw new Error(applyResponse.error || t('commandMenu.err.applyEnv'));
      }
      setEnvContent(newContent);
      await loadConfigProfiles();
      setEnvError(null);
      setModalContent({
        title: t('common.success'),
        content: applyResponse.message || t('commandMenu.env.saved'),
      });
    } catch (err) {
      setEnvError(err instanceof Error ? err.message : t('commandMenu.err.saveFailed'));
    } finally {
      setEnvSaving(false);
    }
  };

  const openEnvFile = async () => {
    setEnvOpening(true);
    setEnvError(null);
    try {
      const response = await settingsApi.openEnvFile();
      if (!response.success) {
        setEnvError(response.error || t('commandMenu.err.openEnv'));
      }
    } catch (err) {
      setEnvError(t('commandMenu.err.openEnv'));
    } finally {
      setEnvOpening(false);
    }
  };

  const menuItems: MenuItem[] = [
    {
      id: 'save',
      label: t('commandMenu.menu.save'),
      icon: 'M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4',
      action: async () => {
        await commandsApi.save(activeConversationId || undefined);
        setModalContent({ title: t('common.success'), content: t('commandMenu.menu.saveDone') });
      },
    },
    {
      id: 'prompt',
      label: t('commandMenu.menu.viewPrompt'),
      icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
      action: async () => {
        const result = await commandsApi.getPrompt(activeConversationId || undefined);
        setModalContent({
          title: t('commandMenu.menu.promptTitle', { count: result.token_count }),
          content: result.prompt || t('commandMenu.none'),
        });
      },
    },
    {
      id: 'context',
      label: t('commandMenu.menu.viewContext'),
      icon: 'M4 6h16M4 10h16M4 14h16M4 18h16',
      action: async () => {
        const result = await commandsApi.getContext(false, activeConversationId || undefined);
        setModalContent({
          title: t('commandMenu.menu.contextTitle', { count: result.message_count ?? 0 }),
          content: JSON.stringify(result.messages, null, 2),
        });
      },
    },
    {
      id: 'skills',
      label: t('commandMenu.menu.viewSkills'),
      icon: 'M13 10V3L4 14h7v7l9-11h-7z',
      action: async () => {
        const result = await commandsApi.getSkills();
        setModalContent({
          title: t('commandMenu.menu.skillsTitle'),
          content: result.skills || t('commandMenu.menu.noSkills'),
        });
      },
    },
    {
      id: 'memclean',
      label: t('commandMenu.menu.clearMemory'),
      icon: 'M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16',
      action: async () => {
        await commandsApi.clearMemory(activeConversationId || undefined);
        await newConversation();
        setModalContent({ title: t('common.success'), content: t('commandMenu.menu.memoryClearedDone') });
      },
    },
    {
      id: 'savemode',
      label: t('commandMenu.menu.toggleSaveMode'),
      icon: 'M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z',
      action: async () => {
        const result = await commandsApi.toggleSaveMode(activeConversationId || undefined);
        setModalContent({
          title: t('commandMenu.menu.saveModeTitle'),
          content: result.save_mode ? t('commandMenu.menu.turnedOn') : t('commandMenu.menu.turnedOff'),
        });
      },
    },
    {
      id: 'backup',
      label: t('commandMenu.menu.backup'),
      icon: 'M9 15L3 9m0 0l6-6M3 9h12a6 6 0 010 12h-3',
      action: async () => {
        openBackup();
      },
    },
        {
      id: 'intercept',
      label: t('commandMenu.menu.intercept'),
      icon: 'M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636',
      action: async () => {
        const result = await settingsApi.toggleCommandIntercept();
        if (!result.success) {
          throw new Error(result.error || t('commandMenu.err.saveFailed'));
        }
        setModalContent({
          title: t('commandMenu.menu.intercept'),
          content: result.command_intercept
            ? t('commandMenu.menu.interceptOn')
            : t('commandMenu.menu.interceptOff'),
        });
      },
    },
{
      id: 'clearlogs',
      label: t('commandMenu.menu.clearLogs'),
      icon: 'M9 13h6m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2zM12 11V7',
      action: async () => {
        const result = await commandsApi.clearLogs();
        const skippedMsg = result.skipped_current
          ? '\n' + t('commandMenu.menu.clearLogsSkipped', { id: result.skipped_current })
          : '';
        setModalContent({
          title: t('commandMenu.menu.clearLogsDone'),
          content: `${t('commandMenu.menu.clearLogsResult', { count: result.cleared_count })}${skippedMsg}${result.errors ? '\n\n' + t('commandMenu.menu.errorsLabel') + '\n' + result.errors.join('\n') : ''}`,
        });
      },
    },
  ];

  const handleItemClick = async (item: MenuItem) => {
    setIsOpen(false);
    try {
      await item.action();
    } catch (error) {
      setModalContent({
        title: t('common.error'),
        content: error instanceof Error ? error.message : t('commandMenu.menu.actionFailed'),
      });
    }
  };

  return (
    <div className="relative">
      {/* 菜单按钮 - 三个点 */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="p-2 hover:bg-spore-accent/30 rounded-lg transition-colors"
      >
        {vertical ? (
          <svg
            className="w-5 h-5 text-spore-muted"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z"
            />
          </svg>
        ) : (
          <svg
            className="w-5 h-5 text-spore-muted"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M5 12h.01M12 12h.01M19 12h.01M6 12a1 1 0 11-2 0 1 1 0 012 0zm7 0a1 1 0 11-2 0 1 1 0 012 0zm7 0a1 1 0 11-2 0 1 1 0 012 0z"
            />
          </svg>
        )}
      </button>

      {/* 下拉菜单 - 向上弹出 */}
      {isOpen && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setIsOpen(false)} />
          <div
            className={`absolute bottom-full mb-2 w-48 bg-spore-card border border-spore-border/50 rounded-xl shadow-elevated z-20 py-2 animate-fade-in ${
              mini
                ? 'right-0 max-h-[calc(100vh-96px)] overflow-y-auto'
                : 'left-1/2 -translate-x-1/2'
            }`}
          >
            {menuItems.map((item) => (
              <button
                key={item.id}
                onClick={() => handleItemClick(item)}
                className="w-full px-4 py-2.5 text-left text-sm hover:bg-spore-accent/50 transition-colors flex items-center gap-3"
              >
                <svg
                  className="w-4 h-4 text-spore-muted"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d={item.icon}
                  />
                </svg>
                {item.label}
              </button>
            ))}
            {/* 分隔线 */}
            <div className="my-1 border-t border-spore-border/30" />
            {/* 设置按钮 */}
            <button
              onClick={() => {
                setIsOpen(false);
                openSettings();
              }}
              className="w-full px-4 py-2.5 text-left text-sm hover:bg-spore-accent/50 transition-colors flex items-center gap-3"
            >
              <svg
                className="w-4 h-4 text-spore-muted"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
                />
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                />
              </svg>
              {t('common.settings')}
            </button>
          </div>
        </>
      )}

      {/* 设置模态框（带标签页） */}
      {showSettings && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 animate-fade-in">
          <div className="bg-spore-card border border-spore-border/50 rounded-2xl w-[680px] max-w-[90vw] max-h-[85vh] overflow-hidden shadow-elevated flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-spore-border/30">
              <h3 className="font-semibold text-spore-text">{t('common.settings')}</h3>
              <div className="flex items-center gap-2">
                {(settingsTab === 'llm' || settingsTab === 'agent' || settingsTab === 'system') && envError && (
                  <span className="text-xs text-spore-error">{envError}</span>
                )}
                {(settingsTab === 'llm' || settingsTab === 'agent' || settingsTab === 'system') && (
                  <>
                    <button
                      onClick={openEnvFile}
                      disabled={envOpening || envLoading}
                      className="px-3 py-1.5 bg-spore-bg hover:bg-spore-accent/60 text-spore-text border border-spore-border/50 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                    >
                      {envOpening ? t('commandMenu.env.opening') : t('commandMenu.env.openEnv')}
                    </button>
                    <button
                      onClick={saveEnvFile}
                      disabled={envSaving || envLoading}
                      className="px-3 py-1.5 bg-spore-highlight hover:bg-spore-highlight-hover text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                    >
                      {envSaving ? t('commandMenu.env.saving') : t('commandMenu.env.saveConfig')}
                    </button>
                  </>
                )}
                <button
                  onClick={() => setShowSettings(false)}
                  className="p-1.5 hover:bg-spore-accent rounded-lg transition-colors"
                >
                  <svg
                    className="w-5 h-5 text-spore-muted"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M6 18L18 6M6 6l12 12"
                    />
                  </svg>
                </button>
              </div>
            </div>
            {/* 标签页 */}
            <div className="flex border-b border-spore-border/30">
              <button
                onClick={() => setSettingsTab('general')}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  settingsTab === 'general'
                    ? 'text-spore-highlight border-b-2 border-spore-highlight'
                    : 'text-spore-muted hover:text-spore-text'
                }`}
              >
                {t('commandMenu.tab.general')}
              </button>
              <button
                onClick={() => setSettingsTab('llm')}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  settingsTab === 'llm'
                    ? 'text-spore-highlight border-b-2 border-spore-highlight'
                    : 'text-spore-muted hover:text-spore-text'
                }`}
              >
                {t('commandMenu.tab.llm')}
              </button>
              <button
                onClick={() => setSettingsTab('agent')}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  settingsTab === 'agent'
                    ? 'text-spore-highlight border-b-2 border-spore-highlight'
                    : 'text-spore-muted hover:text-spore-text'
                }`}
              >
                {t('commandMenu.tab.agent')}
              </button>
              <button
                onClick={() => setSettingsTab('system')}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  settingsTab === 'system'
                    ? 'text-spore-highlight border-b-2 border-spore-highlight'
                    : 'text-spore-muted hover:text-spore-text'
                }`}
              >
                {t('commandMenu.tab.system')}
              </button>
              <button
                onClick={() => { setSettingsTab('tools'); loadToolPolicy(toolPolicyMode); }}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  settingsTab === 'tools'
                    ? 'text-spore-highlight border-b-2 border-spore-highlight'
                    : 'text-spore-muted hover:text-spore-text'
                }`}
              >
                {t('commandMenu.tab.tools')}
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              {settingsTab === 'tools' ? (
                <div className="space-y-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="text-sm text-spore-text font-medium">{t('commandMenu.tools.title')}</div>
                      <div className="text-xs text-spore-muted">{t('commandMenu.tools.desc')}</div>
                      <div className="text-xs text-spore-muted">
                        {t('commandMenu.tools.currentMode')} <span className="text-spore-highlight">{toolContextMode}</span>
                        {" · "}
                        {t('commandMenu.tools.editBaseline')} <span className="text-spore-highlight">{toolPolicyMode}</span>
                        {toolPolicyDirty ? " · " + t('commandMenu.tools.unsaved') : ""}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <button
                        onClick={() => resetToolPolicy()}
                        disabled={toolPolicyLoading || toolPolicySaving}
                        className="px-3 py-1.5 text-xs rounded-lg border border-spore-border/50 text-spore-muted hover:text-spore-text hover:bg-spore-accent/40 disabled:opacity-50"
                      >
                        {t('common.reset')}
                      </button>
                      <button
                        onClick={() => saveToolPolicy()}
                        disabled={toolPolicyLoading || toolPolicySaving || !toolPolicyDirty}
                        className="px-3 py-1.5 text-xs rounded-lg bg-spore-highlight hover:bg-spore-highlight-hover text-white disabled:opacity-50"
                      >
                        {toolPolicySaving ? t('commandMenu.tools.saving') : t('common.save')}
                      </button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="text-xs text-spore-muted">{t('commandMenu.tools.scope')}</div>
                    <div className="flex items-center gap-2">
                      {toolPolicyScopes.map((s) => (
                        <button
                          key={s.value}
                          onClick={() => changeToolPolicyScope(s.value as 'session' | 'global')}
                          disabled={toolPolicyLoading || toolPolicySaving}
                          title={s.description ? t(s.description) : t(s.label)}
                          className={`px-3 py-1.5 rounded-lg text-xs border transition-colors disabled:opacity-50 ${
                            toolPolicyScope === s.value
                              ? 'bg-spore-highlight/20 text-spore-highlight border-spore-highlight/60'
                              : 'bg-spore-bg text-spore-muted border-spore-border/50 hover:text-spore-text hover:bg-spore-accent/50'
                          }`}
                        >
                          {t(s.label)}
                        </button>
                      ))}
                    </div>
                    <div className="text-[11px] text-spore-muted">
                      {toolPolicyScope === 'global'
                        ? t('commandMenu.tools.scopeGlobalHint')
                        : t('commandMenu.tools.scopeSessionHint')}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="text-xs text-spore-muted">{t('commandMenu.tools.modeBaseline')}</div>
                    <div className="flex items-center gap-2">
                      {(["strong_context", "long_context"] as const).map((m) => (
                        <button
                          key={m}
                          onClick={() => {
                            if (m === toolPolicyMode) return;
                            if (toolPolicyDirty) {
                              const ok = window.confirm(
                                t('commandMenu.confirm.discardMode')
                              );
                              if (!ok) return;
                            }
                            setToolPolicyMode(m);
                            loadToolPolicy(m);
                          }}
                          className={`px-3 py-1.5 rounded-lg text-xs border transition-colors ${
                            toolPolicyMode === m
                              ? "bg-spore-highlight/20 text-spore-highlight border-spore-highlight/60"
                              : "bg-spore-bg text-spore-muted border-spore-border/50 hover:text-spore-text"
                          }`}
                        >
                          {m === "strong_context" ? t('commandMenu.tools.strongContextSet') : t('commandMenu.tools.longContextSet')}
                        </button>
                      ))}
                    </div>
                  </div>

                  {toolPolicyError && (
                    <div className="text-xs text-spore-error">{toolPolicyError}</div>
                  )}

                  {toolPolicyLoading ? (
                    <div className="text-sm text-spore-muted py-8 text-center">{t('common.loading')}</div>
                  ) : (
                    <div className="space-y-3">
                      {toolCatalog.map((tool) => {
                        const toolOn = isToolEnabledInPolicy(tool.id, toolPolicy);
                        return (
                          <div
                            key={tool.id}
                            className={`rounded-xl border border-spore-border/50 bg-spore-bg/40 p-3 ${
                              toolOn ? "" : "opacity-60"
                            }`}
                          >
                            <div className="flex items-center justify-between gap-3">
                              <div className="min-w-0">
                                <div className="text-sm text-spore-text font-medium">{tool.label}</div>
                                {tool.description && (
                                  <div className="text-xs text-spore-muted mt-0.5">
                                    {tool.description}
                                  </div>
                                )}
                              </div>
                              <label className="flex items-center gap-2 text-xs text-spore-muted flex-shrink-0 cursor-pointer">
                                <input
                                  type="checkbox"
                                  checked={toolOn}
                                  onChange={(e) => setToolEnabled(tool.id, e.target.checked)}
                                  className="rounded border-spore-border"
                                />
                                {t('commandMenu.tools.enable')}
                              </label>
                            </div>
                            {tool.subs && tool.subs.length > 0 && (
                              <div className="mt-3 pl-3 border-l border-spore-border/40 space-y-2">
                                {tool.subs.map((sub) => {
                                  const subOn = isSubEnabledInPolicy(
                                    tool.id,
                                    sub.id,
                                    toolPolicy
                                  );
                                  return (
                                    <div
                                      key={sub.id}
                                      className="flex items-center justify-between gap-3"
                                    >
                                      <div className="min-w-0">
                                        <div className="text-xs text-spore-text">{sub.label}</div>
                                        {sub.description && (
                                          <div className="text-[11px] text-spore-muted">
                                            {sub.description}
                                          </div>
                                        )}
                                      </div>
                                      <label className="flex items-center gap-2 text-xs text-spore-muted flex-shrink-0 cursor-pointer">
                                        <input
                                          type="checkbox"
                                          checked={subOn}
                                          onChange={(e) =>
                                            setSubEnabled(tool.id, sub.id, e.target.checked)
                                          }
                                          className="rounded border-spore-border"
                                        />
                                        {t('commandMenu.tools.enable')}
                                      </label>
                                    </div>
                                  );
                                })}
                              </div>
                            )}
                          </div>
                        );
                      })}
                      {toolCatalog.length === 0 && (
                        <div className="text-sm text-spore-muted text-center py-6">
                          {t('commandMenu.tools.noTools')}
                        </div>
                      )}
                      <div className="text-[11px] text-spore-muted">
                        {t('commandMenu.tools.enabledTopLevel')} {toolEnabledList.join(", ") || t('commandMenu.none')}
                      </div>
                    </div>
                  )}
                </div>
              ) : settingsTab === 'general' ? (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <div className="text-sm text-spore-text">{t('commandMenu.general.theme')}</div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setTheme('dark')}
                        className={`px-3 py-1.5 rounded-lg text-sm border transition-colors ${
                          theme === 'dark'
                            ? 'bg-spore-highlight/20 text-spore-highlight border-spore-highlight/60'
                            : 'bg-spore-bg text-spore-muted border-spore-border/50 hover:text-spore-text hover:bg-spore-accent/50'
                        }`}
                      >
                        {t('commandMenu.general.dark')}
                      </button>
                      <button
                        onClick={() => setTheme('light')}
                        className={`px-3 py-1.5 rounded-lg text-sm border transition-colors ${
                          theme === 'light'
                            ? 'bg-spore-highlight/20 text-spore-highlight border-spore-highlight/60'
                            : 'bg-spore-bg text-spore-muted border-spore-border/50 hover:text-spore-text hover:bg-spore-accent/50'
                        }`}
                      >
                        {t('commandMenu.general.light')}
                      </button>
                    </div>
                  </div>

                  {/* 角色选择 */}
                  <div className="space-y-2">
                    <div className="text-sm text-spore-text">{t('commandMenu.general.character')}</div>
                    {charactersLoading ? (
                      <div className="text-xs text-spore-muted">{t('common.loading')}</div>
                    ) : (
                      <select
                        value={currentCharacter}
                        onChange={(e) => handleSelectCharacter(e.target.value)}
                        className="w-full px-3 py-2 bg-spore-bg border border-spore-border/50 rounded-lg text-sm text-spore-text focus:outline-none focus:ring-2 focus:ring-spore-highlight/50"
                      >
                        <option value="">{t('commandMenu.general.noCharacter')}</option>
                        {characters.map((char) => (
                          <option key={char.name} value={char.name}>
                            {char.name}
                          </option>
                        ))}
                      </select>
                    )}
                    <div className="text-xs text-spore-muted">
                      {t('commandMenu.general.characterHint')}
                    </div>
                  </div>

                  {/* 自动清理短日志 */}
                  <div className="space-y-3">
                    <label className="flex items-center gap-3 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={autoCleanShortLogs}
                        onChange={(e) => setAutoCleanShortLogs(e.target.checked)}
                        className="w-4 h-4 rounded border-spore-border bg-spore-bg text-spore-accent focus:ring-spore-accent"
                      />
                      <span className="text-sm text-spore-text">{t('commandMenu.general.autoCleanLogs')}</span>
                    </label>
                    {autoCleanShortLogs && (
                      <div className="ml-7 flex items-center gap-2">
                        <span className="text-xs text-spore-muted">{t('commandMenu.general.minLines')}</span>
                        <input
                          type="number"
                          min={1}
                          max={100}
                          value={autoCleanMinLines}
                          onChange={(e) => setAutoCleanMinLines(Number(e.target.value) || 10)}
                          className="w-16 px-2 py-1 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-accent"
                        />
                        <span className="text-xs text-spore-muted">{t('commandMenu.general.linesUnit')}</span>
                      </div>
                    )}
                  </div>
                </div>
              ) : settingsTab === 'llm' ? (
                <div className="space-y-6">
                  <div className="space-y-3 rounded-xl border border-spore-border/50 bg-spore-bg/40 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-medium text-spore-text">{t('commandMenu.profile.title')}</div>
                        <div className="text-xs text-spore-muted">{t('commandMenu.profile.desc')}</div>
                      </div>
                      <button
                        onClick={handleSaveConfigProfile}
                        disabled={profileBusy || envLoading}
                        className="px-3 py-1.5 bg-spore-highlight hover:bg-spore-highlight-hover text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                      >
                        {t('commandMenu.profile.saveCurrent')}
                      </button>
                    </div>
                    <div className="flex flex-col sm:flex-row gap-2">
                      <select
                        value={activeProfileId}
                        onChange={(e) => handleApplyConfigProfile(e.target.value)}
                        disabled={profileBusy || envLoading || configProfiles.length === 0}
                        className="flex-1 px-3 py-2 text-sm bg-spore-card border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50 disabled:opacity-50"
                      >
                        <option value="">
                          {configProfiles.length === 0 ? t('commandMenu.profile.none') : t('commandMenu.profile.unmatched')}
                        </option>
                        {configProfiles.map((profile) => (
                          <option key={profile.id} value={profile.id}>
                            {profile.name}
                          </option>
                        ))}
                      </select>
                      <button
                        onClick={() => activeProfileId && handleApplyConfigProfile(activeProfileId)}
                        disabled={profileBusy || envLoading || !activeProfileId}
                        className="px-3 py-2 bg-spore-bg hover:bg-spore-accent/60 text-spore-text border border-spore-border/50 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                      >
                        {profileBusy ? t('commandMenu.profile.processing') : t('common.apply')}
                      </button>
                      <button
                        onClick={handleDeleteConfigProfile}
                        disabled={profileBusy || envLoading || !activeProfileId}
                        className="px-3 py-2 bg-spore-bg hover:bg-spore-error/10 text-spore-muted hover:text-spore-error border border-spore-border/50 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                      >
                        {t('common.delete')}
                      </button>
                    </div>
                  </div>
                  {envLoading ? (
                    <div className="flex items-center justify-center h-32">
                      <span className="text-spore-muted">{t('common.loading')}</span>
                    </div>
                  ) : (
                    <>
                      {/* 基础配置：最小可用 */}
                      <div className="space-y-4">
                        <div className="flex items-baseline justify-between gap-2">
                          <h4 className="text-sm font-semibold text-spore-text">{t('commandMenu.env.basicTitle')}</h4>
                          <span className="text-[11px] text-spore-muted">{t('commandMenu.env.basicHint')}</span>
                        </div>
                        {ENV_BASIC_CONFIG_GROUPS.map((group) => {
                          const selectedSdk = (envValues['LLM_SDK'] || '').toLowerCase();
                          const isOpenAiGroup = group.title.startsWith('OpenAI');
                          const isAnthropicGroup = group.title.startsWith('Anthropic');
                          const isDisabled =
                            (isAnthropicGroup && selectedSdk === 'openai') ||
                            (isOpenAiGroup && selectedSdk === 'anthropic');

                          return (
                            <div key={group.title} className={`space-y-3 ${isDisabled ? 'opacity-40' : ''}`}>
                              <h5 className="text-sm font-medium text-spore-highlight border-b border-spore-border/30 pb-2">
                                {t(GROUP_TITLE_I18N[group.title] || group.title)}
                              </h5>
                              <div className="space-y-3">
                                {group.items.map((item) => (
                                  <div key={item.key} className="space-y-1">
                                    <label className="flex items-center gap-2 text-xs text-spore-muted">
                                      <span>{t(item.label)}</span>
                                      {item.description && (
                                        <span className="text-spore-muted/60">({t(item.description)})</span>
                                      )}
                                    </label>
                                    {item.type === 'select' ? (
                                      <select
                                        value={envValues[item.key] || ''}
                                        onChange={(e) => updateEnvValue(item.key, e.target.value)}
                                        disabled={isDisabled}
                                        className={`w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50 ${isDisabled ? 'cursor-not-allowed' : ''}`}
                                      >
                                        <option value="">{item.placeholder ? t(item.placeholder) : t('commandMenu.env.notSet')}</option>
                                        {item.options?.map((opt) => (
                                          <option key={opt.value} value={opt.value}>
                                            {t(opt.label)}
                                          </option>
                                        ))}
                                      </select>
                                    ) : (
                                      <input
                                        type={item.type === 'number' ? 'number' : 'text'}
                                        value={envValues[item.key] || ''}
                                        onChange={(e) => updateEnvValue(item.key, e.target.value)}
                                        placeholder={item.placeholder ? t(item.placeholder) : undefined}
                                        disabled={isDisabled}
                                        className={`w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50 font-mono ${isDisabled ? 'cursor-not-allowed' : ''}`}
                                      />
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          );
                        })}
                      </div>

                      {/* 高级配置：默认折叠 */}
                      <div className="rounded-xl border border-spore-border/50 overflow-hidden">
                        <button
                          type="button"
                          onClick={() => setShowAdvancedEnv((v) => !v)}
                          className="w-full flex items-center justify-between gap-3 px-4 py-3 bg-spore-bg/50 hover:bg-spore-accent/30 transition-colors"
                        >
                          <div className="text-left">
                            <div className="text-sm font-semibold text-spore-text">{t('commandMenu.env.advancedTitle')}</div>
                            <div className="text-[11px] text-spore-muted">
                              {t('commandMenu.env.advancedHint')}
                            </div>
                          </div>
                          <svg
                            className={`w-4 h-4 text-spore-muted shrink-0 transition-transform ${showAdvancedEnv ? 'rotate-180' : ''}`}
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </button>
                        {showAdvancedEnv && (
                          <div className="space-y-6 p-4 border-t border-spore-border/30">
                            {LLM_ADVANCED_GROUPS.map((group) => (
                              <EnvGroupFields
                                key={group.title}
                                group={group}
                                envValues={envValues}
                                updateEnvValue={updateEnvValue}
                              />
                            ))}
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </div>
              ) : settingsTab === 'agent' ? (
                <div className="space-y-6">
                  <AgentBaseEditor
                    agentBaseTarget={agentBaseTarget}
                    setAgentBaseTarget={setAgentBaseTarget}
                    envValues={envValues}
                    updateEnvValue={updateEnvValue}
                  />
                  {AGENT_ENV_GROUPS.map((group) => (
                    <EnvGroupFields
                      key={group.title}
                      group={group}
                      envValues={envValues}
                      updateEnvValue={updateEnvValue}
                    />
                  ))}
                </div>
              ) : (
                <div className="space-y-6">
                  {SYSTEM_ENV_GROUPS.map((group) => (
                    <EnvGroupFields
                      key={group.title}
                      group={group}
                      envValues={envValues}
                      updateEnvValue={updateEnvValue}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 备份回滚模态框 */}
      {showBackup && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 animate-fade-in">
          <div className="bg-spore-card border border-spore-border/50 rounded-2xl w-[640px] max-w-[90vw] max-h-[80vh] overflow-hidden shadow-elevated flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-spore-border/30">
              <h3 className="font-semibold text-spore-text">{t('commandMenu.menu.backup')}</h3>
              <div className="flex items-center gap-2">
                {backupError && (
                  <span className="text-xs text-spore-error max-w-[280px] truncate" title={backupError}>
                    {backupError}
                  </span>
                )}
                <button
                  onClick={() =>
                    backupTab === 'checkpoints'
                      ? loadCheckpoints()
                      : fileHistory
                        ? loadFileHistory(fileHistory.path)
                        : loadTrackedFiles()
                  }
                  disabled={backupLoading || backupBusy}
                  className="px-3 py-1.5 bg-spore-bg hover:bg-spore-accent/60 text-spore-text border border-spore-border/50 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                >
                  {t('common.refresh')}
                </button>
                <button
                  onClick={() => setShowBackup(false)}
                  className="p-1.5 hover:bg-spore-accent rounded-lg transition-colors"
                >
                  <svg
                    className="w-5 h-5 text-spore-muted"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M6 18L18 6M6 6l12 12"
                    />
                  </svg>
                </button>
              </div>
            </div>
            {/* 标签页 */}
            <div className="flex border-b border-spore-border/30">
              <button
                onClick={() => {
                  setBackupTab('checkpoints');
                  loadCheckpoints();
                }}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  backupTab === 'checkpoints'
                    ? 'text-spore-highlight border-b-2 border-spore-highlight'
                    : 'text-spore-muted hover:text-spore-text'
                }`}
              >
                {t('commandMenu.backup.checkpointsTab')}
              </button>
              <button
                onClick={() => {
                  setBackupTab('files');
                  loadTrackedFiles();
                }}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  backupTab === 'files'
                    ? 'text-spore-highlight border-b-2 border-spore-highlight'
                    : 'text-spore-muted hover:text-spore-text'
                }`}
              >
                {t('commandMenu.backup.filesTab')}
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              {backupLoading ? (
                <div className="text-sm text-spore-muted py-8 text-center">{t('common.loading')}</div>
              ) : backupTab === 'checkpoints' ? (
                <div className="space-y-3">
                  <div className="text-xs text-spore-muted">
                    {t('commandMenu.backup.checkpointsDesc')}
                  </div>
                  {checkpoints.length === 0 ? (
                    <div className="text-sm text-spore-muted text-center py-6">
                      {t('commandMenu.backup.noCheckpoints')}
                    </div>
                  ) : (
                    checkpoints.map((cp) => (
                      <div
                        key={cp.id}
                        className="flex items-center justify-between gap-3 rounded-xl border border-spore-border/50 bg-spore-bg/40 p-3"
                      >
                        <div className="min-w-0">
                          <div className="text-sm text-spore-text font-medium">
                            {cp.id}
                            <span className="ml-2 text-xs text-spore-muted font-normal">{cp.ts}</span>
                            <span className="ml-2 text-xs text-spore-highlight font-normal">
                              {cp.kind === 'user_message'
                                ? t('commandMenu.backup.kindUser')
                                : t('commandMenu.backup.kindAction')}
                            </span>
                          </div>
                          <div
                            className="text-xs text-spore-text/80 mt-1 line-clamp-2"
                            title={cp.reply_preview || undefined}
                          >
                            {cp.reply_preview || t('commandMenu.backup.noReply')}
                          </div>
                          <div className="text-xs text-spore-muted mt-0.5">
                            {t('commandMenu.backup.checkpointMeta', { count: cp.message_count, files: Object.keys(cp.files || {}).length })}
                          </div>
                        </div>
                        <button
                          onClick={() => handleRewind(cp.id)}
                          disabled={backupBusy}
                          className="px-3 py-1.5 bg-spore-highlight hover:bg-spore-highlight-hover text-white rounded-lg text-xs font-medium transition-colors disabled:opacity-50 flex-shrink-0"
                        >
                          {backupBusy ? t('commandMenu.backup.rewinding') : t('commandMenu.backup.rewindHere')}
                        </button>
                      </div>
                    ))
                  )}
                </div>
              ) : fileHistory ? (
                <div className="space-y-3">
                  <button
                    onClick={() => setFileHistory(null)}
                    className="text-xs text-spore-muted hover:text-spore-text transition-colors"
                  >
                    {t('commandMenu.backup.backToFiles')}
                  </button>
                  <div className="text-sm text-spore-text font-mono break-all">{fileHistory.path}</div>
                  <div className="space-y-2">
                    {fileHistory.has_baseline && (
                      <div className="flex items-center justify-between gap-3 rounded-xl border border-spore-border/50 bg-spore-bg/40 p-3">
                        <div className="min-w-0">
                          <div className="text-sm text-spore-text font-medium">v0 · baseline</div>
                          <div className="text-xs text-spore-muted mt-0.5">{t('commandMenu.backup.baselineDesc')}</div>
                        </div>
                        <button
                          onClick={() => handleRestoreFile(fileHistory.path, 0)}
                          disabled={backupBusy}
                          className="px-3 py-1.5 bg-spore-bg hover:bg-spore-accent/60 text-spore-text border border-spore-border/50 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 flex-shrink-0"
                        >
                          {t('commandMenu.backup.restore')}
                        </button>
                      </div>
                    )}
                    {fileHistory.versions
                      .slice()
                      .reverse()
                      .map((v) => (
                        <div
                          key={v.id}
                          className="flex items-center justify-between gap-3 rounded-xl border border-spore-border/50 bg-spore-bg/40 p-3"
                        >
                          <div className="min-w-0">
                            <div className="text-sm text-spore-text font-medium">
                              v{v.id}
                              <span className="ml-2 text-xs text-spore-muted font-normal">{v.ts}</span>
                            </div>
                            <div className="text-xs text-spore-muted mt-0.5">
                              {v.op} · {v.store === 'delete' ? t('commandMenu.backup.deletedState') : `${v.size} bytes`}
                            </div>
                          </div>
                          <button
                            onClick={() => handleRestoreFile(fileHistory.path, v.id)}
                            disabled={backupBusy}
                            className="px-3 py-1.5 bg-spore-bg hover:bg-spore-accent/60 text-spore-text border border-spore-border/50 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 flex-shrink-0"
                          >
                            {t('commandMenu.backup.restore')}
                          </button>
                        </div>
                      ))}
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  <div className="text-xs text-spore-muted">
                    {t('commandMenu.backup.filesDesc')}
                  </div>
                  {trackedFiles.length === 0 ? (
                    <div className="text-sm text-spore-muted text-center py-6">{t('commandMenu.backup.noTrackedFiles')}</div>
                  ) : (
                    trackedFiles.map((f) => (
                      <button
                        key={f}
                        onClick={() => loadFileHistory(f)}
                        className="w-full text-left rounded-xl border border-spore-border/50 bg-spore-bg/40 hover:bg-spore-accent/30 p-3 text-sm text-spore-text font-mono break-all transition-colors"
                      >
                        {f}
                      </button>
                    ))
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 内容模态框 */}
      {modalContent && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 animate-fade-in">
          <div className="bg-spore-card border border-spore-border/50 rounded-2xl max-w-2xl max-h-[80vh] w-full mx-4 overflow-hidden shadow-elevated">
            <div className="flex items-center justify-between px-5 py-4 border-b border-spore-border/30">
              <h3 className="font-semibold text-spore-text">{modalContent.title}</h3>
              <button
                onClick={() => setModalContent(null)}
                className="p-1.5 hover:bg-spore-accent rounded-lg transition-colors"
              >
                <svg
                  className="w-5 h-5 text-spore-muted"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
            </div>
            <div className="p-5 overflow-auto max-h-[60vh]">
              <pre className="text-sm whitespace-pre-wrap break-words font-mono text-spore-text bg-spore-bg/50 rounded-xl p-4">
                {modalContent.content}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
