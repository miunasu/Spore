/**
 * 命令菜单组件 - 现代化设计
 */
import React, { useState, useEffect } from 'react';
import { useChatStore } from '../../stores/chatStore';
import { useSettingsStore } from '../../stores/settingsStore';
import { commandsApi, filesApi, settingsApi } from '../../services/api';

interface MenuItem {
  id: string;
  label: string;
  icon: string;
  action: () => Promise<void>;
}

interface CommandMenuProps {
  vertical?: boolean;
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

// ENV 配置分组
// basic: 最小可用配置（能连上模型即可跑）
// advanced: 其余调优/兼容/资源/路径等，UI 中默认折叠
type EnvConfigGroup = { title: string; items: EnvConfigItem[] };

const ENV_BASIC_CONFIG_GROUPS: EnvConfigGroup[] = [
  {
    title: 'LLM SDK 选择',
    items: [
      {
        key: 'LLM_SDK',
        label: 'SDK 类型',
        type: 'select',
        options: [
          { value: 'openai', label: 'OpenAI SDK' },
          { value: 'anthropic', label: 'Anthropic SDK' },
        ],
        description: 'openai 支持 OpenAI/DeepSeek/第三方代理，anthropic 直连 Claude API',
        placeholder: '默认: openai',
      },
    ],
  },
  {
    title: 'OpenAI API',
    items: [
      { key: 'OPENAI_API_KEY', label: 'API Key', type: 'text', placeholder: '默认: 无' },
      {
        key: 'OPENAI_API_URL',
        label: 'API URL',
        type: 'text',
        placeholder: '默认: https://api.openai.com/v1',
      },
      { key: 'OPENAI_MODEL', label: '模型', type: 'text', placeholder: '默认: gpt-4o-mini' },
    ],
  },
  {
    title: 'Anthropic API',
    items: [
      { key: 'ANTHROPIC_API_KEY', label: 'API Key', type: 'text', placeholder: '默认: 无' },
      {
        key: 'ANTHROPIC_API_URL',
        label: 'API URL',
        type: 'text',
        placeholder: '默认: https://api.anthropic.com',
      },
      {
        key: 'ANTHROPIC_MODEL',
        label: '模型',
        type: 'text',
        placeholder: '默认: claude-sonnet-4-20250514',
      },
    ],
  },
];

const ENV_ADVANCED_CONFIG_GROUPS: EnvConfigGroup[] = [
  {
    title: 'OpenAI 高级',
    items: [
      {
        key: 'USE_RESPONSES_API',
        label: '使用 Responses API',
        type: 'select',
        options: [
          { value: 'true', label: '是' },
          { value: 'false', label: '否' },
        ],
        placeholder: '默认: false',
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
        placeholder: '默认: 不传',
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
        placeholder: '默认: 不传',
        description: 'Claude output_config.effort；设置后默认启用 adaptive thinking',
      },
      {
        key: 'ANTHROPIC_THINKING_MODE',
        label: 'Thinking Mode',
        type: 'select',
        options: [
          { value: 'adaptive', label: 'adaptive（推荐）' },
          { value: 'enabled', label: 'enabled（手动 budget）' },
          { value: 'disabled', label: 'disabled' },
        ],
        placeholder: '默认: 自动',
        description: '留空时：有 effort 用 adaptive，有 budget 用 enabled',
      },
      {
        key: 'ANTHROPIC_THINKING_BUDGET_TOKENS',
        label: 'Thinking Budget Tokens',
        type: 'text',
        placeholder: '默认: 自动（仅 enabled 模式）',
        description: '手动扩展思考 budget_tokens，需 >=1024 且 < max_tokens',
      },
    ],
  },
  {
    title: '子 Agent LLM',
    items: [
      {
        key: 'SUB_AGENT_LLM_SDK',
        label: '子 Agent SDK',
        type: 'select',
        options: [
          { value: 'openai', label: 'OpenAI SDK' },
          { value: 'anthropic', label: 'Anthropic SDK' },
        ],
        placeholder: '默认: 继承主 Agent',
      },
      { key: 'SUB_AGENT_OPENAI_API_KEY', label: '子 Agent OpenAI Key', type: 'text', placeholder: '默认: 继承主 Agent' },
      { key: 'SUB_AGENT_OPENAI_API_URL', label: '子 Agent OpenAI URL', type: 'text', placeholder: '默认: 继承主 Agent' },
      { key: 'SUB_AGENT_OPENAI_MODEL', label: '子 Agent OpenAI 模型', type: 'text', placeholder: '默认: 继承主 Agent' },
      { key: 'SUB_AGENT_ANTHROPIC_API_KEY', label: '子 Agent Anthropic Key', type: 'text', placeholder: '默认: 继承主 Agent' },
      { key: 'SUB_AGENT_ANTHROPIC_API_URL', label: '子 Agent Anthropic URL', type: 'text', placeholder: '默认: 继承主 Agent' },
      { key: 'SUB_AGENT_ANTHROPIC_MODEL', label: '子 Agent Anthropic 模型', type: 'text', placeholder: '默认: 继承主 Agent' },
    ],
  },
  {
    title: 'LLM 参数',
    items: [
      {
        key: 'MAX_OUTPUT_TOKENS',
        label: '最大输出 Token',
        type: 'text',
        placeholder: '默认: 15000',
        description: 'LLM 单次输出的最大 token 数',
      },
      {
        key: 'CONTEXT_MAX_TOKENS',
        label: '上下文最大 Token',
        type: 'text',
        placeholder: '默认: 128000',
      },
      {
        key: 'CONTEXT_WARNING_THRESHOLD',
        label: '上下文警告阈值',
        type: 'text',
        placeholder: '默认: 0.8',
        description: '0.0-1.0，超过此比例时警告',
      },
      {
        key: 'MAX_SINGLE_MESSAGE_RATIO',
        label: '单消息最大比例',
        type: 'text',
        placeholder: '默认: 0.3',
        description: '相对于上下文最大Token',
      },
      {
        key: 'API_TIMEOUT',
        label: 'API 超时时间',
        type: 'text',
        placeholder: '默认: 300 秒',
      },
    ],
  },
  {
    title: 'SDK 兼容性',
    items: [
      {
        key: 'CLEAN_SDK_HEADERS',
        label: '清理 SDK Headers',
        type: 'select',
        options: [
          { value: 'true', label: '是' },
          { value: 'false', label: '否' },
        ],
        description: '某些第三方代理需要开启',
        placeholder: '默认: false',
      },
      {
        key: 'CLEAN_AUTH_HEADER',
        label: '清理 Auth Header',
        type: 'select',
        options: [
          { value: 'true', label: '是' },
          { value: 'false', label: '否' },
        ],
        description: '仅对 Anthropic SDK 有效',
        placeholder: '默认: false',
      },
      {
        key: 'SYSTEM_AS_USER',
        label: 'System 作为 User',
        type: 'select',
        options: [
          { value: 'true', label: '是' },
          { value: 'false', label: '否' },
        ],
        description: '兼容不支持 system role 的模型',
        placeholder: '默认: false',
      },
      {
        key: 'SYSTEM_PROMPT_FILE',
        label: '系统提示文件',
        type: 'text',
        placeholder: '默认: prompt.md',
        description: '位于 prompt 目录下',
      },
    ],
  },
  {
    title: '对话管理',
    items: [
      {
        key: 'CONTEXT_MODE',
        label: '上下文处理模式',
        type: 'select',
        options: [
          { value: 'strong_context', label: '强上下文' },
          { value: 'long_context', label: '长上下文' },
          { value: 'auto', label: '自动选择' },
        ],
        placeholder: '默认: strong_context',
        description: '控制工具集和上下文处理策略',
      },
      {
        key: 'DEFAULT_CHARACTER',
        label: '默认角色',
        type: 'text',
        placeholder: '默认: 无',
      },
      {
        key: 'RULE_REMINDER_INTERVAL',
        label: '规则提醒间隔',
        type: 'text',
        placeholder: '默认: 10',
        description: '每 N 次 LLM 回复提醒一次，0 禁用',
      },
      {
        key: 'RULE_REMINDER_SHORT',
        label: '精简版规则提醒',
        type: 'select',
        options: [
          { value: 'true', label: '是' },
          { value: 'false', label: '否' },
        ],
        placeholder: '默认: false',
        description: '节省 token',
      },
      {
        key: 'LIMIT_WRITE_TOOL_RETURN',
        label: '限制写工具返回',
        type: 'select',
        options: [
          { value: 'true', label: '是' },
          { value: 'false', label: '否' },
        ],
        placeholder: '默认: true',
        description: '节省 token',
      },
    ],
  },
  {
    title: '日志配置',
    items: [
      {
        key: 'LOG_TO_FILE',
        label: '记录到文件',
        type: 'select',
        options: [
          { value: 'true', label: '是' },
          { value: 'false', label: '否' },
        ],
        placeholder: '默认: true',
      },
      {
        key: 'LOG_FILE_MAX_SIZE',
        label: '日志文件最大大小',
        type: 'text',
        placeholder: '默认: 10485760 (10MB)',
      },
      {
        key: 'LOG_BACKUP_COUNT',
        label: '日志备份数量',
        type: 'text',
        placeholder: '默认: 5',
      },
      {
        key: 'LOG_MONITOR_MAX_LINE_LENGTH',
        label: '日志行最大长度',
        type: 'text',
        placeholder: '默认: 200 字符',
      },
      { key: 'LOG_ERROR_FILENAME', label: '错误日志文件名', type: 'text', placeholder: '默认: error.log' },
      { key: 'LOG_LLM_VALIDATION_FILENAME', label: 'LLM 校验日志', type: 'text', placeholder: '默认: llm_validation.log' },
      { key: 'LOG_TOOL_EXECUTION_FILENAME', label: '工具执行日志', type: 'text', placeholder: '默认: tool_execution.log' },
      { key: 'LOG_GENERAL_FILENAME', label: '通用日志', type: 'text', placeholder: '默认: general.log' },
      { key: 'LOG_MONITOR_LOCK_FILENAME', label: '监控锁文件', type: 'text', placeholder: '默认: .monitor.lock' },
      { key: 'LOG_MONITOR_CHECK_INTERVAL', label: '日志检查间隔', type: 'text', placeholder: '默认: 0.5 秒' },
      {
        key: 'LOG_MONITOR_TYPES',
        label: '日志监控类型',
        type: 'text',
        placeholder: '默认: error,llm_validation,tool_execution',
      },
    ],
  },
  {
    title: '工具配置',
    items: [
      {
        key: 'WEB_BROWSER_TIMEOUT',
        label: '浏览器超时',
        type: 'text',
        placeholder: '默认: 15 秒',
      },
      {
        key: 'WEB_PROXY_PORT',
        label: 'Web 代理端口',
        type: 'text',
        placeholder: '默认: 7897',
      },
      {
        key: 'WEB_MAX_CONTENT_LENGTH',
        label: 'Web 内容最大长度',
        type: 'text',
        placeholder: '默认: 2000 字符',
      },
      {
        key: 'TOOL_EXECUTION_TIMEOUT',
        label: '工具执行超时',
        type: 'text',
        placeholder: '默认: 120 秒',
      },
      {
        key: 'SHELL_COMMAND_TIMEOUT',
        label: 'Shell 命令超时',
        type: 'text',
        placeholder: '默认: 60 秒',
      },
    ],
  },
  {
    title: '多 Agent 配置',
    items: [
      {
        key: 'MULTI_AGENT_MAX_COUNT',
        label: '最大并发子 Agent',
        type: 'text',
        placeholder: '默认: 5',
      },
      {
        key: 'SUB_AGENT_MAX_ITERATIONS',
        label: '子 Agent 最大迭代',
        type: 'text',
        placeholder: '默认: 100',
      },
      {
        key: 'CODER_MAX_ITERATIONS',
        label: 'Coder 最大迭代',
        type: 'text',
        placeholder: '默认: 1000',
      },
      {
        key: 'MULTI_AGENT_TIMEOUT',
        label: '多 Agent 超时',
        type: 'text',
        placeholder: '默认: 无限等待',
        description: '秒，留空表示无限等待',
      },
      {
        key: 'MULTI_AGENT_JOIN_INTERVAL',
        label: '等待轮询间隔',
        type: 'text',
        placeholder: '默认: 2.0 秒',
        description: '用于检查中断信号',
      },
      {
        key: 'MULTI_AGENT_MONITOR_ENABLED',
        label: '启用多 Agent 监控',
        type: 'select',
        options: [
          { value: 'true', label: '是' },
          { value: 'false', label: '否' },
        ],
        placeholder: '默认: true',
      },
    ],
  },
  {
    title: 'Chat 进程配置',
    items: [
      {
        key: 'CHAT_MAX_WORKERS',
        label: '最大并发 LLM 请求',
        type: 'text',
        placeholder: '默认: 5',
      },
      {
        key: 'CHAT_RESPONSE_EXPIRE',
        label: '响应缓存过期时间',
        type: 'text',
        placeholder: '默认: 300 秒',
      },
      {
        key: 'CHAT_RESPONSE_CLEANUP_INTERVAL',
        label: '缓存清理间隔',
        type: 'text',
        placeholder: '默认: 60 秒',
      },
      {
        key: 'IPC_CHECK_INTERVAL',
        label: 'IPC 检查间隔',
        type: 'text',
        placeholder: '默认: 0.1 秒',
      },
    ],
  },
  {
    title: '路径配置',
    items: [
      { key: 'SKILLS_DIR', label: 'Skills 目录', type: 'text', placeholder: '默认: skills' },
      { key: 'CHARACTERS_DIR', label: 'Characters 目录', type: 'text', placeholder: '默认: characters' },
      { key: 'PROMPT_DIR', label: 'Prompt 目录', type: 'text', placeholder: '默认: prompt' },
      { key: 'LOG_DIR', label: '日志目录', type: 'text', placeholder: '默认: logs' },
      { key: 'OUTPUT_DIR', label: '输出目录', type: 'text', placeholder: '默认: output' },
      { key: 'UPLOAD_DIR', label: '上传目录', type: 'text', placeholder: '默认: uploads' },
    ],
  },
  {
    title: 'Desktop 启动配置',
    items: [
      {
        key: 'LAUNCH_MODE',
        label: '启动模式',
        type: 'select',
        options: [
          { value: 'cli', label: 'CLI' },
          { value: 'desktop', label: 'Desktop' },
        ],
        placeholder: '默认: cli',
      },
      { key: 'DESKTOP_API_HOST', label: 'API Host', type: 'text', placeholder: '默认: 127.0.0.1' },
      { key: 'DESKTOP_API_PORT', label: 'API Port', type: 'text', placeholder: '默认: 8765' },
    ],
  },
  {
    title: '拦截开关',
    items: [
      {
        key: 'COMMAND_INTERCEPT',
        label: '拦截开关',
        type: 'select',
        options: [
          { value: 'true', label: '开启（推荐）' },
          { value: 'false', label: '关闭' },
        ],
        description: '总开关：开启后启用 shell 安全拦截策略（删除/写入等，后续可扩展）',
        placeholder: '默认: true',
      },
      {
        key: 'INTERCEPT_SHELL_DELETE',
        label: '拦截 shell 删除',
        type: 'select',
        options: [
          { value: 'true', label: '开启' },
          { value: 'false', label: '关闭' },
        ],
        description: '仅总开关开启时生效；拦截 del/rm/rmdir/Remove-Item',
        placeholder: '默认: true（不写则开启）',
      },
      {
        key: 'INTERCEPT_SHELL_WRITE',
        label: '拦截 shell 写入',
        type: 'select',
        options: [
          { value: 'true', label: '开启' },
          { value: 'false', label: '关闭' },
        ],
        description: '仅总开关开启时生效；拦截 Set-Content/Out-File（防 BOM）',
        placeholder: '默认: true（不写则开启）',
      },
    ],
  },
];

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

export const CommandMenu: React.FC<CommandMenuProps> = ({ vertical = false }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [settingsTab, setSettingsTab] = useState<'general' | 'env'>('general');
  const [showAdvancedEnv, setShowAdvancedEnv] = useState(false);
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
  
  const { newConversation, activeConversationId } = useChatStore();
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
        } else if (showSettings) {
          setShowSettings(false);
        } else if (isOpen) {
          setIsOpen(false);
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, showSettings, modalContent]);

  // 加载 .env 文件
  const loadEnvFile = async () => {
    setEnvLoading(true);
    setEnvError(null);
    try {
      const data = await filesApi.read('.env');
      setEnvContent(data.content);
      setEnvValues(parseEnvContent(data.content));
    } catch (err) {
      setEnvError('加载 .env 失败');
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
        setEnvError(response.error || '加载配置套失败');
      }
    } catch {
      setEnvError('加载配置套失败');
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
  const openSettings = () => {
    setShowSettings(true);
    loadEnvFile();
    loadConfigProfiles();
    loadCharacters();
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
        throw new Error(response.error || '应用配置套失败');
      }

      await loadEnvFile();
      await loadConfigProfiles();
      setActiveProfileId(profileId);
      setModalContent({
        title: '成功',
        content: response.message || '配置套已应用到当前 Spore 进程',
      });
    } catch (err) {
      setEnvError(err instanceof Error ? err.message : '应用配置套失败');
    } finally {
      setProfileBusy(false);
    }
  };

  const handleSaveConfigProfile = async () => {
    const currentProfile = activeProfileId
      ? configProfiles.find((profile) => profile.id === activeProfileId)
      : undefined;
    const name = window.prompt(
      '配置套名称',
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
        throw new Error('当前没有可保存到配置套的配置项');
      }
      const response = await settingsApi.saveConfigProfile({
        name: trimmedName,
        profile_id: currentProfile?.name === trimmedName ? activeProfileId : undefined,
        values,
      });
      if (!response.success || !response.profile) {
        throw new Error(response.error || '保存配置套失败');
      }

      await loadConfigProfiles();
      setActiveProfileId(response.profile.id);
      setModalContent({
        title: '成功',
        content: `配置套 "${response.profile.name}" 已保存`,
      });
    } catch (err) {
      setEnvError(err instanceof Error ? err.message : '保存配置套失败');
    } finally {
      setProfileBusy(false);
    }
  };

  const handleDeleteConfigProfile = async () => {
    if (!activeProfileId) {
      return;
    }

    const profile = configProfiles.find((item) => item.id === activeProfileId);
    if (!window.confirm(`删除配置套 "${profile?.name || activeProfileId}"？`)) {
      return;
    }

    setProfileBusy(true);
    setEnvError(null);
    try {
      const response = await settingsApi.deleteConfigProfile(activeProfileId);
      if (!response.success) {
        throw new Error(response.error || '删除配置套失败');
      }
      setActiveProfileId('');
      await loadConfigProfiles();
    } catch (err) {
      setEnvError(err instanceof Error ? err.message : '删除配置套失败');
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
        throw new Error(applyResponse.error || '应用配置失败');
      }
      setEnvContent(newContent);
      await loadConfigProfiles();
      setEnvError(null);
      setModalContent({
        title: '成功',
        content: applyResponse.message || '配置已保存并应用到当前 Spore 进程',
      });
    } catch (err) {
      setEnvError(err instanceof Error ? err.message : '保存失败');
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
        setEnvError(response.error || '打开 .env 失败');
      }
    } catch (err) {
      setEnvError('打开 .env 失败');
    } finally {
      setEnvOpening(false);
    }
  };

  const menuItems: MenuItem[] = [
    {
      id: 'save',
      label: '保存对话',
      icon: 'M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4',
      action: async () => {
        await commandsApi.save(activeConversationId || undefined);
        setModalContent({ title: '成功', content: '对话已保存' });
      },
    },
    {
      id: 'prompt',
      label: '查看提示词',
      icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
      action: async () => {
        const result = await commandsApi.getPrompt(activeConversationId || undefined);
        setModalContent({
          title: `系统提示词 (${result.token_count} tokens)`,
          content: result.prompt || '无',
        });
      },
    },
    {
      id: 'context',
      label: '查看上下文',
      icon: 'M4 6h16M4 10h16M4 14h16M4 18h16',
      action: async () => {
        const result = await commandsApi.getContext(false, activeConversationId || undefined);
        setModalContent({
          title: `上下文 (${result.message_count} 条消息)`,
          content: JSON.stringify(result.messages, null, 2),
        });
      },
    },
    {
      id: 'skills',
      label: '查看技能',
      icon: 'M13 10V3L4 14h7v7l9-11h-7z',
      action: async () => {
        const result = await commandsApi.getSkills();
        setModalContent({
          title: '可用技能',
          content: result.skills || '无可用技能',
        });
      },
    },
    {
      id: 'memclean',
      label: '清除记忆',
      icon: 'M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16',
      action: async () => {
        await commandsApi.clearMemory(activeConversationId || undefined);
        await newConversation();
        setModalContent({ title: '成功', content: '记忆已清除' });
      },
    },
    {
      id: 'savemode',
      label: '切换节省模式',
      icon: 'M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z',
      action: async () => {
        const result = await commandsApi.toggleSaveMode(activeConversationId || undefined);
        setModalContent({
          title: '节省模式',
          content: result.save_mode ? '已开启' : '已关闭',
        });
      },
    },
        {
      id: 'intercept',
      label: '拦截开关',
      icon: 'M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636',
      action: async () => {
        const result = await settingsApi.toggleCommandIntercept();
        if (!result.success) {
          throw new Error(result.error || '切换失败');
        }
        setModalContent({
          title: '拦截开关',
          content: result.command_intercept
            ? '已开启：命令拦截策略生效（含 shell 删除/危险写入等）。'
            : '已关闭：已关闭全部命令拦截策略（请谨慎）。',
        });
      },
    },
{
      id: 'clearlogs',
      label: '清理日志',
      icon: 'M9 13h6m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2zM12 11V7',
      action: async () => {
        const result = await commandsApi.clearLogs();
        const skippedMsg = result.skipped_current
          ? `\n(已跳过当前会话: ${result.skipped_current})`
          : '';
        setModalContent({
          title: '清理完成',
          content: `已清理 ${result.cleared_count} 个日志文件/文件夹${skippedMsg}${result.errors ? '\n\n错误:\n' + result.errors.join('\n') : ''}`,
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
        title: '错误',
        content: error instanceof Error ? error.message : '操作失败',
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
          <div className="absolute left-1/2 -translate-x-1/2 bottom-full mb-2 w-48 bg-spore-card border border-spore-border/50 rounded-xl shadow-elevated z-20 py-2 animate-fade-in">
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
              设置
            </button>
          </div>
        </>
      )}

      {/* 设置模态框（带标签页） */}
      {showSettings && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 animate-fade-in">
          <div className="bg-spore-card border border-spore-border/50 rounded-2xl w-[600px] max-w-[90vw] max-h-[85vh] overflow-hidden shadow-elevated flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-spore-border/30">
              <h3 className="font-semibold text-spore-text">设置</h3>
              <div className="flex items-center gap-2">
                {settingsTab === 'env' && envError && (
                  <span className="text-xs text-spore-error">{envError}</span>
                )}
                {settingsTab === 'env' && (
                  <>
                    <button
                      onClick={openEnvFile}
                      disabled={envOpening || envLoading}
                      className="px-3 py-1.5 bg-spore-bg hover:bg-spore-accent/60 text-spore-text border border-spore-border/50 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                    >
                      {envOpening ? '打开中...' : '打开 .env'}
                    </button>
                    <button
                      onClick={saveEnvFile}
                      disabled={envSaving || envLoading}
                      className="px-3 py-1.5 bg-spore-highlight hover:bg-spore-highlight-hover text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                    >
                      {envSaving ? '保存中...' : '保存配置'}
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
                常规
              </button>
              <button
                onClick={() => setSettingsTab('env')}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  settingsTab === 'env'
                    ? 'text-spore-highlight border-b-2 border-spore-highlight'
                    : 'text-spore-muted hover:text-spore-text'
                }`}
              >
                环境配置
              </button>
            </div>
            {/* 内容区域 */}
            <div className="flex-1 overflow-y-auto p-5">
              {settingsTab === 'general' ? (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <div className="text-sm text-spore-text">主题</div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setTheme('dark')}
                        className={`px-3 py-1.5 rounded-lg text-sm border transition-colors ${
                          theme === 'dark'
                            ? 'bg-spore-highlight/20 text-spore-highlight border-spore-highlight/60'
                            : 'bg-spore-bg text-spore-muted border-spore-border/50 hover:text-spore-text hover:bg-spore-accent/50'
                        }`}
                      >
                        暗色
                      </button>
                      <button
                        onClick={() => setTheme('light')}
                        className={`px-3 py-1.5 rounded-lg text-sm border transition-colors ${
                          theme === 'light'
                            ? 'bg-spore-highlight/20 text-spore-highlight border-spore-highlight/60'
                            : 'bg-spore-bg text-spore-muted border-spore-border/50 hover:text-spore-text hover:bg-spore-accent/50'
                        }`}
                      >
                        亮色
                      </button>
                    </div>
                  </div>
                  
                  {/* 角色选择 */}
                  <div className="space-y-2">
                    <div className="text-sm text-spore-text">角色</div>
                    {charactersLoading ? (
                      <div className="text-xs text-spore-muted">加载中...</div>
                    ) : (
                      <select
                        value={currentCharacter}
                        onChange={(e) => handleSelectCharacter(e.target.value)}
                        className="w-full px-3 py-2 bg-spore-bg border border-spore-border/50 rounded-lg text-sm text-spore-text focus:outline-none focus:ring-2 focus:ring-spore-highlight/50"
                      >
                        <option value="">无角色</option>
                        {characters.map((char) => (
                          <option key={char.name} value={char.name}>
                            {char.name}
                          </option>
                        ))}
                      </select>
                    )}
                    <div className="text-xs text-spore-muted">
                      选择角色后会在对话中自动应用，选择"无角色"则禁用角色系统
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
                      <span className="text-sm text-spore-text">启动时自动清理短日志</span>
                    </label>
                    {autoCleanShortLogs && (
                      <div className="ml-7 flex items-center gap-2">
                        <span className="text-xs text-spore-muted">最小行数:</span>
                        <input
                          type="number"
                          min={1}
                          max={100}
                          value={autoCleanMinLines}
                          onChange={(e) => setAutoCleanMinLines(Number(e.target.value) || 10)}
                          className="w-16 px-2 py-1 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-accent"
                        />
                        <span className="text-xs text-spore-muted">行</span>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="space-y-6">
                  <div className="space-y-3 rounded-xl border border-spore-border/50 bg-spore-bg/40 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-medium text-spore-text">API 配置套</div>
                        <div className="text-xs text-spore-muted">按当前 SDK 保存对应的 API 地址、Key、模型和兼容参数。</div>
                      </div>
                      <button
                        onClick={handleSaveConfigProfile}
                        disabled={profileBusy || envLoading}
                        className="px-3 py-1.5 bg-spore-highlight hover:bg-spore-highlight-hover text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                      >
                        保存当前
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
                          {configProfiles.length === 0 ? '暂无配置套' : '未匹配配置套'}
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
                        {profileBusy ? '处理中...' : '应用'}
                      </button>
                      <button
                        onClick={handleDeleteConfigProfile}
                        disabled={profileBusy || envLoading || !activeProfileId}
                        className="px-3 py-2 bg-spore-bg hover:bg-spore-error/10 text-spore-muted hover:text-spore-error border border-spore-border/50 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                      >
                        删除
                      </button>
                    </div>
                  </div>
                  {envLoading ? (
                    <div className="flex items-center justify-center h-32">
                      <span className="text-spore-muted">加载中...</span>
                    </div>
                  ) : (
                    <>
                      {/* 基础配置：最小可用 */}
                      <div className="space-y-4">
                        <div className="flex items-baseline justify-between gap-2">
                          <h4 className="text-sm font-semibold text-spore-text">基础配置</h4>
                          <span className="text-[11px] text-spore-muted">最小可用：SDK + Key / URL / 模型</span>
                        </div>
                        {ENV_BASIC_CONFIG_GROUPS.map((group) => {
                          const selectedSdk = (envValues['LLM_SDK'] || '').toLowerCase();
                          const isDisabled =
                            (group.title === 'Anthropic API' && selectedSdk === 'openai') ||
                            (group.title === 'OpenAI API' && selectedSdk === 'anthropic');

                          return (
                            <div key={group.title} className={`space-y-3 ${isDisabled ? 'opacity-40' : ''}`}>
                              <h5 className="text-sm font-medium text-spore-highlight border-b border-spore-border/30 pb-2">
                                {group.title}
                              </h5>
                              <div className="space-y-3">
                                {group.items.map((item) => (
                                  <div key={item.key} className="space-y-1">
                                    <label className="flex items-center gap-2 text-xs text-spore-muted">
                                      <span>{item.label}</span>
                                      {item.description && (
                                        <span className="text-spore-muted/60">({item.description})</span>
                                      )}
                                    </label>
                                    {item.type === 'select' ? (
                                      <select
                                        value={envValues[item.key] || ''}
                                        onChange={(e) => updateEnvValue(item.key, e.target.value)}
                                        disabled={isDisabled}
                                        className={`w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50 ${isDisabled ? 'cursor-not-allowed' : ''}`}
                                      >
                                        <option value="">{item.placeholder || '未设置'}</option>
                                        {item.options?.map((opt) => (
                                          <option key={opt.value} value={opt.value}>
                                            {opt.label}
                                          </option>
                                        ))}
                                      </select>
                                    ) : (
                                      <input
                                        type={item.type === 'number' ? 'number' : 'text'}
                                        value={envValues[item.key] || ''}
                                        onChange={(e) => updateEnvValue(item.key, e.target.value)}
                                        placeholder={item.placeholder}
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
                            <div className="text-sm font-semibold text-spore-text">高级配置</div>
                            <div className="text-[11px] text-spore-muted">
                              兼容性、子 Agent、超时、日志、路径、拦截等
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
                            {ENV_ADVANCED_CONFIG_GROUPS.map((group) => {
                              const selectedSdk = (envValues['LLM_SDK'] || '').toLowerCase();
                              const isDisabled =
                                (group.title === 'Anthropic 高级' && selectedSdk === 'openai') ||
                                (group.title === 'OpenAI 高级' && selectedSdk === 'anthropic');

                              return (
                                <div key={group.title} className={`space-y-3 ${isDisabled ? 'opacity-40' : ''}`}>
                                  <h5 className="text-sm font-medium text-spore-highlight border-b border-spore-border/30 pb-2">
                                    {group.title}
                                  </h5>
                                  <div className="space-y-3">
                                    {group.items.map((item) => (
                                      <div key={item.key} className="space-y-1">
                                        <label className="flex items-center gap-2 text-xs text-spore-muted">
                                          <span>{item.label}</span>
                                          {item.description && (
                                            <span className="text-spore-muted/60">({item.description})</span>
                                          )}
                                        </label>
                                        {item.type === 'select' ? (
                                          <select
                                            value={envValues[item.key] || ''}
                                            onChange={(e) => updateEnvValue(item.key, e.target.value)}
                                            disabled={isDisabled}
                                            className={`w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50 ${isDisabled ? 'cursor-not-allowed' : ''}`}
                                          >
                                            <option value="">{item.placeholder || '未设置'}</option>
                                            {item.options?.map((opt) => (
                                              <option key={opt.value} value={opt.value}>
                                                {opt.label}
                                              </option>
                                            ))}
                                          </select>
                                        ) : (
                                          <input
                                            type={item.type === 'number' ? 'number' : 'text'}
                                            value={envValues[item.key] || ''}
                                            onChange={(e) => updateEnvValue(item.key, e.target.value)}
                                            placeholder={item.placeholder}
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
                        )}
                      </div>
                    </>
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
