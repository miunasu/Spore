/**
 * 命令菜单组件 - 现代化设计
 */
import React, { useState, useEffect } from 'react';
import { useChatStore } from '../../stores/chatStore';
import { useSettingsStore } from '../../stores/settingsStore';
import { commandsApi, filesApi, settingsApi, backupApi, ApiError } from '../../services/api';

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
];

const ENV_ADVANCED_CONFIG_GROUPS: EnvConfigGroup[] = [
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
  {
    title: '备份恢复',
    items: [
      {
        key: 'BACKUP_ENABLED',
        label: '备份系统',
        type: 'select',
        options: [
          { value: 'true', label: '开启（推荐）' },
          { value: 'false', label: '关闭' },
        ],
        description: '总开关：文件写操作自动增量备份 + 每轮对话点快照，支持文件级/对话级回滚',
        placeholder: '默认: true',
      },
      {
        key: 'BACKUP_DIR',
        label: '备份目录',
        type: 'text',
        description: '备份数据存储目录（相对项目根目录或绝对路径）；修改后需重启后端生效',
        placeholder: '默认: .spore',
      },
      {
        key: 'BACKUP_MAX_FILE_BYTES',
        label: '单文件备份上限',
        type: 'number',
        description: '超过该大小（字节）的文件跳过备份，避免占用过多空间',
        placeholder: '默认: 52428800（50MB）',
      },
      {
        key: 'BACKUP_MAX_DELETE_FILES',
        label: '删除目录备份上限',
        type: 'number',
        description: '删除目录时最多备份的文件数量',
        placeholder: '默认: 200',
      },
    ],
  },
  {
    title: '安全 Agent',
    items: [
      {
        key: 'SECURITY_AGENT_MODE',
        label: '安全 Agent 模式',
        type: 'select',
        options: [
          { value: 'off', label: 'off（关闭）' },
          { value: 'basic', label: 'basic（高危命令 AI 风险评估）' },
          { value: 'full', label: 'full（basic + 普通命令意图与恶意研判）' },
        ],
        description: 'off 全关；basic 仅对命中高危关键词的命令做 AI 风险评估与确认；full 额外对普通命令做意图解析+恶意研判，判定恶意时自动中断本轮会话',
        placeholder: '默认: full',
      },
      {
        key: 'SECURITY_GUARD_MODE',
        label: '风险容忍度',
        type: 'select',
        options: [
          { value: 'strict', label: 'strict（命中即确认）' },
          { value: 'balanced', label: 'balanced（低风险自动放行）' },
          { value: 'permissive', label: 'permissive（低+中风险放行）' },
        ],
        description: 'strict 最谨慎；balanced 平衡；permissive 仅高风险才拦截',
        placeholder: '默认: balanced',
      },
      {
        key: 'SECURITY_LLM_TIMEOUT',
        label: '风险评估超时',
        type: 'number',
        description: '高危命令 AI 风险评估的超时时间（秒）',
        placeholder: '默认: 30',
      },
      {
        key: 'SECURITY_INTENT_TIMEOUT',
        label: '意图研判超时',
        type: 'number',
        description: 'full 模式下普通命令意图/恶意研判的超时时间（秒）',
        placeholder: '默认: 45',
      },
    ],
  },
];

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
}> = ({ group, envValues, updateEnvValue }) => (
  <div className="space-y-3">
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
              className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50"
            >
              <option value="">{item.placeholder || '未设置'}</option>
              {item.options?.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          ) : (
            <input
              type={item.type === 'number' ? 'number' : 'text'}
              value={envValues[item.key] || ''}
              onChange={(e) => updateEnvValue(item.key, e.target.value)}
              placeholder={item.placeholder}
              className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50 font-mono"
            />
          )}
        </div>
      ))}
    </div>
  </div>
);

// Agent 基座配置目标：子 Agent 是所有 AutoAgent 的默认基座，
// 其余 4 个 AutoAgent 可各自覆盖（字段留空则回退到子 Agent → 主 Agent）
type AgentBaseTarget = {
  id: string;
  label: string;
  prefix: string; // env key 前缀
  hint: string;
};

const AGENT_BASE_TARGETS: AgentBaseTarget[] = [
  { id: 'sub_agent', label: '子 Agent（默认基座）', prefix: 'SUB_AGENT', hint: '所有子 Agent / AutoAgent 的默认基座；留空则继承主 Agent' },
  { id: 'supervisor', label: 'Supervisor（循环检测）', prefix: 'AGENT_SUPERVISOR', hint: '检测对话是否结束；留空则继承子 Agent' },
  { id: 'mode_selector', label: 'ModeSelector（模式选择）', prefix: 'AGENT_MODE_SELECTOR', hint: '自动选择上下文模式；留空则继承子 Agent' },
  { id: 'security', label: 'Security（安全 Agent）', prefix: 'AGENT_SECURITY', hint: '高危命令风险评估 + 普通命令意图/恶意研判；推荐 Sonnet/GPT-4o-mini 级模型；留空则继承子 Agent' },
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
  const target =
    AGENT_BASE_TARGETS.find((t) => t.id === agentBaseTarget) || AGENT_BASE_TARGETS[0];
  const keys = agentBaseKeys(target.prefix);
  const targetSdk = (envValues[keys.sdk] || '').toLowerCase();
  const subSdk = (envValues['SUB_AGENT_LLM_SDK'] || '').toLowerCase();
  const mainSdk = (envValues['LLM_SDK'] || '').toLowerCase() || 'openai';
  // 有效 SDK：决定展示哪一套字段（该目标显式选择 → 子 Agent → 主 Agent）
  const effectiveSdk = targetSdk || (target.id !== 'sub_agent' ? subSdk : '') || mainSdk;
  const isAnthropic = effectiveSdk === 'anthropic';
  const inheritHint = target.id === 'sub_agent' ? '默认: 继承主 Agent' : '默认: 继承子 Agent';
  return (
    <div className="space-y-3">
      <h5 className="text-sm font-medium text-spore-highlight border-b border-spore-border/30 pb-2">
        Agent 基座（颗粒化）
      </h5>
      <p className="text-[11px] text-spore-muted/70 -mt-1">
        每个目标拥有独立的基座 + 高级参数（effort/thinking），与主 Agent 互不影响；任一字段留空即继承上层基座。
      </p>
      {/* 配置目标下拉 */}
      <div className="space-y-1">
        <label className="text-xs text-spore-muted">配置目标</label>
        <select
          value={agentBaseTarget}
          onChange={(e) => setAgentBaseTarget(e.target.value)}
          className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-highlight/40 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/60"
        >
          {AGENT_BASE_TARGETS.map((t) => (
            <option key={t.id} value={t.id}>
              {t.label}
            </option>
          ))}
        </select>
        <p className="text-[11px] text-spore-muted/70">{target.hint}</p>
      </div>
      {/* SDK 选择 */}
      <div className="space-y-1">
        <label className="text-xs text-spore-muted">SDK 类型</label>
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
        { show: !isAnthropic, label: 'OpenAI Key', k: keys.openaiKey },
        { show: !isAnthropic, label: 'OpenAI URL', k: keys.openaiUrl },
        { show: !isAnthropic, label: 'OpenAI 模型', k: keys.openaiModel },
        { show: isAnthropic, label: 'Anthropic Key', k: keys.anthropicKey },
        { show: isAnthropic, label: 'Anthropic URL', k: keys.anthropicUrl },
        { show: isAnthropic, label: 'Anthropic 模型', k: keys.anthropicModel },
      ]
        .filter((f) => f.show)
        .map((f) => (
          <div key={f.k} className="space-y-1">
            <label className="text-xs text-spore-muted">{f.label}</label>
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
          高级参数 · {isAnthropic ? 'Anthropic' : 'OpenAI'}（留空继承上层基座）
        </p>
        {!isAnthropic && (
          <>
            <div className="space-y-1">
              <label className="text-xs text-spore-muted">使用 Responses API</label>
              <select
                value={envValues[keys.useResponsesApi] || ''}
                onChange={(e) => updateEnvValue(keys.useResponsesApi, e.target.value)}
                className="w-full px-3 py-2 text-sm bg-spore-bg border border-spore-border/50 rounded-lg text-spore-text focus:outline-none focus:border-spore-highlight/50"
              >
                <option value="">{inheritHint}</option>
                <option value="true">是</option>
                <option value="false">否</option>
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
                <option value="none">none（明确不传此参数）</option>
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
                <option value="none">none（明确不传此参数）</option>
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
                <option value="adaptive">adaptive（推荐）</option>
                <option value="enabled">enabled（手动 budget）</option>
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
    { value: 'session', label: '仅当前会话', description: '每个会话独立配置工具开关' },
    { value: 'global', label: '全局', description: '所有会话共用同一套工具开关' },
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
  const applyToolPolicyResponse = (response: any) => {
    if (!response?.success) {
      setToolPolicyError(response?.error || '加载工具策略失败');
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
      setToolPolicyError('加载工具策略失败');
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
        setToolPolicyError(response.error || '保存失败');
        return;
      }
      applyToolPolicyResponse(response);
    } catch {
      setToolPolicyError('保存工具策略失败');
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
        setToolPolicyError(response.error || '重置失败');
        return;
      }
      // reload full view to refresh catalog/policy consistently
      await loadToolPolicy(toolPolicyMode);
    } catch {
      setToolPolicyError('重置工具策略失败');
    } finally {
      setToolPolicySaving(false);
    }
  };

  const changeToolPolicyScope = async (scope: 'session' | 'global') => {
    if (scope === toolPolicyScope) return;
    if (toolPolicyDirty) {
      const ok = window.confirm('当前有未保存的工具开关修改，切换作用域将丢弃它们，是否继续？');
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
        setToolPolicyError(response.error || '切换作用域失败');
        return;
      }
      applyToolPolicyResponse(response);
    } catch {
      setToolPolicyError('切换作用域失败');
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
        '当前有未保存的工具开关修改，切换会话将丢弃它们，是否继续？'
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
      setBackupError(extractApiError(err, '加载对话点失败'));
    } finally {
      setBackupLoading(false);
    }
  };

  const loadTrackedFiles = async () => {
    setBackupLoading(true);
    setBackupError(null);
    setFileHistory(null);
    try {
      const res = await backupApi.listTrackedFiles();
      setTrackedFiles(res.files || []);
    } catch (err) {
      setBackupError(extractApiError(err, '加载备份文件列表失败'));
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
      `回滚到对话点 ${checkpointId}？\n将同时恢复文件和对话历史，该对话点之后的修改会被撤销。`
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
        `已回到对话点 ${res.checkpoint} (${res.ts})`,
        `对话历史: 截断到 ${res.message_count} 条消息`,
      ];
      if (res.restored.length) {
        lines.push(`恢复文件 ${res.restored.length} 个:`, ...res.restored.map((p) => `  - ${p}`));
      }
      if (res.deleted.length) {
        lines.push(
          `删除文件（回滚创建操作）${res.deleted.length} 个:`,
          ...res.deleted.map((p) => `  - ${p}`)
        );
      }
      if (res.skipped.length) {
        lines.push(
          `跳过（仅其它会话修改）${res.skipped.length} 个:`,
          ...res.skipped.map((p) => `  - ${p}`)
        );
      }
      if (res.failed.length) {
        lines.push(
          `失败 ${res.failed.length} 个:`,
          ...res.failed.map((f) => `  - ${f.path}: ${f.error}`)
        );
      }
      setModalContent({
        title: res.success ? '回滚成功' : '回滚部分成功',
        content: lines.join('\n'),
      });
    } catch (err) {
      setBackupError(extractApiError(err, '回滚失败'));
    } finally {
      setBackupBusy(false);
    }
  };

  const loadFileHistory = async (path: string) => {
    setBackupLoading(true);
    setBackupError(null);
    try {
      const res = await backupApi.getFileHistory(path);
      setFileHistory({
        path: res.path,
        has_baseline: res.has_baseline,
        versions: res.versions || [],
      });
    } catch (err) {
      setBackupError(extractApiError(err, '加载文件历史失败'));
    } finally {
      setBackupLoading(false);
    }
  };

  const handleRestoreFile = async (path: string, versionId: number) => {
    const label = versionId === 0 ? 'baseline（首次备份前的原始内容）' : `v${versionId}`;
    if (!window.confirm(`将文件恢复到 ${label}？\n${path}`)) return;
    setBackupBusy(true);
    setBackupError(null);
    try {
      const res = await backupApi.restoreFile({ path, version_id: versionId });
      await loadFileHistory(path);
      setModalContent({
        title: '恢复成功',
        content: res.deleted
          ? `${res.path}\n已恢复到 v${res.restored_to_version}（该版本文件不存在，已删除）`
          : `${res.path}\n已恢复到 v${res.restored_to_version}`,
      });
    } catch (err) {
      setBackupError(extractApiError(err, '恢复文件失败'));
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
      id: 'backup',
      label: '备份回滚',
      icon: 'M9 15L3 9m0 0l6-6M3 9h12a6 6 0 010 12h-3',
      action: async () => {
        openBackup();
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
              设置
            </button>
          </div>
        </>
      )}

      {/* 设置模态框（带标签页） */}
      {showSettings && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 animate-fade-in">
          <div className="bg-spore-card border border-spore-border/50 rounded-2xl w-[680px] max-w-[90vw] max-h-[85vh] overflow-hidden shadow-elevated flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-spore-border/30">
              <h3 className="font-semibold text-spore-text">设置</h3>
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
                onClick={() => setSettingsTab('llm')}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  settingsTab === 'llm'
                    ? 'text-spore-highlight border-b-2 border-spore-highlight'
                    : 'text-spore-muted hover:text-spore-text'
                }`}
              >
                LLM 设置
              </button>
              <button
                onClick={() => setSettingsTab('agent')}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  settingsTab === 'agent'
                    ? 'text-spore-highlight border-b-2 border-spore-highlight'
                    : 'text-spore-muted hover:text-spore-text'
                }`}
              >
                Agent 设置
              </button>
              <button
                onClick={() => setSettingsTab('system')}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  settingsTab === 'system'
                    ? 'text-spore-highlight border-b-2 border-spore-highlight'
                    : 'text-spore-muted hover:text-spore-text'
                }`}
              >
                系统
              </button>
              <button
                onClick={() => { setSettingsTab('tools'); loadToolPolicy(toolPolicyMode); }}
                className={`px-4 py-2 text-sm font-medium transition-colors ${
                  settingsTab === 'tools'
                    ? 'text-spore-highlight border-b-2 border-spore-highlight'
                    : 'text-spore-muted hover:text-spore-text'
                }`}
              >
                工具策略
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              {settingsTab === 'tools' ? (
                <div className="space-y-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="text-sm text-spore-text font-medium">工具策略</div>
                      <div className="text-xs text-spore-muted">关闭后：工具说明 / 协议注入 / 执行校验都会剔除对应能力。作用域可在「仅当前会话」与「全局」之间切换。</div>
                      <div className="text-xs text-spore-muted">
                        当前会话模式: <span className="text-spore-highlight">{toolContextMode}</span>
                        {" · "}
                        编辑基线: <span className="text-spore-highlight">{toolPolicyMode}</span>
                        {toolPolicyDirty ? " · 未保存" : ""}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <button
                        onClick={() => resetToolPolicy()}
                        disabled={toolPolicyLoading || toolPolicySaving}
                        className="px-3 py-1.5 text-xs rounded-lg border border-spore-border/50 text-spore-muted hover:text-spore-text hover:bg-spore-accent/40 disabled:opacity-50"
                      >
                        重置
                      </button>
                      <button
                        onClick={() => saveToolPolicy()}
                        disabled={toolPolicyLoading || toolPolicySaving || !toolPolicyDirty}
                        className="px-3 py-1.5 text-xs rounded-lg bg-spore-highlight hover:bg-spore-highlight-hover text-white disabled:opacity-50"
                      >
                        {toolPolicySaving ? "保存中..." : "保存"}
                      </button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="text-xs text-spore-muted">作用域</div>
                    <div className="flex items-center gap-2">
                      {toolPolicyScopes.map((s) => (
                        <button
                          key={s.value}
                          onClick={() => changeToolPolicyScope(s.value as 'session' | 'global')}
                          disabled={toolPolicyLoading || toolPolicySaving}
                          title={s.description || s.label}
                          className={`px-3 py-1.5 rounded-lg text-xs border transition-colors disabled:opacity-50 ${
                            toolPolicyScope === s.value
                              ? 'bg-spore-highlight/20 text-spore-highlight border-spore-highlight/60'
                              : 'bg-spore-bg text-spore-muted border-spore-border/50 hover:text-spore-text hover:bg-spore-accent/50'
                          }`}
                        >
                          {s.label}
                        </button>
                      ))}
                    </div>
                    <div className="text-[11px] text-spore-muted">
                      {toolPolicyScope === 'global'
                        ? '全局：所有会话共用 tool_policy.json 中的开关配置'
                        : '仅当前会话：只影响当前对话，其它会话保持各自配置'}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="text-xs text-spore-muted">编辑的模式基线</div>
                    <div className="flex items-center gap-2">
                      {(["strong_context", "long_context"] as const).map((m) => (
                        <button
                          key={m}
                          onClick={() => {
                            if (m === toolPolicyMode) return;
                            if (toolPolicyDirty) {
                              const ok = window.confirm(
                                '当前有未保存的工具开关修改，切换模式基线将丢弃它们，是否继续？'
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
                          {m === "strong_context" ? "强上下文工具集" : "长上下文工具集"}
                        </button>
                      ))}
                    </div>
                  </div>

                  {toolPolicyError && (
                    <div className="text-xs text-spore-error">{toolPolicyError}</div>
                  )}

                  {toolPolicyLoading ? (
                    <div className="text-sm text-spore-muted py-8 text-center">加载中...</div>
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
                                启用
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
                                        启用
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
                          当前模式无可用工具
                        </div>
                      )}
                      <div className="text-[11px] text-spore-muted">
                        已启用顶层工具: {toolEnabledList.join(", ") || "无"}
                      </div>
                    </div>
                  )}
                </div>
              ) : settingsTab === 'general' ? (
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
              ) : settingsTab === 'llm' ? (
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
                          const isOpenAiGroup = group.title.startsWith('OpenAI');
                          const isAnthropicGroup = group.title.startsWith('Anthropic');
                          const isDisabled =
                            (isAnthropicGroup && selectedSdk === 'openai') ||
                            (isOpenAiGroup && selectedSdk === 'anthropic');

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
                              LLM 参数、SDK 兼容性
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
              <h3 className="font-semibold text-spore-text">备份回滚</h3>
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
                  刷新
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
                对话点
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
                文件备份
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              {backupLoading ? (
                <div className="text-sm text-spore-muted py-8 text-center">加载中...</div>
              ) : backupTab === 'checkpoints' ? (
                <div className="space-y-3">
                  <div className="text-xs text-spore-muted">
                    只有当某条 LLM 回复实际修改了文件时才会产生对话点。回滚即回到这条回复之前：
                    截断当前会话的对话历史，并把本会话在该点之后修改过的文件恢复到当时的版本；
                    其它会话修改的文件不受影响。
                  </div>
                  {checkpoints.length === 0 ? (
                    <div className="text-sm text-spore-muted text-center py-6">
                      当前会话没有对话点快照
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
                          </div>
                          <div
                            className="text-xs text-spore-text/80 mt-1 line-clamp-2"
                            title={cp.reply_preview || undefined}
                          >
                            {cp.reply_preview || '（工具执行轮，无文字回复）'}
                          </div>
                          <div className="text-xs text-spore-muted mt-0.5">
                            消息数 {cp.message_count} · 跟踪文件 {Object.keys(cp.files || {}).length}
                          </div>
                        </div>
                        <button
                          onClick={() => handleRewind(cp.id)}
                          disabled={backupBusy}
                          className="px-3 py-1.5 bg-spore-highlight hover:bg-spore-highlight-hover text-white rounded-lg text-xs font-medium transition-colors disabled:opacity-50 flex-shrink-0"
                        >
                          {backupBusy ? '回滚中...' : '回滚到此'}
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
                    ← 返回文件列表
                  </button>
                  <div className="text-sm text-spore-text font-mono break-all">{fileHistory.path}</div>
                  <div className="space-y-2">
                    {fileHistory.has_baseline && (
                      <div className="flex items-center justify-between gap-3 rounded-xl border border-spore-border/50 bg-spore-bg/40 p-3">
                        <div className="min-w-0">
                          <div className="text-sm text-spore-text font-medium">v0 · baseline</div>
                          <div className="text-xs text-spore-muted mt-0.5">首次备份前的原始内容</div>
                        </div>
                        <button
                          onClick={() => handleRestoreFile(fileHistory.path, 0)}
                          disabled={backupBusy}
                          className="px-3 py-1.5 bg-spore-bg hover:bg-spore-accent/60 text-spore-text border border-spore-border/50 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 flex-shrink-0"
                        >
                          恢复
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
                              {v.op} · {v.store === 'delete' ? '删除' : `${v.size} bytes`}
                            </div>
                          </div>
                          <button
                            onClick={() => handleRestoreFile(fileHistory.path, v.id)}
                            disabled={backupBusy}
                            className="px-3 py-1.5 bg-spore-bg hover:bg-spore-accent/60 text-spore-text border border-spore-border/50 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 flex-shrink-0"
                          >
                            恢复
                          </button>
                        </div>
                      ))}
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  <div className="text-xs text-spore-muted">
                    Agent 每次写文件前都会自动备份，点击文件查看版本历史并恢复到任意版本。
                  </div>
                  {trackedFiles.length === 0 ? (
                    <div className="text-sm text-spore-muted text-center py-6">尚无被跟踪的文件备份</div>
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
