/**
 * Agent 活动栏 - 非阻塞状态提示
 *
 * 显示安全 Agent 解析出的"Agent 正在做什么"命令意图、恶意告警，
 * 以及高危命令的风险扫描 / 自动放行提示。
 * 与 ConfirmBar（阻塞确认）互补：这里只做信息展示，不要求用户操作。
 */
import React from 'react';
import { useChatStore } from '../../stores/chatStore';

const RISK_STYLE: Record<string, string> = {
  low: 'text-emerald-400',
  medium: 'text-amber-400',
  high: 'text-red-400',
};

const RISK_LABEL: Record<string, string> = {
  low: '低风险',
  medium: '中风险',
  high: '高风险',
};

export const AgentActivityBar: React.FC = () => {
  const activity = useChatStore((state) => state.activeAgentActivity());

  if (!activity) {
    return null;
  }

  let icon = '💡';
  let label = '';
  let textClass = 'text-spore-muted';

  if (activity.kind === 'intent') {
    icon = '💡';
  } else if (activity.kind === 'security_checking') {
    icon = '🛡️';
    textClass = 'text-sky-400';
  } else if (activity.kind === 'security_malicious') {
    icon = '🚨';
    label = '恶意命令';
    textClass = 'text-red-400';
  } else if (activity.kind === 'security_alert') {
    icon = activity.riskLevel === 'high' ? '🚨' : '⚡';
    if (activity.riskLevel) {
      label = RISK_LABEL[activity.riskLevel] || '';
      textClass = RISK_STYLE[activity.riskLevel] || 'text-spore-muted';
    }
  }

  const pulsing = activity.kind === 'security_checking';

  return (
    <div className="mb-2 flex items-center gap-2 px-3 py-2 rounded-xl bg-spore-card/60 border border-spore-border/40">
      <span className={`text-base flex-shrink-0 ${pulsing ? 'animate-pulse' : ''}`}>
        {icon}
      </span>
      <div className="flex-1 min-w-0 flex items-center gap-2">
        {label && (
          <span className={`text-[11px] font-medium px-1.5 py-0.5 rounded ${textClass} bg-spore-accent/40 flex-shrink-0`}>
            {label}
          </span>
        )}
        <span className={`text-xs truncate ${textClass}`} title={activity.command || activity.text}>
          {activity.text}
        </span>
      </div>
    </div>
  );
};
