/**
 * 安全熔断弹窗 —— 恶意命令研判结果 + 处置建议 + 手动/自动修复选择
 *
 * security_malicious 触发熔断后立即弹出（研判结果先行展示，处置建议加载中）；
 * security_remediation 到达后补充建议并解锁"自动修复"。多起事件排队逐个处理。
 * 全局挂载（App.tsx），普通模式与 Mini 模式均生效。
 */
import React from 'react';
import { useSecurityStore } from '../../stores/securityStore';
import { useChatStore } from '../../stores/chatStore';

export const SecurityRemediationModal: React.FC = () => {
  const incidents = useSecurityStore((state) => state.incidents);
  const removeIncident = useSecurityStore((state) => state.removeIncident);
  const conversations = useChatStore((state) => state.conversations);

  const incident = incidents[0];
  if (!incident) return null;

  const queuedCount = incidents.length - 1;
  const sourceConv = conversations.find((c) => c.id === incident.sessionId);

  // 手动处理：把处置建议留档到源会话（本地消息），关闭弹窗
  const handleManual = () => {
    if (incident.adviceReady) {
      const steps = (incident.manualSteps || [])
        .map((s, i) => `${i + 1}. ${s}`)
        .join('\n');
      useChatStore.getState().addMessage(incident.sessionId, {
        id: `remediation_${Date.now()}`,
        role: 'assistant',
        content:
          `🛡️ 安全 Agent 处置建议（用户选择手动处理）\n` +
          (incident.summary ? `概述：${incident.summary}\n` : '') +
          (incident.impact ? `可能影响：${incident.impact}\n` : '') +
          (steps ? `排查/修复步骤：\n${steps}` : ''),
        timestamp: Date.now(),
      });
    }
    removeIncident(incident.id);
  };

  // 自动修复：新建会话，把安全 Agent 上下文作为用户输入交给 Spore
  const handleAutoFix = () => {
    const prompt = incident.autoFixPrompt;
    if (!prompt) return;
    removeIncident(incident.id);
    void useChatStore.getState().startSecurityAutoFix(prompt);
  };

  const autoFixDisabled = !incident.adviceReady || !incident.autoFixPrompt;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-lg rounded-xl border border-red-500/60 bg-spore-panel shadow-2xl overflow-hidden">
        {/* 标题栏 */}
        <div className="flex items-center gap-2 px-4 py-3 bg-red-500/10 border-b border-red-500/30">
          <span className="text-lg">🚨</span>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-semibold text-spore-text">
              安全 Agent 已熔断会话
              {sourceConv ? `（${sourceConv.name}）` : ''}
            </div>
            <div className="text-xs text-spore-muted">
              检测到恶意命令，已中断该会话及其子 Agent
            </div>
          </div>
          {queuedCount > 0 && (
            <span className="text-[11px] px-1.5 py-0.5 rounded bg-spore-accent/40 text-spore-muted flex-shrink-0">
              还有 {queuedCount} 起待处理
            </span>
          )}
        </div>

        {/* 研判结果 */}
        <div className="px-4 py-3 space-y-2 max-h-[55vh] overflow-y-auto">
          <div>
            <div className="text-xs text-spore-muted mb-1">恶意命令（已执行）</div>
            <div className="text-xs font-mono text-spore-text bg-spore-accent/30 rounded-lg px-2 py-1.5 break-all">
              {incident.command}
            </div>
          </div>
          {incident.intent && (
            <div className="text-xs text-spore-text">
              <span className="text-spore-muted">意图：</span>
              {incident.intent}
            </div>
          )}
          {incident.maliciousReason && (
            <div className="text-xs text-red-400">
              <span className="text-spore-muted">恶意原因：</span>
              {incident.maliciousReason}
            </div>
          )}

          {/* 处置建议 */}
          <div className="pt-2 border-t border-spore-border/30">
            {!incident.adviceReady ? (
              <div className="flex items-center gap-2 py-2 text-xs text-spore-muted">
                <span className="inline-block w-3 h-3 rounded-full border-2 border-spore-muted border-t-transparent animate-spin" />
                安全 Agent 正在生成处置建议…
              </div>
            ) : (
              <div className="space-y-2">
                {incident.summary && (
                  <div className="text-xs text-spore-text">
                    <span className="text-spore-muted">概述：</span>
                    {incident.summary}
                  </div>
                )}
                {incident.impact && (
                  <div className="text-xs text-spore-text">
                    <span className="text-spore-muted">可能影响：</span>
                    {incident.impact}
                  </div>
                )}
                {(incident.manualSteps || []).length > 0 && (
                  <div>
                    <div className="text-xs text-spore-muted mb-1">
                      排查 / 修复步骤
                    </div>
                    <ol className="space-y-1">
                      {(incident.manualSteps || []).map((step, index) => (
                        <li key={index} className="text-xs text-spore-text">
                          {index + 1}. {step}
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
                {incident.aiGenerated === false && (
                  <div className="text-[11px] text-spore-muted">
                    （AI 建议生成失败，以上为通用处置建议）
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* 操作按钮 */}
        <div className="flex items-center justify-end gap-2 px-4 py-3 border-t border-spore-border/30 bg-spore-accent/10">
          <button
            onClick={handleManual}
            className="px-3 py-1.5 text-sm rounded-lg bg-spore-accent hover:bg-spore-border text-spore-text transition-colors"
          >
            我来手动处理
          </button>
          <button
            onClick={handleAutoFix}
            disabled={autoFixDisabled}
            title={
              autoFixDisabled
                ? '等待安全 Agent 生成处置建议后可用'
                : '新建会话，由 Spore 按安全 Agent 的建议自动排查与修复'
            }
            className={`px-3 py-1.5 text-sm rounded-lg text-white transition-colors whitespace-nowrap ${
              autoFixDisabled
                ? 'bg-red-600/40 cursor-not-allowed'
                : 'bg-red-600 hover:bg-red-700'
            }`}
          >
            🔧 自动修复（新建会话）
          </button>
        </div>
      </div>
    </div>
  );
};
