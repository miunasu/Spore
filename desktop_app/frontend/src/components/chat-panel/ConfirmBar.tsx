/**
 * 确认栏组件 - 通用的操作确认UI
 * 显示在输入区上方，用于确认删除等危险操作
 */
import React from 'react';
import { useConfirmStore } from '../../stores/confirmStore';
import { wsService } from '../../services/websocket';
import { useT } from '../../i18n';

export const ConfirmBar: React.FC = () => {
  const t = useT();
  const { pendingRequests, removeRequest } = useConfirmStore();

  // 队列化：始终显示最早到达的请求，其余排队等待
  const pendingRequest = pendingRequests[0];
  const queuedCount = pendingRequests.length - 1;

  if (!pendingRequest) {
    return null;
  }

  const handleRespond = (confirmed: boolean) => {
    // 通过 WebSocket 发送响应
    const sent = wsService.sendConfirmResponse(pendingRequest.request_id, confirmed);
    if (sent) {
      removeRequest(pendingRequest.request_id);
    }
  };

  // 操作类型图标
  const getActionIcon = (actionType: string) => {
    switch (actionType) {
      case 'delete':
        return '🗑️';
      case 'overwrite':
        return '📝';
      case 'security_high':
        return '🚨';
      case 'security_medium':
      case 'security_low':
      case 'security':
        return '⚡';
      default:
        return '⚠️';
    }
  };

  // 操作类型颜色
  const getActionColor = (actionType: string) => {
    switch (actionType) {
      case 'delete':
      case 'security_high':
        return 'border-red-500/50 bg-red-500/10';
      case 'security_medium':
      case 'security':
        return 'border-amber-500/50 bg-amber-500/10';
      case 'security_low':
        return 'border-emerald-500/50 bg-emerald-500/10';
      default:
        return 'border-yellow-500/50 bg-yellow-500/10';
    }
  };

  // 确认按钮：高危操作用更醒目的措辞
  const isHighRisk = pendingRequest.action_type === 'security_high';
  const confirmLabel = isHighRisk ? t('confirmBar.highRiskConfirm') : t('common.confirm');

  return (
    <div className={`mb-3 rounded-xl border ${getActionColor(pendingRequest.action_type)} overflow-hidden`}>
      {/* 主要信息行 */}
      <div className="flex items-center gap-3 px-4 py-3">
        {/* 图标 */}
        <span className="text-lg flex-shrink-0">
          {getActionIcon(pendingRequest.action_type)}
        </span>

        {/* 消息 */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <div className="text-sm font-medium text-spore-text">
              {pendingRequest.title}
            </div>
            {queuedCount > 0 && (
              <span className="text-[11px] px-1.5 py-0.5 rounded bg-spore-accent/40 text-spore-muted flex-shrink-0">
                {t('confirmBar.queued', { n: queuedCount })}
              </span>
            )}
          </div>
          <div className="text-xs text-spore-muted">
            {pendingRequest.message}
          </div>
        </div>

        {/* 操作按钮 */}
        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            onClick={() => handleRespond(false)}
            className="px-3 py-1.5 text-sm rounded-lg bg-spore-accent hover:bg-spore-border text-spore-text transition-colors"
          >
            {t('common.cancel')}
          </button>
          <button
            onClick={() => handleRespond(true)}
            className="px-3 py-1.5 text-sm rounded-lg bg-red-600 hover:bg-red-700 text-white transition-colors whitespace-nowrap"
          >
            {confirmLabel}
          </button>
        </div>
      </div>

      {/* 详情列表 - 默认展开 */}
      {pendingRequest.details.length > 0 && (
        <div className="px-4 pb-3 border-t border-spore-border/30">
          <div className="mt-2 max-h-40 overflow-y-auto space-y-1">
            {pendingRequest.details.map((detail, index) => (
              <div
                key={index}
                className="text-xs text-spore-muted font-mono truncate"
                title={detail}
              >
                • {detail}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
