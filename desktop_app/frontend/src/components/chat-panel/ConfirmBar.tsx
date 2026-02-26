/**
 * 确认栏组件 - 通用的操作确认UI
 * 显示在输入区上方，用于确认删除等危险操作
 */
import React from 'react';
import { useConfirmStore } from '../../stores/confirmStore';
import { wsService } from '../../services/websocket';

export const ConfirmBar: React.FC = () => {
  const { pendingRequest, clearRequest } = useConfirmStore();

  if (!pendingRequest) {
    return null;
  }

  const handleRespond = (confirmed: boolean) => {
    // 通过 WebSocket 发送响应
    const sent = wsService.sendConfirmResponse(pendingRequest.request_id, confirmed);
    if (sent) {
      clearRequest();
    }
  };

  // 操作类型图标
  const getActionIcon = (actionType: string) => {
    switch (actionType) {
      case 'delete':
        return '🗑️';
      case 'overwrite':
        return '📝';
      default:
        return '⚠️';
    }
  };

  // 操作类型颜色
  const getActionColor = (actionType: string) => {
    switch (actionType) {
      case 'delete':
        return 'border-red-500/50 bg-red-500/10';
      default:
        return 'border-yellow-500/50 bg-yellow-500/10';
    }
  };

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
          <div className="text-sm font-medium text-spore-text">
            {pendingRequest.title}
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
            取消
          </button>
          <button
            onClick={() => handleRespond(true)}
            className="px-3 py-1.5 text-sm rounded-lg bg-red-600 hover:bg-red-700 text-white transition-colors"
          >
            确认
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
