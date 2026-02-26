/**
 * Todo 进度条组件
 * 显示在聊天区顶部，可折叠展开
 */
import React from 'react';
import { useTodoStore } from '../../stores/todoStore';

export const TodoBar: React.FC = () => {
  const { todos, isExpanded, toggleExpanded } = useTodoStore();

  // 没有任务时不显示
  if (todos.length === 0) {
    return null;
  }

  // 统计
  const completed = todos.filter((t) => t.status === 'completed').length;
  const failed = todos.filter((t) => t.status === 'failed').length;
  const total = todos.length;

  // 当前任务（第一个 pending）
  const currentTask = todos.find((t) => t.status === 'pending');

  // 进度百分比
  const progress = total > 0 ? ((completed + failed) / total) * 100 : 0;

  // 状态图标
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <span className="text-green-400">✓</span>;
      case 'failed':
        return <span className="text-red-400">✗</span>;
      default:
        return <span className="text-spore-muted">○</span>;
    }
  };

  return (
    <div className="border-b border-spore-border/30 bg-spore-card/50">
      {/* 摘要行 */}
      <div
        onClick={toggleExpanded}
        className="flex items-center gap-3 px-4 py-2 cursor-pointer hover:bg-spore-accent/20 transition-colors"
      >
        {/* 展开图标 */}
        <svg
          className={`w-3 h-3 text-spore-muted transition-transform ${isExpanded ? 'rotate-90' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>

        {/* 图标 */}
        <span className="text-sm">📋</span>

        {/* 当前任务 */}
        <span className="flex-1 text-sm text-spore-text truncate">
          {currentTask ? currentTask.content : '所有任务已完成'}
        </span>

        {/* 进度 */}
        <span className="text-xs text-spore-muted">
          [{completed}/{total}]
        </span>

        {/* 进度条 */}
        <div className="w-20 h-1.5 bg-spore-border/30 rounded-full overflow-hidden">
          <div
            className="h-full bg-spore-highlight transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {/* 展开详情 */}
      {isExpanded && (
        <div className="px-4 pb-3 space-y-1 max-h-48 overflow-y-auto">
          {todos.map((todo) => (
            <div
              key={todo.id}
              className={`flex items-center gap-2 text-sm py-1 ${
                todo.status === 'pending' ? 'text-spore-text' : 'text-spore-muted'
              }`}
            >
              {getStatusIcon(todo.status)}
              <span className={todo.status === 'completed' ? 'line-through' : ''}>
                {todo.id}. {todo.content}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
