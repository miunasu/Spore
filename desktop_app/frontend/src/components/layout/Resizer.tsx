/**
 * 可拖拽调整大小的分隔条组件
 */
import React, { useCallback, useEffect, useState } from 'react';

interface ResizerProps {
  direction: 'horizontal' | 'vertical';
  onResize: (delta: number) => void;
  className?: string;
}

export const Resizer: React.FC<ResizerProps> = ({ direction, onResize, className = '' }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [startPos, setStartPos] = useState(0);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsDragging(true);
    setStartPos(direction === 'horizontal' ? e.clientX : e.clientY);
  }, [direction]);

  const handleMouseMove = useCallback((e: MouseEvent) => {
    if (!isDragging) return;
    const currentPos = direction === 'horizontal' ? e.clientX : e.clientY;
    const delta = currentPos - startPos;
    onResize(delta);
    setStartPos(currentPos);
  }, [isDragging, startPos, direction, onResize]);

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
  }, []);

  useEffect(() => {
    if (isDragging) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = direction === 'horizontal' ? 'col-resize' : 'row-resize';
      document.body.style.userSelect = 'none';
    }
    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, [isDragging, handleMouseMove, handleMouseUp, direction]);

  const baseClass = direction === 'horizontal'
    ? 'w-1 cursor-col-resize hover:bg-spore-highlight/50 active:bg-spore-highlight'
    : 'h-1 cursor-row-resize hover:bg-spore-highlight/50 active:bg-spore-highlight';

  return (
    <div
      className={`${baseClass} bg-spore-border/30 transition-colors flex-shrink-0 ${isDragging ? 'bg-spore-highlight' : ''} ${className}`}
      onMouseDown={handleMouseDown}
    />
  );
};
