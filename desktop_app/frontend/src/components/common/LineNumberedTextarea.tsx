import React, { useMemo, useRef } from 'react';

type LineNumberedTextareaProps = {
  value: string;
  onChange: (event: React.ChangeEvent<HTMLTextAreaElement>) => void;
  onScroll?: (event: React.UIEvent<HTMLTextAreaElement>) => void;
  className?: string;
  textareaClassName?: string;
  spellCheck?: boolean;
};

export const LineNumberedTextarea: React.FC<LineNumberedTextareaProps> = ({
  value,
  onChange,
  onScroll,
  className = '',
  textareaClassName = '',
  spellCheck = false,
}) => {
  const gutterRef = useRef<HTMLDivElement>(null);
  const lineCount = useMemo(() => value.split('\n').length, [value]);
  const lineNumbers = useMemo(
    () => Array.from({ length: Math.max(1, lineCount) }, (_, index) => index + 1),
    [lineCount]
  );

  const handleScroll = (event: React.UIEvent<HTMLTextAreaElement>) => {
    if (gutterRef.current) {
      gutterRef.current.scrollTop = event.currentTarget.scrollTop;
    }
    onScroll?.(event);
  };

  return (
    <div className={`line-numbered-editor ${className}`}>
      <div ref={gutterRef} className="line-numbered-editor__gutter" aria-hidden="true">
        {lineNumbers.map((lineNumber) => (
          <div className="line-numbered-editor__line" key={lineNumber}>
            {lineNumber}
          </div>
        ))}
      </div>
      <textarea
        value={value}
        onChange={onChange}
        onScroll={handleScroll}
        className={`line-numbered-editor__textarea ${textareaClassName}`}
        spellCheck={spellCheck}
        wrap="off"
      />
    </div>
  );
};
