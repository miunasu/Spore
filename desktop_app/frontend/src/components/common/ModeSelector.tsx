import React, { useState, useRef, useEffect } from 'react';

interface Mode {
  value: string;
  label: string;
  description?: string;
}

interface ModeSelectorProps {
  value: string;
  modes: Mode[];
  onChange: (value: string) => void;
}

// 模式图标映射
const getModeIcon = (value: string) => {
  const icons: Record<string, JSX.Element> = {
    strong_context: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
      </svg>
    ),
    lite_context: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    ),
    no_context: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
      </svg>
    ),
  };
  
  return icons[value] || (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
    </svg>
  );
};

export const ModeSelector: React.FC<ModeSelectorProps> = ({ value, modes, onChange }) => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const selectedMode = modes.find((m) => m.value === value);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  return (
    <div ref={dropdownRef} className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="p-1.5 rounded hover:bg-spore-accent/30 text-spore-muted hover:text-spore-text transition-colors"
        title={selectedMode?.label || '上下文处理模式'}
      >
        {getModeIcon(value)}
      </button>

      {isOpen && (
        <div className="absolute top-full mt-2 right-0 min-w-[200px] bg-spore-panel border border-spore-border rounded-lg shadow-elevated overflow-hidden z-50 animate-fade-in">
          {modes.map((mode) => (
            <button
              key={mode.value}
              onClick={() => {
                onChange(mode.value);
                setIsOpen(false);
              }}
              className={`w-full text-left px-3 py-2 transition-all duration-150 border-l-2 flex items-start gap-2 ${
                mode.value === value
                  ? 'bg-spore-highlight/10 text-spore-highlight border-spore-highlight'
                  : 'text-spore-text hover:bg-spore-accent/50 border-transparent hover:border-spore-highlight/30'
              }`}
            >
              <div className={`flex-shrink-0 mt-0.5 ${mode.value === value ? 'text-spore-highlight' : 'text-spore-muted'}`}>
                {getModeIcon(mode.value)}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium">{mode.label}</span>
                  {mode.value === value && (
                    <svg
                      className="w-3.5 h-3.5 text-spore-highlight flex-shrink-0"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  )}
                </div>
                {mode.description && (
                  <p className="text-xs text-spore-muted mt-0.5 leading-snug">{mode.description}</p>
                )}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
};
