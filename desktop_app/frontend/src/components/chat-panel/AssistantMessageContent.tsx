import { useMemo } from 'react';
import { SafeMarkdownRenderer } from '../common/SafeMarkdownRenderer';
import { prepareAssistantMarkdown } from './assistantMessageParsing';

type AssistantMessageContentProps = {
  content: string;
  variant?: 'default' | 'mini';
};

export function AssistantMessageContent({
  content,
  variant = 'default',
}: AssistantMessageContentProps) {
  const markdown = useMemo(() => prepareAssistantMarkdown(content), [content]);
  return (
    <SafeMarkdownRenderer
      content={markdown}
      variant={variant === 'mini' ? 'mini' : 'chat'}
    />
  );
}
