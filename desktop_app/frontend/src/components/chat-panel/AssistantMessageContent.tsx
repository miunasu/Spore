import { useMemo } from 'react';
import { SafeMarkdownRenderer } from '../common/SafeMarkdownRenderer';
import { prepareAssistantMarkdown } from './assistantMessageParsing';
import { HtmlPreview, extractStandaloneHtml } from '../common/HtmlPreview';
import { useSettingsStore } from '../../stores/settingsStore';
import { useT } from '../../i18n';

type AssistantMessageContentProps = {
  content: string;
  variant?: 'default' | 'mini';
};

export function AssistantMessageContent({
  content,
  variant = 'default',
}: AssistantMessageContentProps) {
  const t = useT();
  const htmlRenderingEnabled = useSettingsStore((state) => state.htmlRenderingEnabled);
  const html = useMemo(() => extractStandaloneHtml(content), [content]);
  const markdown = useMemo(() => prepareAssistantMarkdown(content), [content]);

  if (htmlRenderingEnabled && html) {
    return <HtmlPreview content={html} title={t('chatPanel.htmlPreview.messageTitle')} />;
  }

  return (
    <SafeMarkdownRenderer
      content={markdown}
      variant={variant === 'mini' ? 'mini' : 'chat'}
    />
  );
}
