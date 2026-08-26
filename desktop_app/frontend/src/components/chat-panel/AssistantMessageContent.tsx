import { useMemo } from 'react';
import { SafeMarkdownRenderer } from '../common/SafeMarkdownRenderer';
import { prepareAssistantMarkdown } from './assistantMessageParsing';
import { HtmlPreview, extractStandaloneHtml, splitContentWithHtml } from '../common/HtmlPreview';
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

  const splitResult = useMemo(() => {
    if (!htmlRenderingEnabled) return null;
    return splitContentWithHtml(content);
  }, [content, htmlRenderingEnabled]);

  const html = useMemo(() => extractStandaloneHtml(content), [content]);
  const markdown = useMemo(() => prepareAssistantMarkdown(content), [content]);

  // 如果检测到混合内容（文本 + HTML）
  if (htmlRenderingEnabled && splitResult && splitResult.html) {
    return (
      <div className="flex flex-col gap-4">
        {splitResult.before && (
          <SafeMarkdownRenderer
            content={prepareAssistantMarkdown(splitResult.before)}
            variant={variant === 'mini' ? 'mini' : 'chat'}
          />
        )}
        <HtmlPreview
          content={splitResult.html}
          title={t('chatPanel.htmlPreview.messageTitle')}
          frontendAgentEnabled={true}
        />
        {splitResult.after && (
          <SafeMarkdownRenderer
            content={prepareAssistantMarkdown(splitResult.after)}
            variant={variant === 'mini' ? 'mini' : 'chat'}
          />
        )}
      </div>
    );
  }

  // 如果整个内容都是HTML（向后兼容）
  if (htmlRenderingEnabled && html) {
    return <HtmlPreview content={html} title={t('chatPanel.htmlPreview.messageTitle')} frontendAgentEnabled={true} />;
  }

  // 普通Markdown渲染
  return (
    <SafeMarkdownRenderer
      content={markdown}
      variant={variant === 'mini' ? 'mini' : 'chat'}
    />
  );
}
