const ATTACHMENTS_MARKER = '@SPORE:USER_ATTACHMENTS=';

export interface ParsedMessageContent {
  content: string;
  attachments: string[];
}

const uniquePaths = (paths: string[]): string[] => {
  const seen = new Set<string>();
  return paths.reduce<string[]>((result, path) => {
    const normalized = path.trim();
    if (normalized && !seen.has(normalized)) {
      seen.add(normalized);
      result.push(normalized);
    }
    return result;
  }, []);
};

export const getAttachmentName = (path: string): string => {
  const normalized = path.replace(/\\/g, '/');
  const parts = normalized.split('/').filter(Boolean);
  return parts[parts.length - 1] || path;
};

export const buildMessageContent = (text: string, paths: string[]): string => {
  const content = text.trim();
  const attachments = uniquePaths(paths);
  if (attachments.length === 0) return content;

  const attachmentBlock = `${ATTACHMENTS_MARKER}${JSON.stringify(attachments)}`;
  return content ? `${content}\n\n${attachmentBlock}` : attachmentBlock;
};

export const parseMessageContent = (value: string): ParsedMessageContent => {
  const content = value || '';
  const markerIndex = content.lastIndexOf(ATTACHMENTS_MARKER);
  if (markerIndex < 0) return { content, attachments: [] };

  const prefix = content.slice(0, markerIndex);
  if (markerIndex > 0 && !prefix.endsWith('\n')) {
    return { content, attachments: [] };
  }

  try {
    const parsed = JSON.parse(content.slice(markerIndex + ATTACHMENTS_MARKER.length));
    if (!Array.isArray(parsed) || !parsed.every((path) => typeof path === 'string')) {
      return { content, attachments: [] };
    }
    const attachments = uniquePaths(parsed);
    if (attachments.length === 0) return { content, attachments: [] };
    return { content: prefix.trimEnd(), attachments };
  } catch {
    return { content, attachments: [] };
  }
};
