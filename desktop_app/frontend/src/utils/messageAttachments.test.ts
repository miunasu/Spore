import { describe, expect, it } from 'vitest';

import {
  buildMessageContent,
  getAttachmentName,
  parseMessageContent,
} from './messageAttachments';

describe('message attachments', () => {
  it('keeps paths in the backend content and removes them from display text', () => {
    const paths = ['C:\\work\\report.docx', 'C:\\work\\notes.txt'];
    const serialized = buildMessageContent('Please review these files', paths);

    expect(serialized).toContain('C:\\\\work\\\\report.docx');
    expect(parseMessageContent(serialized)).toEqual({
      content: 'Please review these files',
      attachments: paths,
    });
  });

  it('supports attachment-only messages and deduplicates paths', () => {
    const serialized = buildMessageContent('', ['C:\\work\\report.docx', 'C:\\work\\report.docx']);

    expect(parseMessageContent(serialized)).toEqual({
      content: '',
      attachments: ['C:\\work\\report.docx'],
    });
  });

  it('leaves malformed or manually typed markers visible', () => {
    const content = 'Keep @SPORE:USER_ATTACHMENTS=not-json visible';
    expect(parseMessageContent(content)).toEqual({ content, attachments: [] });
  });

  it('uses the final path segment as the chip label', () => {
    expect(getAttachmentName('C:\\work\\report.docx')).toBe('report.docx');
  });
});
