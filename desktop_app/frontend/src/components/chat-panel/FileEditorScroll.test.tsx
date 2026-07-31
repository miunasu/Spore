// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { useEditorStore } from '../../stores/editorStore';
import { FileEditorContent } from './FileEditorContent';

const file = {
  path: 'src/example.js',
  name: 'example.js',
  content: Array.from({ length: 120 }, (_, index) => `const line${index} = ${index};`).join('\n'),
  originalContent: Array.from({ length: 120 }, (_, index) => `const line${index} = ${index};`).join('\n'),
  hasChanges: false,
};

afterEach(() => {
  useEditorStore.setState({
    openFiles: [],
    activeFilePath: null,
    isLoading: false,
    isSaving: false,
    error: null,
  });
});

describe('FileEditorContent scroll restoration', () => {
  it('restores independent preview and edit scroll positions after mode switches', () => {
    useEditorStore.setState({
      openFiles: [file],
      activeFilePath: file.path,
      isLoading: false,
      isSaving: false,
      error: null,
    });

    const { container } = render(<FileEditorContent />);
    const preview = container.querySelector<HTMLElement>('.syntax-viewer');
    expect(preview).toBeInTheDocument();
    preview!.scrollTop = 480;
    preview!.scrollLeft = 64;
    fireEvent.scroll(preview!);

    fireEvent.click(screen.getByRole('button', { name: '编辑' }));
    const textarea = container.querySelector<HTMLTextAreaElement>('textarea');
    expect(textarea).toBeInTheDocument();
    expect(textarea?.scrollTop).toBe(480);
    expect(textarea?.scrollLeft).toBe(64);
    textarea!.scrollTop = 220;
    textarea!.scrollLeft = 32;
    fireEvent.scroll(textarea!);

    fireEvent.click(screen.getByRole('button', { name: '预览' }));
    const restoredPreview = container.querySelector<HTMLElement>('.syntax-viewer');
    expect(restoredPreview?.scrollTop).toBe(480);
    expect(restoredPreview?.scrollLeft).toBe(64);

    fireEvent.click(screen.getByRole('button', { name: '编辑' }));
    const restoredTextarea = container.querySelector<HTMLTextAreaElement>('textarea');
    expect(restoredTextarea?.scrollTop).toBe(220);
    expect(restoredTextarea?.scrollLeft).toBe(32);
  });
});
