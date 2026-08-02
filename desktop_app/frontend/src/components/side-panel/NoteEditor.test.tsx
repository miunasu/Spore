// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useLangStore } from '../../i18n';
import { filesApi } from '../../services/api';
import { NoteEditor, TODO_SEPARATOR } from './NoteEditor';

vi.mock('../../services/api', () => ({
  filesApi: {
    read: vi.fn(),
    write: vi.fn(),
  },
}));

const readMock = vi.mocked(filesApi.read);
const writeMock = vi.mocked(filesApi.write);

const firePointerEvent = (
  element: Element,
  type: 'pointerdown' | 'pointermove' | 'pointerup',
  options: { pointerId?: number; button?: number; clientX?: number; clientY?: number } = {},
) => {
  const event = new MouseEvent(type, {
    bubbles: true,
    cancelable: true,
    button: options.button ?? 0,
    clientX: options.clientX ?? 0,
    clientY: options.clientY ?? 0,
  });
  Object.defineProperty(event, 'pointerId', { value: options.pointerId ?? 1 });
  fireEvent(element, event);
};

const mockRowRect = (row: HTMLElement, top: number) => {
  vi.spyOn(row, 'getBoundingClientRect').mockReturnValue({
    x: 0,
    y: top,
    top,
    left: 0,
    right: 200,
    bottom: top + 40,
    width: 200,
    height: 40,
    toJSON: () => ({}),
  });
};

beforeEach(() => {
  useLangStore.setState({ lang: 'zh' });
  readMock.mockResolvedValue({
    path: 'note.txt',
    size: 0,
    content: [
      'note body',
      TODO_SEPARATOR,
      '[x] 已完成',
      '[ ] 第一项',
      '[ ] 第二项',
    ].join('\n'),
  });
  writeMock.mockResolvedValue({ success: true, path: 'note.txt', size: 0 });
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe('NoteEditor todo view', () => {
  it('hides completed todos and can show them again', async () => {
    render(<NoteEditor />);

    fireEvent.click(await screen.findByRole('tab', { name: /待办/ }));
    expect(screen.getByText('已完成')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: '隐藏已完成' }));
    expect(screen.queryByText('已完成')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '显示已完成' })).toHaveAttribute('aria-pressed', 'true');

    fireEvent.click(screen.getByRole('button', { name: '显示已完成' }));
    expect(screen.getByText('已完成')).toBeInTheDocument();
  });

  it('keeps a normal short row click available for todo controls', async () => {
    render(<NoteEditor />);
    const tabs = await screen.findAllByRole('tab');
    fireEvent.click(tabs[1]);

    const firstRow = document.querySelectorAll<HTMLElement>('[data-todo-id]')[1];
    const checkbox = firstRow?.querySelector<HTMLButtonElement>('[role="checkbox"]');
    expect(firstRow).not.toBeNull();
    expect(checkbox).not.toBeNull();
    expect(checkbox).toHaveAttribute('aria-checked', 'false');

    firePointerEvent(checkbox!, 'pointerdown', { pointerId: 5, clientX: 10, clientY: 50 });
    firePointerEvent(checkbox!, 'pointerup', { pointerId: 5, clientX: 10, clientY: 50 });
    fireEvent.click(checkbox!);

    expect(checkbox).toHaveAttribute('aria-checked', 'true');
  });

  it('persists the order produced by holding and dragging a todo row', async () => {
    render(<NoteEditor />);
    fireEvent.click(await screen.findByRole('tab', { name: /待办/ }));

    const doneRow = screen.getByText('已完成').closest<HTMLElement>('[data-todo-id]');
    const firstRow = screen.getByText('第一项').closest<HTMLElement>('[data-todo-id]');
    const secondRow = screen.getByText('第二项').closest<HTMLElement>('[data-todo-id]');
    expect(doneRow).not.toBeNull();
    expect(firstRow).not.toBeNull();
    expect(secondRow).not.toBeNull();
    mockRowRect(doneRow!, 0);
    mockRowRect(firstRow!, 40);
    mockRowRect(secondRow!, 80);

    vi.useFakeTimers();
    firePointerEvent(secondRow!, 'pointerdown', { pointerId: 7, clientX: 20, clientY: 100 });
    act(() => vi.advanceTimersByTime(220));
    firePointerEvent(secondRow!, 'pointermove', { pointerId: 7, clientX: 20, clientY: 44 });
    firePointerEvent(secondRow!, 'pointerup', { pointerId: 7, clientX: 20, clientY: 44 });
    vi.useRealTimers();

    expect(screen.getAllByTitle('双击或按 Enter/F2 编辑').map((item) => item.textContent)).toEqual([
      '已完成',
      '第二项',
      '第一项',
    ]);
    expect(screen.queryByRole('button', { name: /拖动待办/ })).not.toBeInTheDocument();

    const saveButton = screen.getByRole('button', { name: '保存' });
    await waitFor(() => expect(saveButton).not.toBeDisabled());
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(writeMock).toHaveBeenCalledWith(
        'note.txt',
        [
          'note body',
          TODO_SEPARATOR,
          '[x] 已完成',
          '[ ] 第二项',
          '[ ] 第一项',
        ].join('\n'),
      );
    });
  });
});
