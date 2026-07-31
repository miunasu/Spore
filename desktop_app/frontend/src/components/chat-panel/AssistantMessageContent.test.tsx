// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AssistantMessageContent } from './AssistantMessageContent';
import { useSettingsStore } from '../../stores/settingsStore';

afterEach(() => {
  useSettingsStore.setState({ htmlRenderingEnabled: false });
});

describe('AssistantMessageContent', () => {
  it('renders Markdown and GFM structures', () => {
    const { container } = render(
      <AssistantMessageContent content={'# Title\n\n- item\n\n~~old~~\n\n| A | B |\n| --- | --- |\n| 1 | 2 |'} />
    );

    expect(screen.getByRole('heading', { name: 'Title' })).toBeInTheDocument();
    expect(screen.getByRole('list')).toBeInTheDocument();
    expect(container.querySelector('del')).toHaveTextContent('old');
    expect(screen.getByRole('table')).toBeInTheDocument();
  });

  it('highlights explicit and bare code without executing it', () => {
    const { container, rerender } = render(
      <AssistantMessageContent content={'```js\nconst answer = 42;\n```'} />
    );
    expect(container.querySelector('pre code.language-javascript')).toBeInTheDocument();
    expect(container.querySelector('pre code.language-js')).not.toBeInTheDocument();
    expect(container.querySelector('.hljs-keyword')).toHaveTextContent('const');

    rerender(<AssistantMessageContent content={'<root><script>alert(1)</script></root>'} />);
    expect(container.querySelector('pre code.language-xml')).toBeInTheDocument();
    expect(container.querySelector('script')).not.toBeInTheDocument();
    expect(container.textContent).toContain('<script>');
  });

  it('renders raw HTML as literal text', () => {
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => undefined);
    const { container } = render(
      <AssistantMessageContent content={'Before <script>alert(1)</script> after <img src=x onerror=alert(2)>'} />
    );

    expect(container.querySelector('script')).not.toBeInTheDocument();
    expect(container.querySelector('img')).not.toBeInTheDocument();
    expect(container.textContent).toContain('<script>alert(1)</script>');
    expect(alertSpy).not.toHaveBeenCalled();
    alertSpy.mockRestore();
  });

  it('blocks dangerous links and remote Markdown images', () => {
    const { container } = render(
      <AssistantMessageContent
        content={'[safe](https://example.com) [bad](javascript:alert(1)) ![tracker](https://example.com/pixel.png)'}
      />
    );

    const safe = screen.getByRole('link', { name: 'safe' });
    expect(safe).toHaveAttribute('href', 'https://example.com');
    expect(safe).toHaveAttribute('target', '_blank');
    expect(safe).toHaveAttribute('rel', 'noopener noreferrer nofollow');
    expect(screen.queryByRole('link', { name: 'bad' })).not.toBeInTheDocument();
    expect(container.querySelector('img')).not.toBeInTheDocument();
    expect(container.textContent).toContain('[tracker]');
  });

  it('uses the compact class without changing the rendering path', () => {
    const { container } = render(
      <AssistantMessageContent content={'**compact**'} variant="mini" />
    );
    expect(container.firstChild).toHaveClass('markdown-renderer--mini');
    expect(container.querySelector('strong')).toHaveTextContent('compact');
  });

  it('renders standalone HTML in a sandbox only when enabled', () => {
    const content = '<!doctype html><html><body><button>Run</button></body></html>';
    const { container, rerender } = render(<AssistantMessageContent content={content} />);
    expect(container.querySelector('iframe')).not.toBeInTheDocument();

    useSettingsStore.setState({ htmlRenderingEnabled: true });
    rerender(<AssistantMessageContent content={content} />);
    expect(container.querySelector('iframe')).toHaveAttribute('sandbox');
    expect(container.querySelector('button')).not.toBeInTheDocument();
  });
});
