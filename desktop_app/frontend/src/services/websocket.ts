/**
 * WebSocket 服务
 * 管理与后端的实时连接
 */

import type { WSEvent } from '../types';

type EventHandler = (events: WSEvent[]) => void;

class WebSocketService {
  private ws: WebSocket | null = null;
  private url: string;
  private handlers: Set<EventHandler> = new Set();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private pingInterval: number | null = null;
  
  // 消息批量处理
  private messageBuffer: WSEvent[] = [];
  private flushTimer: number | null = null;
  private readonly FLUSH_INTERVAL = 50; // 50ms 批量处理

  // 连接到独立的 WebSocket 推送进程（端口 8766）
  // 这个进程独立于主 FastAPI 进程，不受 GIL 阻塞影响
  constructor(url = 'ws://127.0.0.1:8766') {
    this.url = url;
  }

  connect(): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        console.log('[WebSocket] 连接成功');
        this.reconnectAttempts = 0;
        this.startPing();
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          // 处理后端批量消息
          if (data.type === 'batch' && Array.isArray(data.data)) {
            console.log(`[WebSocket] 收到批量消息: ${data.data.length} 条`);
            for (const msg of data.data) {
              this.bufferMessage(msg as WSEvent);
            }
          } else {
            this.bufferMessage(data as WSEvent);
          }
        } catch (e) {
          // 忽略非 JSON 消息（如 pong）
        }
      };

      this.ws.onclose = () => {
        console.log('[WebSocket] 连接关闭');
        this.stopPing();
        this.flushMessages(); // 确保剩余消息被处理
        this.attemptReconnect();
      };

      this.ws.onerror = (error) => {
        console.error('[WebSocket] 错误:', error);
      };
    } catch (error) {
      console.error('[WebSocket] 连接失败:', error);
      this.attemptReconnect();
    }
  }

  private bufferMessage(event: WSEvent): void {
    this.messageBuffer.push(event);
    
    if (!this.flushTimer) {
      this.flushTimer = window.setTimeout(() => {
        this.flushMessages();
      }, this.FLUSH_INTERVAL);
    }
  }

  private flushMessages(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    
    if (this.messageBuffer.length === 0) return;
    
    const events = [...this.messageBuffer];
    this.messageBuffer = [];
    
    this.handlers.forEach((handler) => handler(events));
  }

  disconnect(): void {
    this.stopPing();
    this.flushMessages(); // 确保剩余消息被处理
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  subscribe(handler: EventHandler): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  // 兼容旧的单事件处理方式
  subscribeSingle(handler: (event: WSEvent) => void): () => void {
    const batchHandler = (events: WSEvent[]) => {
      events.forEach(handler);
    };
    this.handlers.add(batchHandler);
    return () => this.handlers.delete(batchHandler);
  }

  private startPing(): void {
    this.pingInterval = window.setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send('ping');
      }
    }, 30000);
  }

  private stopPing(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log('[WebSocket] 达到最大重连次数');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    
    console.log(`[WebSocket] ${delay}ms 后尝试重连 (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
    
    setTimeout(() => this.connect(), delay);
  }

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  /**
   * 发送消息到后端
   */
  send(message: object): boolean {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
      return true;
    }
    return false;
  }

  /**
   * 发送确认响应
   */
  sendConfirmResponse(requestId: string, confirmed: boolean): boolean {
    return this.send({
      type: 'confirm_response',
      request_id: requestId,
      confirmed
    });
  }
}

// 单例导出
export const wsService = new WebSocketService();
