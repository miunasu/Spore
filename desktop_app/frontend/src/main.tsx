import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import { initApiPort } from './services/api'
import { wsService } from './services/websocket'
import { invoke } from '@tauri-apps/api/tauri'
import { useChatStore } from './stores/chatStore'
import { initializeEdgeSnapListener } from './stores/miniModeStore'

async function bootstrap() {
  // 在 Tauri 环境下，从 .env 读取 DESKTOP_API_PORT 并初始化 API 端口
  // 非 Tauri 环境（独立后端 / 开发服务器）invoke 会抛异常，保持默认值 8765
  try {
    const port = await invoke<number>('get_api_port');
    initializeEdgeSnapListener();
    initApiPort(port);
    // WebSocket 推送进程端口 = API 端口 + 1（与 ipc_bridge.py 保持一致）
    wsService.setUrl(`ws://127.0.0.1:${port + 1}`);
    // 端口确定后再修正默认会话端口并执行 switchSession
    // （store 初始化器在此之前运行，端口尚未确定，所以不能在那里做）
    useChatStore.getState().setMainBackendPort(port);
  } catch {
    // 非 Tauri 环境或命令不可用，使用默认端口
    // store 里的 MAIN_PORT=8765 回退值仍然有效
  }

  ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  )
}

bootstrap()
