"""
独立后端实例
作为子进程运行，监听指定端口
"""
import os
import sys
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# 添加项目根目录到路径
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from desktop_app.backend.core import initialize_desktop_backend, shutdown_desktop_backend

# 获取实例配置
INSTANCE_ID = os.environ.get('SPORE_INSTANCE_ID', 'default')
INSTANCE_PORT = int(os.environ.get('SPORE_INSTANCE_PORT', '8765'))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    initialize_desktop_backend()
    
    # 启动 WebSocket 推送进程
    from desktop_app.backend.websocket.ipc_bridge import start_ipc_consumer
    start_ipc_consumer()
    
    # 设置日志回调
    from desktop_app.backend.websocket.log_bridge import setup_log_callbacks, setup_agent_monitor_callbacks
    setup_log_callbacks()
    setup_agent_monitor_callbacks()
    
    yield
    
    from desktop_app.backend.websocket.ipc_bridge import stop_ipc_consumer
    stop_ipc_consumer()
    shutdown_desktop_backend()


# 创建 FastAPI 应用
app = FastAPI(
    title=f"Spore Desktop API - Instance {INSTANCE_ID}",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
from desktop_app.backend.routes import chat, commands, files, agents
app.include_router(chat.router, prefix="/api/chat", tags=["Chat"])
app.include_router(commands.router, prefix="/api/commands", tags=["Commands"])
app.include_router(files.router, prefix="/api/files", tags=["Files"])
app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])


@app.get("/")
def root():
    return {"status": "ok", "instance_id": INSTANCE_ID, "port": INSTANCE_PORT}


@app.get("/health")
def health_check():
    from desktop_app.backend.core import is_initialized
    return {
        "status": "healthy" if is_initialized() else "initializing",
        "instance_id": INSTANCE_ID,
    }


@app.post("/shutdown")
def shutdown():
    """优雅关闭端点"""
    import threading
    threading.Timer(0.5, lambda: os._exit(0)).start()
    return {"status": "shutting_down"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=INSTANCE_PORT, log_level="warning")
