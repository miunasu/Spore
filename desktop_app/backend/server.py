"""
FastAPI 主服务
提供 REST API 端点，WebSocket 推送由独立进程处理
"""
import atexit
import signal
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from .core import initialize_desktop_backend, shutdown_desktop_backend

# 清理标志
_cleanup_done = False


def cleanup_all():
    """清理所有资源"""
    global _cleanup_done
    if _cleanup_done:
        return
    _cleanup_done = True
    
    try:
        from .confirm_manager import stop_response_listener
        stop_response_listener()
    except Exception:
        pass
    
    try:
        from .websocket.ipc_bridge import stop_ipc_consumer
        stop_ipc_consumer()
    except Exception:
        pass
    
    try:
        from .instance_manager import get_instance_manager
        get_instance_manager().stop_all()
    except Exception:
        pass
    
    try:
        shutdown_desktop_backend()
    except Exception:
        pass


def signal_handler(signum, frame):
    """信号处理器"""
    cleanup_all()
    sys.exit(0)


atexit.register(cleanup_all)
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期"""
    global _cleanup_done
    _cleanup_done = False
    
    # 初始化后端
    initialize_desktop_backend()
    
    # 启动 WebSocket 推送进程
    from .websocket.ipc_bridge import start_ipc_consumer
    start_ipc_consumer()
    
    # 设置日志回调
    from .websocket.log_bridge import setup_log_callbacks, setup_agent_monitor_callbacks, setup_todo_callbacks
    setup_log_callbacks()
    setup_agent_monitor_callbacks()
    setup_todo_callbacks()
    
    # 启动确认响应监听
    from .confirm_manager import start_response_listener
    start_response_listener()
    
    yield
    
    cleanup_all()


# FastAPI 应用
app = FastAPI(
    title="Spore Desktop API",
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
from .routes import chat, commands, files, agents, instances, confirm
app.include_router(chat.router, prefix="/api/chat", tags=["Chat"])
app.include_router(commands.router, prefix="/api/commands", tags=["Commands"])
app.include_router(files.router, prefix="/api/files", tags=["Files"])
app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])
app.include_router(instances.router, prefix="/api/instances", tags=["Instances"])
app.include_router(confirm.router, prefix="/api/confirm", tags=["Confirm"])


@app.get("/")
def root():
    return {"status": "ok", "message": "Spore Desktop API"}


@app.get("/health")
def health_check():
    from .core import is_initialized
    return {"status": "healthy" if is_initialized() else "initializing"}


def run_desktop_app():
    """运行桌面应用后端"""
    import os
    import io
    
    # PyInstaller 打包后无窗口模式下，sys.stdout/stderr 可能是 None
    # 这会导致 uvicorn 日志配置失败（isatty() 调用报错）
    # 解决方案：将 stdout/stderr 重定向到 devnull 或日志文件
    if sys.stdout is None or sys.stderr is None:
        # 尝试重定向到日志文件
        log_dir = os.path.join(os.getcwd(), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        try:
            log_file = open(os.path.join(log_dir, 'uvicorn.log'), 'a', encoding='utf-8')
            if sys.stdout is None:
                sys.stdout = log_file
            if sys.stderr is None:
                sys.stderr = log_file
        except Exception:
            # 如果无法创建日志文件，使用 devnull
            devnull = open(os.devnull, 'w')
            if sys.stdout is None:
                sys.stdout = devnull
            if sys.stderr is None:
                sys.stderr = devnull
    
    from base.config import get_config
    config = get_config()
    host = getattr(config, 'desktop_api_host', '127.0.0.1')
    port = getattr(config, 'desktop_api_port', 8765)
    
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    run_desktop_app()
