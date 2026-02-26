# -*- mode: python ; coding: utf-8 -*-
"""
Spore Backend PyInstaller Spec File
Package backend as a single standalone executable (onefile mode)
All Python runtime, DLLs, and dependencies are embedded
"""

import os
import sys

# Project root directory
PROJECT_ROOT = os.path.dirname(os.path.abspath(SPEC))

block_cipher = None

a = Analysis(
    ['main_entry.py'],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=[
        # onefile mode: no need to include resource files
        # prompt/skills/characters are packaged by Tauri resources mechanism
        # Backend locates them via SPORE_RESOURCE_DIR environment variable
    ],
    hiddenimports=[
        'base',
        'base.config',
        'base.logger',
        'base.client',
        'base.tools',
        'base.state_manager',
        'base.conversation_loop',
        'base.cli_commands',
        'base.ipc_manager',
        'base.chat_process',
        'base.agent_process',
        'base.agent_types',
        'base.agent_database',
        'base.character_manager',
        'base.event_signal',
        'base.interrupt_handler',
        'base.log_monitor',
        'base.memory_manager',
        'base.multi_agent_monitor',
        'base.prompt_loader',
        'base.rule_reminder',
        'base.todo_manager',
        'base.text_protocol',
        'base.text_protocol.action_parser',
        'base.text_protocol.protocol_manager',
        'base.text_protocol.result_formatter',
        'base.text_protocol.tool_doc_generator',
        'base.utils',
        'base.utils.characters',
        'base.utils.encoding',
        'base.utils.env',
        'base.utils.grep',
        'base.utils.json_utils',
        'base.utils.python_exec',
        'base.utils.shell',
        'base.utils.skills',
        'base.utils.system_io',
        'base.utils.terminal',
        'base.utils.token_counter',
        'base.utils.web_browser',
        'AutoAgent',
        'AutoAgent.character_selector',
        'AutoAgent.mode_selector',
        'AutoAgent.supervisor',
        'desktop_app',
        'desktop_app.backend',
        'desktop_app.backend.core',
        'desktop_app.backend.server',
        'desktop_app.backend.standalone',
        'desktop_app.backend.instance_manager',
        'desktop_app.backend.confirm_manager',
        'desktop_app.backend.routes',
        'desktop_app.backend.routes.chat',
        'desktop_app.backend.routes.commands',
        'desktop_app.backend.routes.files',
        'desktop_app.backend.routes.agents',
        'desktop_app.backend.routes.instances',
        'desktop_app.backend.routes.confirm',
        'desktop_app.backend.websocket',
        'desktop_app.backend.websocket.ipc_bridge',
        'desktop_app.backend.websocket.log_bridge',
        'desktop_app.backend.websocket.manager',
        'desktop_app.backend.websocket.ws_process',
        'desktop_app.resource_manager',
        'uvicorn',
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'fastapi',
        'starlette',
        'starlette.routing',
        'starlette.middleware',
        'starlette.middleware.cors',
        'pydantic',
        'websockets',
        'openai',
        'anthropic',
        'httpx',
        'tiktoken',
        'tiktoken_ext',
        'tiktoken_ext.openai_public',
        'dotenv',
        'yaml',
        'colorama',
        'pyperclip',
        'win32pipe',
        'win32file',
        'win32api',
        'pywintypes',
        'docxtpl',
        'requests',
        'bs4',
        'ddgs',
        'psutil',
        'pefile',
        'Crypto',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'cv2',
        'torch',
        'tensorflow',
        'pytest',
        'hypothesis',
        'flask',
        'flask_cors',
        'flask_socketio',
        'eventlet',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# onefile mode: all content packed into a single exe
# Python DLL, all dependencies, and data files are embedded
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,       # Include all binary dependencies (python313.dll, etc.)
    a.zipfiles,       # Include all zip-compressed modules
    a.datas,          # Include all data files
    [],
    name='spore_backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[
        'python313.dll',   # Don't compress Python DLL to avoid compatibility issues
        'vcruntime140.dll',
        'vcruntime140_1.dll',
    ],
    runtime_tmpdir=None,   # Use default temp directory for extraction
    console=False,         # No console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='desktop_app/frontend/src-tauri/icons/icon.ico',
)

# Note: onefile mode does not need COLLECT step
# Output is directly at dist/spore_backend.exe (single file)