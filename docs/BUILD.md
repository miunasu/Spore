# 构建指南（v3.0）

本文说明如何从源码构建 **Spore 3.0** Windows 桌面安装包（Tauri + PyInstaller 后端 sidecar）。

---

## 产物与版本

| 组件 | 版本字段位置 | 当前 |
|------|--------------|------|
| Python 工程 | `pyproject.toml` → `version` | `3.0.0` |
| 前端 npm | `desktop_app/frontend/package.json` | `3.0.0` |
| Tauri 应用 | `desktop_app/frontend/src-tauri/tauri.conf.json` → `package.version` | `3.0.0` |
| Rust crate | `desktop_app/frontend/src-tauri/Cargo.toml` | `3.0.0` |
| FastAPI | `desktop_app/backend/server.py` / `standalone.py` | `3.0.0` |

安装包输出通常位于：

- `desktop_app/frontend/src-tauri/target/release/bundle/nsis/`
- 或脚本汇总目录 `release/`

---

## 环境要求

- Windows 10/11 x64
- Python ≥ 3.10（推荐与 `.venv` 一致）
- [uv](https://github.com/astral-sh/uv)
- Node.js 18+ 或 20 LTS
- Rust（`rustup`，MSVC toolchain）
- Visual Studio Build Tools（C++ 桌面开发）
- 项目根存在可用的 `.env`（打包会拷贝为资源）

---

## 一键构建（推荐）

```bat
build_installer.bat
```

脚本主要步骤（摘要）：

1. 同步 Python 依赖（`uv sync`）
2. 使用 PyInstaller + `spore_backend.spec` 打包 `spore_backend` 后端
3. 准备 Tauri sidecar：`desktop_app/frontend/src-tauri/binaries/spore_backend-*.exe`
4. 同步资源：`prompt/`、`skills/`、`characters/`、`.env`、`rg.exe`（ripgrep 可自动下载校验）
5. 构建前端与 Tauri NSIS 安装包

失败时按报错阶段排查；ripgrep 缓存目录：`.tool-cache/ripgrep/`。

---

## 分步构建

### 1. Python 后端

```bash
uv sync
uv run pyinstaller spore_backend.spec --noconfirm
```

产物一般在 `dist/spore_backend/` 或 spec 指定路径；复制为 Tauri `externalBin` 所需文件名：

```text
desktop_app/frontend/src-tauri/binaries/spore_backend-x86_64-pc-windows-msvc.exe
```

### 2. 前端

```bash
cd desktop_app/frontend
npm install
npm run build
```

### 3. Tauri

```bash
cd desktop_app/frontend
npm run tauri build
```

开发联调：

```bash
# 终端 A：后端
uv run python main_entry.py   # LAUNCH_MODE=desktop

# 终端 B：前端
cd desktop_app/frontend
npm run dev

# 或 Tauri 开发窗
npm run tauri dev
```

默认 API：`http://127.0.0.1:8765`，WebSocket：`8766`（端口 + 1）。

---

## 打包结构要点

- **后端**：PyInstaller onefile/onedir 由 `spore_backend.spec` 决定；入口 `main_entry.py`
- **资源**：Tauri `resources` 包含 prompt/skills/characters/.env/rg.exe
- **工作目录**：安装后由 Tauri `main.rs` 与 `resource_manager` 保证 cwd / `SPORE_RESOURCE_DIR` 正确
- **隐藏导入**：若运行缺模块，补 `spore_backend.spec` 的 `hiddenimports`

---

## 常见问题

### PyInstaller 运行报错缺模块

补全 `hiddenimports`：`base` 及其子包、`desktop_app`、`uvicorn`/`fastapi`/`starlette`、`openai`/`anthropic`/`tiktoken` 等。

### Tauri 构建失败

1. `rustc --version` / VS C++ 工具是否可用  
2. Node 版本是否过旧  
3. 清理 `desktop_app/frontend/dist`、`node_modules/.vite` 后重试  

### build_installer.bat 失败

1. 根目录是否有 `.env`  
2. 网络是否能拉 ripgrep  
3. 删除 `.tool-cache/ripgrep/` 后重试  
4. `uv sync` 是否成功  

### 安装包体积

后端 50–80MB 量级常见（含 Python 运行时）。

### 修改图标

替换 `desktop_app/frontend/src-tauri/icons/` 后重新构建。

### 修改版本号

同步修改上表所有版本字段为同一主版本（例如 `3.0.0`），再执行完整构建。

---

## 相关

- [架构设计](ARCHITECTURE.md)
- [配置说明](CONFIGURATION.md)
- [前端使用](FRONTEND.md)