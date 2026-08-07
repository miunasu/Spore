# 构建指南（v4.1）

> [English](en/BUILD.md)

本文说明如何从源码构建 **Spore 4.1** Windows 桌面安装包（Tauri + PyInstaller 后端 sidecar）。

---

## 产物与版本

| 组件 | 版本字段位置 |
|------|--------------|
| Python 工程 | `pyproject.toml` → `version` |
| 前端 npm | `desktop_app/frontend/package.json` |
| Tauri 应用 | `desktop_app/frontend/src-tauri/tauri.conf.json` → `package.version` |
| Rust crate | `desktop_app/frontend/src-tauri/Cargo.toml` |
| FastAPI | `desktop_app/backend/server.py` / `standalone.py` |

> 上述字段当前均为 `4.1.0`；升版本时请保持全部字段一致后再构建。

安装包输出：

- `desktop_app/frontend/src-tauri/target/release/bundle/nsis/`
- 脚本会汇总到根目录 `release/`（`Spore.exe` + `Spore_<版本>_x64-setup.exe`）

---

## 环境要求

- Windows 10/11 x64
- Python ≥ 3.10（构建环境实际使用 3.13）
- [uv](https://github.com/astral-sh/uv)
- PyInstaller（仅构建工具，已不属于 `pyproject.toml` 的运行依赖；干净环境需显式安装，例如 `uv pip install pyinstaller`）
- Node.js 18+ 或 20 LTS
- Rust（`rustup`，MSVC toolchain）
- Visual Studio Build Tools（C++ 桌面开发）
- PowerShell（脚本用其下载/校验 ripgrep）
- 项目根存在可用的 `.env`（打包会拷贝为资源，**缺失会导致构建失败**）

---

## 一键构建（推荐）

```bat
build_installer.bat
```

脚本分 6 个阶段：

1. **PyInstaller 后端（onefile）**：清理旧产物；`.venv` 缺 pyinstaller 时尝试 `uv sync`（或设 `FORCE_UV_SYNC=1` 强制）；执行 `uv run pyinstaller spore_backend.spec --noconfirm`，产出 `dist/spore_backend.exe`。注意 PyInstaller 已不在 `pyproject.toml` 运行依赖中，因此干净环境仅靠该自动 `uv sync` 仍不会安装它，必须先显式安装
2. **Tauri sidecar**：复制为 `desktop_app/frontend/src-tauri/binaries/spore_backend-x86_64-pc-windows-msvc.exe`（Tauri `externalBin` 要求平台三元组后缀）
3. **资源同步**：`prompt/`、`skills/`、`characters/`、`.env` 复制进 `src-tauri/`；下载并 SHA256 校验 **ripgrep 14.1.1**（缓存于 `.tool-cache/ripgrep/`），复制 `rg.exe`
4. **前端 + Tauri 构建**：清理 Vite 缓存；`node_modules` 缺失时 `npm install`（或 `FORCE_NPM_INSTALL=1`）；`npm run tauri build` 产出 NSIS 安装包
5. **汇总产物**：`Spore.exe` 与 NSIS 安装包复制到根目录 `release/`
6. **报告**：打印产物清单与安装目录结构说明

失败时按报错阶段排查；任一阶段失败脚本会停在 `:error` 并提示。

---

## 分步构建

### 1. Python 后端

```bash
uv sync
uv pip install pyinstaller    # 干净环境必需；PyInstaller 不在项目运行依赖中
uv run pyinstaller spore_backend.spec --noconfirm
```

产物为单文件 `dist/spore_backend.exe`；复制为 Tauri `externalBin` 所需文件名：

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
npm run dev                   # Vite http://localhost:1420

# 或 Tauri 开发窗（会自动以 uv 拉起后端）
npm run tauri dev
```

默认 API：`http://127.0.0.1:8765`，WebSocket：`ws://127.0.0.1:8766`。REST 端口由 `DESKTOP_API_PORT` 动态读取，当前 WebSocket 客户端 URL 仍固定为 `8766`。

---

## 打包结构要点

- **后端**：PyInstaller **onefile**（`spore_backend.spec`），入口 `main_entry.py`，`console=False`；spec 的 `datas` 包含 `learning/schema.sql`，供 frozen 后端从 PyInstaller 解压目录中的 `learning/schema.sql` 读取
- **资源**：`prompt/**`、`skills/**`、`characters/**`、`.env`、`rg.exe` 由 Tauri `resources` 携带，运行时经 `SPORE_RESOURCE_DIR` 定位；`learning/schema.sql` 则内嵌在后端 onefile 中，不从 Tauri 资源根读取
- **frozen 路径**：打包后配置、Learning 数据库等可写运行数据以 `Path.cwd()` 为运行根；Python 模块随 onefile 解压到临时目录，`schema.sql` 使用模块相对路径读取
- **进程托管**：Tauri `main.rs` 以 sidecar 方式拉起后端，注入 `SPORE_DESKTOP_MODE=1` 与 `SPORE_RESOURCE_DIR`，并用 Windows Job Object 保证窗口关闭时整棵子进程树一并退出
- **工作目录**：安装后由 `main.rs` 与 `resource_manager` 保证 cwd 正确，并创建可写目录（`output/`、`history/`、`logs/`、`note.txt`）
- **隐藏导入**：若运行缺模块，补 `spore_backend.spec` 的 `hiddenimports`

安装目录布局（脚本第 6 阶段打印的权威结构）：

```text
Spore.exe              # Tauri 前端
spore_backend.exe      # Python 后端（onefile，依赖内嵌）
rg.exe                 # ripgrep 搜索工具
prompt/  skills/  characters/   # 只读资源
.env                   # 配置（打包时从项目根复制）
output/  history/  logs/  note.txt   # 运行时生成
```

---

## 常见问题

### PyInstaller 运行报错缺模块

补全 `hiddenimports`：`base` 及其子包、`AutoAgent`、`desktop_app`、`uvicorn`/`fastapi`/`starlette`、`openai`/`anthropic`/`tiktoken`、`bsdiff4` 等。

### Tauri 构建失败

1. `rustc --version` / VS C++ 工具是否可用  
2. Node 版本是否过旧  
3. 清理 `desktop_app/frontend/dist`、`node_modules/.vite` 后重试  

### build_installer.bat 失败

1. 根目录是否有 `.env`  
2. 网络是否能拉 ripgrep  
3. 删除 `.tool-cache/ripgrep/` 后重试  
4. `uv sync` 是否成功  
5. 干净 `.venv` 中是否已显式安装 PyInstaller；脚本检测不到 `.venv\Scripts\pyinstaller.exe` 时虽然会自动运行 `uv sync`，但当前 `pyproject.toml` 不声明 PyInstaller，因此同步后仍可能在 `uv run pyinstaller` 处失败

### 安装包体积

后端 onefile 约 25–30MB，NSIS 安装包约 30MB 量级（含 Python 运行时）。

### 修改图标

替换 `desktop_app/frontend/src-tauri/icons/` 后重新构建。

### 修改版本号

同步修改「产物与版本」表中所有版本字段为同一版本（例如 `4.1.0`），再执行完整构建。

---

## 相关

- [架构设计](ARCHITECTURE.md)
- [配置说明](CONFIGURATION.md)
- [前端使用](FRONTEND.md)
