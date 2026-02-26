# 构建指南

## 从源码运行

### 1. 安装依赖

```bash
# 安装 Python 依赖
pip install -r requirements.txt
```

> 📌 **注意**：其他外部工具依赖请查看 `requirements.txt` 中的 **External Tool Dependencies** 章节。

### 2. 配置环境

编辑 `.env` 文件，填写 LLM API Key。

### 3. 启动应用

```bash
# CLI 模式
python main.py

# 桌面模式
编译成功后双击release文件夹中的Spore.exe
编译成功后通过release文件夹中的安装程序进行安装
# 或
python main_entry.py
```

---

## 构建 Windows 安装包

### 前置要求

- Python 3.10+
- Node.js 18.x / 20.x LTS
- Rust + Cargo
- Visual Studio Build Tools（Windows）
- PyInstaller：`pip install pyinstaller`

### 一键构建

```bash
build_installer.bat
```

该脚本会自动完成以下步骤：
1. 使用 PyInstaller 构建后端（onefile 模式，单文件可执行程序）
2. 准备 Tauri sidecar（复制后端 exe 并重命名为 `spore_backend-x86_64-pc-windows-msvc.exe`）
3. 准备资源文件（prompt/skills/characters/.env/rg.exe）
4. 构建 Tauri 前端并打包 NSIS 安装包
5. 复制所有构建产物到 `release/` 目录

### 输出文件

```
release/
├── Spore.exe                           # Tauri 前端可执行文件
└── Spore_1.0.0_x64-setup.exe          # NSIS 安装包（推荐分发）
```

### 安装后目录结构

```
安装目录/
├── Spore.exe                    # Tauri 前端
├── spore_backend.exe            # Python 后端（单文件，包含所有依赖）
├── rg.exe                       # ripgrep 搜索工具
├── prompt/                      # 提示词模板（只读）
├── skills/                      # 技能包（只读）
├── characters/                  # 角色定义（只读）
├── .env                         # 配置文件
└── 运行时创建的目录：
    ├── output/                  # 输出文件
    ├── history/                 # 对话历史
    ├── logs/                    # 日志文件
    └── note.txt                 # 笔记文件
```

---

## 手动构建（高级）

如果需要单独构建各个组件：

### 1. 构建后端

```bash
# 安装 PyInstaller
pip install pyinstaller

# 构建单文件可执行程序（onefile 模式）
pyinstaller spore_backend.spec --noconfirm
```

输出位置：`dist/spore_backend.exe`（单文件，约 50-80MB）

### 2. 构建前端

```bash
cd desktop_app/frontend

# 安装依赖
npm install

# 构建 Tauri 应用
npm run tauri build
```

输出位置：
- 可执行文件：`desktop_app/frontend/src-tauri/target/release/Spore.exe`
- NSIS 安装包：`desktop_app/frontend/src-tauri/target/release/bundle/nsis/Spore_1.0.0_x64-setup.exe`

---

## 构建配置

### PyInstaller 配置（spore_backend.spec）

关键配置说明：

- **模式**：onefile 模式，所有依赖打包到单个 exe 文件
- **入口**：`main_entry.py`
- **资源文件**：不包含在 exe 中，由 Tauri 的 resources 机制处理
- **隐藏导入**：包含所有必需的 Python 模块（base、desktop_app、uvicorn、fastapi 等）
- **排除模块**：排除不需要的大型库（tkinter、matplotlib、numpy 等）
- **UPX 压缩**：启用，但排除 Python DLL 以避免兼容性问题
- **控制台**：`console=False`，无控制台窗口

### Tauri 配置（tauri.conf.json）

关键配置说明：

- **产品名称**：Spore
- **版本**：1.0.0
- **打包目标**：NSIS（Windows 安装包）
- **标识符**：com.spore.desktop
- **资源文件**：prompt/、skills/、characters/、.env、rg.exe
- **外部二进制**：spore_backend（自动添加平台后缀）
- **窗口配置**：1400x900，最小 1000x600，无边框，透明背景

---

## 常见问题

### Q: PyInstaller 打包后运行报错？

检查 `spore_backend.spec` 中的 `hiddenimports` 是否包含所有依赖模块。常见缺失模块：
- base 及其子模块
- desktop_app 及其子模块
- uvicorn、fastapi、starlette
- openai、anthropic、tiktoken

### Q: Tauri 构建失败？

1. 确保已安装 Rust：`rustc --version`
2. 确保已安装 Visual Studio Build Tools（包含 C++ 工具）
3. 检查 Node.js 版本：推荐 18.x 或 20.x LTS
4. 清理缓存后重试：删除 `desktop_app/frontend/dist` 和 `node_modules/.vite`

### Q: build_installer.bat 执行失败？

1. 检查是否缺少 `.env` 文件（必需）
2. 检查是否缺少 `rg.exe`（ripgrep，必需）
3. 确保 PyInstaller 已安装：`pip install pyinstaller`
4. 查看错误信息，确认是哪个步骤失败

### Q: 安装包体积太大？

后端 exe 约 50-80MB 是正常的（包含 Python 运行时和所有依赖）。
PyInstaller spec 已启用 UPX 压缩，无需额外操作。

### Q: 如何修改安装包图标？

修改 `desktop_app/frontend/src-tauri/icons/icon.ico`，然后重新构建。

---

## 开发模式

### 前端开发

```bash
cd desktop_app/frontend
npm run dev
```

前端会在 `http://localhost:1420` 启动，支持热重载。

### 后端开发

```bash
python main_entry.py
```

后端 API 在 `http://127.0.0.1:8765` 启动。

### 调试 Tauri

```bash
cd desktop_app/frontend
npm run tauri dev
```

会同时启动前端开发服务器和 Tauri 窗口。
