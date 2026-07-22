# Build Guide (v4.0)

> [中文](../BUILD.md)

This document explains how to build the **Spore 4.0** Windows desktop installer from source (Tauri + a PyInstaller backend sidecar).

---

## Artifacts and Versions

| Component | Version field location |
|------|--------------|
| Python project | `pyproject.toml` → `version` |
| Frontend npm | `desktop_app/frontend/package.json` |
| Tauri app | `desktop_app/frontend/src-tauri/tauri.conf.json` → `package.version` |
| Rust crate | `desktop_app/frontend/src-tauri/Cargo.toml` |
| FastAPI | `desktop_app/backend/server.py` / `standalone.py` |

> All of the fields above are currently `4.0.0`; when bumping the version, keep every field consistent before building.

Installer output:

- `desktop_app/frontend/src-tauri/target/release/bundle/nsis/`
- The script aggregates the artifacts into the root-level `release/` directory (`Spore.exe` + `Spore_<version>_x64-setup.exe`)

---

## Requirements

- Windows 10/11 x64
- Python ≥ 3.10 (the build environment actually uses 3.13)
- [uv](https://github.com/astral-sh/uv)
- Node.js 18+ or 20 LTS
- Rust (`rustup`, MSVC toolchain)
- Visual Studio Build Tools (C++ desktop development)
- PowerShell (the script uses it to download/verify ripgrep)
- A working `.env` in the project root (packaging copies it as a resource; **if missing, the build fails**)

---

## One-Click Build (Recommended)

```bat
build_installer.bat
```

The script has 6 stages:

1. **PyInstaller backend (onefile)**: cleans old artifacts; automatically runs `uv sync` if `.venv` lacks pyinstaller (or set `FORCE_UV_SYNC=1` to force it); runs `uv run pyinstaller spore_backend.spec --noconfirm`, producing `dist/spore_backend.exe`
2. **Tauri sidecar**: copies it to `desktop_app/frontend/src-tauri/binaries/spore_backend-x86_64-pc-windows-msvc.exe` (Tauri `externalBin` requires the platform-triple suffix)
3. **Resource sync**: copies `prompt/`, `skills/`, `characters/`, `.env` into `src-tauri/`; downloads and SHA256-verifies **ripgrep 14.1.1** (cached in `.tool-cache/ripgrep/`), copies `rg.exe`
4. **Frontend + Tauri build**: cleans the Vite cache; runs `npm install` if `node_modules` is missing (or `FORCE_NPM_INSTALL=1`); `npm run tauri build` produces the NSIS installer
5. **Artifact aggregation**: copies `Spore.exe` and the NSIS installer to the root-level `release/` directory
6. **Report**: prints the artifact list and an explanation of the installation directory structure

On failure, troubleshoot based on the failing stage; if any stage fails, the script stops at `:error` with a message.

---

## Step-by-Step Build

### 1. Python Backend

```bash
uv sync
uv run pyinstaller spore_backend.spec --noconfirm
```

The artifact is a single file `dist/spore_backend.exe`; copy it to the file name required by the Tauri `externalBin`:

```text
desktop_app/frontend/src-tauri/binaries/spore_backend-x86_64-pc-windows-msvc.exe
```

### 2. Frontend

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

Development / debugging:

```bash
# Terminal A: backend
uv run python main_entry.py   # LAUNCH_MODE=desktop

# Terminal B: frontend
cd desktop_app/frontend
npm run dev                   # Vite http://localhost:1420

# Or the Tauri dev window (automatically starts the backend via uv)
npm run tauri dev
```

Default API: `http://127.0.0.1:8765`, WebSocket: `ws://127.0.0.1:8766` (port + 1).

---

## Packaging Structure Notes

- **Backend**: PyInstaller **onefile** (`spore_backend.spec`), entry point `main_entry.py`, `console=False`; the spec's `datas` is empty — resources are not bundled into the exe
- **Resources**: carried by Tauri `resources`: `prompt/**`, `skills/**`, `characters/**`, `.env`, `rg.exe`; located at runtime via `SPORE_RESOURCE_DIR`
- **Process hosting**: Tauri `main.rs` launches the backend as a sidecar, injecting `SPORE_DESKTOP_MODE=1` and `SPORE_RESOURCE_DIR`, and uses a Windows Job Object to ensure the entire child-process tree exits when the window closes
- **Working directory**: after installation, `main.rs` and `resource_manager` ensure the cwd is correct and create writable directories (`output/`, `history/`, `logs/`, `note.txt`)
- **Hidden imports**: if a module is missing at runtime, add it to `hiddenimports` in `spore_backend.spec`

Installation directory layout (the authoritative structure printed by stage 6 of the script):

```text
Spore.exe              # Tauri frontend
spore_backend.exe      # Python backend (onefile, dependencies embedded)
rg.exe                 # ripgrep search tool
prompt/  skills/  characters/   # Read-only resources
.env                   # Configuration (copied from the project root at packaging time)
output/  history/  logs/  note.txt   # Generated at runtime
```

---

## FAQ

### PyInstaller reports a missing module at runtime

Complete `hiddenimports`: `base` and its subpackages, `AutoAgent`, `desktop_app`, `uvicorn`/`fastapi`/`starlette`, `openai`/`anthropic`/`tiktoken`, `bsdiff4`, etc.

### Tauri build fails

1. Check whether `rustc --version` / the VS C++ tools are available  
2. Check whether the Node version is too old  
3. Clean `desktop_app/frontend/dist` and `node_modules/.vite`, then retry  

### build_installer.bat fails

1. Whether the root directory has a `.env`  
2. Whether the network can fetch ripgrep  
3. Delete `.tool-cache/ripgrep/` and retry  
4. Whether `uv sync` succeeded  

### Installer size

The backend onefile is about 25–30MB; the NSIS installer is on the order of 30MB (including the Python runtime).

### Changing the icon

Replace the contents of `desktop_app/frontend/src-tauri/icons/` and rebuild.

### Changing the version number

Update all version fields in the "Artifacts and Versions" table to the same version (e.g. `4.0.0`), then run a full build.

---

## Related

- [Architecture Design](ARCHITECTURE.md)
- [Configuration Guide](CONFIGURATION.md)
- [Frontend Guide](FRONTEND.md)
