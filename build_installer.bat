@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

REM ========================================
REM Spore Desktop Complete Installer Build Script
REM Steps:
REM   1. PyInstaller package backend (onefile mode, single exe)
REM   2. Prepare Tauri sidecar (copy one exe only)
REM   3. Prepare Tauri resource files
REM   4. Build Tauri NSIS installer
REM   5. Copy artifacts to project root
REM ========================================

echo ========================================
echo  Spore Desktop Installer Build
echo ========================================
echo.

cd /d "%~dp0"
set "PROJECT_ROOT=%cd%"
set "FRONTEND_DIR=%PROJECT_ROOT%\desktop_app\frontend"
set "TAURI_DIR=%FRONTEND_DIR%\src-tauri"
set "NSIS_PATCHER=%PROJECT_ROOT%\desktop_app\scripts\patch_nsis_installer.py"
set "NSIS_SCRIPT=%TAURI_DIR%\target\release\nsis\x64\installer.nsi"
set "NSIS_BUNDLE_DIR=%TAURI_DIR%\target\release\bundle\nsis"
set "PROJECT_PYTHON=%PROJECT_ROOT%\.venv\Scripts\python.exe"
set "UV_CACHE_DIR=%PROJECT_ROOT%\.uv-cache"
set "TOOLS_CACHE_DIR=%PROJECT_ROOT%\.tool-cache"
set "RG_VERSION=14.1.1"
set "RG_PACKAGE_NAME=ripgrep-%RG_VERSION%-x86_64-pc-windows-msvc.zip"
set "RG_PACKAGE_SHA256=%RG_PACKAGE_NAME%.sha256"
set "RG_RELEASE_BASE_URL=https://github.com/BurntSushi/ripgrep/releases/download/%RG_VERSION%"
set "RG_CACHE_DIR=%TOOLS_CACHE_DIR%\ripgrep\%RG_VERSION%"
set "RG_ARCHIVE_PATH=%RG_CACHE_DIR%\%RG_PACKAGE_NAME%"
set "RG_SHA256_PATH=%RG_CACHE_DIR%\%RG_PACKAGE_SHA256%"
set "RG_EXTRACT_DIR=%RG_CACHE_DIR%\ripgrep-%RG_VERSION%-x86_64-pc-windows-msvc"
set "RG_EXE_PATH=%RG_EXTRACT_DIR%\rg.exe"

REM ----------------------------------------
REM Environment Check
REM ----------------------------------------
echo [CHECK] Checking build environment...

where uv >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [WARN] uv not found
    echo.
    
    REM Check if Python is available
    where python >nul 2>nul
    if !ERRORLEVEL! neq 0 (
        echo [ERROR] uv is required to build the project
        echo [ERROR] Install uv first: https://docs.astral.sh/uv/getting-started/installation/
        goto :error
    )
    
    set /p "INSTALL_UV=Do you want to install uv using Python pip? (Y/N): "
    if /I "!INSTALL_UV!"=="Y" (
        echo [INFO] Installing uv via pip...
        python -m pip install uv
        if !ERRORLEVEL! neq 0 (
            echo [ERROR] Failed to install uv via pip
            echo [ERROR] Please install uv manually: https://docs.astral.sh/uv/getting-started/installation/
            goto :error
        )
        echo [OK] uv installed successfully
    ) else (
        echo [ERROR] uv is required to build the project
        echo [ERROR] Install uv first: https://docs.astral.sh/uv/getting-started/installation/
        goto :error
    )
)

where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Node.js not found
    goto :error
)

where cargo >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Rust/Cargo not found
    goto :error
)

where powershell >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] PowerShell not found
    goto :error
)

if not exist "%PROJECT_ROOT%\pyproject.toml" (
    echo [ERROR] pyproject.toml not found
    echo [HINT] Please sync latest branch code before building.
    goto :error
)

if not exist "%NSIS_PATCHER%" (
    echo [ERROR] NSIS data guard patcher not found: %NSIS_PATCHER%
    goto :error
)

echo [OK] Build environment check passed
echo.

REM ----------------------------------------
REM Step 1: PyInstaller package backend (onefile mode)
REM ----------------------------------------
echo ========================================
echo [1/6] PyInstaller packaging backend (onefile)...
echo ========================================

REM Clean old build artifacts
if exist "dist\spore_backend.exe" (
    echo Cleaning old dist\spore_backend.exe...
    del /f "dist\spore_backend.exe"
)
if exist "dist\spore_backend" (
    echo Cleaning old dist\spore_backend directory...
    rmdir /s /q "dist\spore_backend"
)
if exist "build\spore_backend" (
    echo Cleaning old build\spore_backend...
    rmdir /s /q "build\spore_backend"
)

set "BACKEND_DEPS_NEED_UPDATE=0"
if not exist "%PROJECT_PYTHON%" (
    set "BACKEND_DEPS_NEED_UPDATE=1"
) else (
    "%PROJECT_PYTHON%" -c "import inspect; from anthropic import Anthropic; assert 'output_config' in inspect.signature(Anthropic(api_key='build-check').messages.stream).parameters" >nul 2>nul
    if !ERRORLEVEL! neq 0 set "BACKEND_DEPS_NEED_UPDATE=1"
    "%PROJECT_PYTHON%" -c "import PyInstaller" >nul 2>nul
    if !ERRORLEVEL! neq 0 set "BACKEND_DEPS_NEED_UPDATE=1"
)

if "!BACKEND_DEPS_NEED_UPDATE!"=="1" (
    echo [WARN] Anthropic SDK is missing/too old or PyInstaller is unavailable.
    echo [INFO] Updating project build dependencies automatically from uv.lock...
) else (
    echo [OK] Existing Anthropic SDK supports output_config.
    echo [INFO] Checking project dependencies against uv.lock...
)

call uv sync --locked --group dev
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Automatic dependency update failed: uv sync --locked --group dev
    goto :error
)

if not exist "%PROJECT_PYTHON%" (
    echo [ERROR] Project Python not found after dependency update: %PROJECT_PYTHON%
    goto :error
)

echo Verifying build SDK versions after dependency update...
call "%PROJECT_PYTHON%" -c "import inspect, anthropic, PyInstaller; from anthropic import Anthropic; assert 'output_config' in inspect.signature(Anthropic(api_key='build-check').messages.stream).parameters, 'Anthropic SDK does not support output_config'; print('anthropic ' + anthropic.__version__ + ' (output_config supported)'); print('PyInstaller ' + PyInstaller.__version__)"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Dependency update completed, but the required SDK interface is still unavailable.
    echo [HINT] Check pyproject.toml and uv.lock, then run: uv lock --upgrade-package anthropic
    goto :error
)

echo Executing project PyInstaller (onefile mode)...
call "%PROJECT_PYTHON%" -m PyInstaller spore_backend.spec --noconfirm
if %ERRORLEVEL% neq 0 (
    echo [ERROR] PyInstaller packaging failed
    goto :error
)

REM onefile mode output is at dist/spore_backend.exe (single file)
if not exist "dist\spore_backend.exe" (
    echo [ERROR] Build artifact dist\spore_backend.exe does not exist
    goto :error
)

REM Display file size
for %%f in ("dist\spore_backend.exe") do (
    echo [OK] Backend packaging complete: dist\spore_backend.exe (%%~zf bytes)
)
echo.

REM ----------------------------------------
REM Step 2: Prepare Tauri sidecar binary
REM ----------------------------------------
echo ========================================
echo [2/6] Preparing Tauri sidecar...
echo ========================================

set "BINARIES_DIR=%TAURI_DIR%\binaries"
if not exist "%BINARIES_DIR%" mkdir "%BINARIES_DIR%"

REM Clean old sidecar files
if exist "%BINARIES_DIR%" (
    echo Cleaning old binaries directory...
    del /f /q "%BINARIES_DIR%\*" 2>nul
)

REM Tauri externalBin requires filename with platform suffix
set "SIDECAR_NAME=spore_backend-x86_64-pc-windows-msvc.exe"

REM onefile mode only needs to copy one exe
echo Copying spore_backend.exe to %SIDECAR_NAME%
copy /y "dist\spore_backend.exe" "%BINARIES_DIR%\%SIDECAR_NAME%" >nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to copy sidecar exe
    goto :error
)

echo [OK] Sidecar preparation complete (single file mode, no dependencies needed)
echo.

REM ----------------------------------------
REM Step 3: Prepare Tauri resource files
REM ----------------------------------------
echo ========================================
echo [3/6] Preparing resource files...
echo ========================================

REM Tauri bundles prompt/skills/characters/.env_example (installed as .env) directly from PROJECT_ROOT
REM via src-tauri/tauri.conf.json resource mappings.
if not exist "%PROJECT_ROOT%\.env_example" (
    echo [ERROR] .env_example does not exist, please create config file first
    goto :error
)

REM Ensure ripgrep exists (download + SHA256 verify + cache)
echo Preparing rg.exe (ripgrep)...
call :ensure_ripgrep
if %ERRORLEVEL% neq 0 (
    goto :error
)

copy /y "%RG_EXE_PATH%" "%TAURI_DIR%\rg.exe" >nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to copy rg.exe to Tauri resources
    goto :error
)

echo [OK] Resource files preparation complete
echo.

REM ----------------------------------------
REM Step 4: Build frontend and package Tauri
REM ----------------------------------------
echo ========================================
echo [4/6] Building Tauri installer...
echo ========================================

REM Generate src-tauri/.env from .env_example (placeholder config bundled into installer).
REM src-tauri/.env is gitignored; it is created fresh on every build.
copy /y "%PROJECT_ROOT%\.env_example" "%TAURI_DIR%\.env" >nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to copy .env_example to src-tauri/.env
    goto :error
)

REM Clean stale .env from Tauri release output to avoid os error 183 on re-builds.
if exist "%TAURI_DIR%\target\release\.env" (
    rmdir /s /q "%TAURI_DIR%\target\release\.env" 2>nul
    del /f "%TAURI_DIR%\target\release\.env" 2>nul
)

cd "%FRONTEND_DIR%"

REM Clean frontend cache
if exist "dist" rmdir /s /q "dist"
if exist ".vite" rmdir /s /q ".vite"
if exist "node_modules\.vite" rmdir /s /q "node_modules\.vite"
REM Keep exactly one fresh NSIS artifact so the data-guard patcher can replace it safely.
if exist "%NSIS_BUNDLE_DIR%" rmdir /s /q "%NSIS_BUNDLE_DIR%"

set "NEED_NPM_INSTALL=0"
if not exist "node_modules" set "NEED_NPM_INSTALL=1"
if /I "%FORCE_NPM_INSTALL%"=="1" set "NEED_NPM_INSTALL=1"

if "%NEED_NPM_INSTALL%"=="1" (
    echo Installing frontend dependencies...
    call npm install
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] npm install failed
        goto :error
    )
) else (
    echo [OK] Frontend dependencies already installed ^(skip npm install^)
)

REM Build Tauri (will automatically build frontend first)
echo Building Tauri application...
call npm run tauri build
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Tauri build failed
    goto :error
)

REM Tauri v1 has no lightweight installer hook. Patch its generated NSIS script
REM so upgrades detect and protect existing .env/skills/output/history/logs/.spore data.
echo Applying existing-data guard to NSIS installer...
"%PROJECT_PYTHON%" "%NSIS_PATCHER%" --nsi "%NSIS_SCRIPT%" --compile --bundle-dir "%NSIS_BUNDLE_DIR%"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to apply or compile NSIS existing-data guard
    goto :error
)

echo [OK] Tauri build complete ^(existing-data guard enabled^)
echo.

REM ----------------------------------------
REM Step 5: Copy artifacts to project root
REM ----------------------------------------
echo ========================================
echo [5/6] Copying artifacts to project root...
echo ========================================

set "RELEASE_DIR=%PROJECT_ROOT%\release"
if not exist "%RELEASE_DIR%" mkdir "%RELEASE_DIR%"

REM Clean old release directory
echo Cleaning old release directory...
del /f /q "%RELEASE_DIR%\*" 2>nul
for /d %%d in ("%RELEASE_DIR%\*") do rmdir /s /q "%%d" 2>nul

REM Copy Spore.exe (Tauri frontend)
if exist "%TAURI_DIR%\target\release\Spore.exe" (
    echo Copying Spore.exe...
    copy /y "%TAURI_DIR%\target\release\Spore.exe" "%RELEASE_DIR%\Spore.exe" >nul
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to copy Spore.exe
        goto :error
    )
) else (
    echo [WARN] Spore.exe not found
)

REM Copy NSIS installer (current version only; drop stale Spore_*_x64-setup.exe)
set "BUNDLE_DIR=%TAURI_DIR%\target\release\bundle\nsis"
if exist "%RELEASE_DIR%\Spore_*_x64-setup.exe" (
    echo Cleaning old installers in release directory...
    del /f /q "%RELEASE_DIR%\Spore_*_x64-setup.exe" >nul 2>nul
)
if exist "%BUNDLE_DIR%" (
    echo Copying NSIS installer...
    for %%f in ("%BUNDLE_DIR%\*.exe") do (
        copy /y "%%f" "%RELEASE_DIR%\" >nul
        echo   Copied: %%~nxf
    )
) else (
    echo [WARN] NSIS installer directory not found
)

echo [OK] Artifacts copied to release directory
echo.

REM ----------------------------------------
REM Step 6: Output results
REM ----------------------------------------
echo ========================================
echo [6/6] Build complete!
echo ========================================
echo.

echo Build artifacts location: %RELEASE_DIR%
echo.
if exist "%RELEASE_DIR%" (
    echo File list:
    for %%f in ("%RELEASE_DIR%\*") do (
        echo   %%~nxf (%%~zf bytes)
    )
) else (
    echo [WARN] release directory does not exist
)

echo.
echo Usage instructions:
echo   1. Development testing: Run release\Spore.exe directly
echo   2. Distribution: Use release\Spore_*_x64-setup.exe installer
echo.
echo Installation directory structure:
echo   Spore.exe                    # Tauri frontend
echo   spore_backend.exe            # Python backend (single file with all dependencies)
echo   rg.exe                       # ripgrep (search tool)
echo   prompt/                      # Read-only resources (directly in root)
echo   skills/
echo   characters/
echo   .env                         # Config file (copied from project root during packaging)
echo   output/                      # Created automatically at runtime
echo   history/
echo   logs/
echo   note.txt
echo.

cd "%PROJECT_ROOT%"
goto :end

:ensure_ripgrep
if exist "%RG_EXE_PATH%" (
    echo [OK] Using cached ripgrep: %RG_EXE_PATH%
    exit /b 0
)

echo [INFO] Downloading ripgrep %RG_VERSION%...
if not exist "%RG_CACHE_DIR%" mkdir "%RG_CACHE_DIR%"

if exist "%RG_ARCHIVE_PATH%" del /f /q "%RG_ARCHIVE_PATH%" >nul 2>nul
if exist "%RG_SHA256_PATH%" del /f /q "%RG_SHA256_PATH%" >nul 2>nul

powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing -Uri '%RG_RELEASE_BASE_URL%/%RG_PACKAGE_NAME%' -OutFile '%RG_ARCHIVE_PATH%'"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to download ripgrep package
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing -Uri '%RG_RELEASE_BASE_URL%/%RG_PACKAGE_SHA256%' -OutFile '%RG_SHA256_PATH%'"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to download ripgrep SHA256 file
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "$expected = (Select-String -Path '%RG_SHA256_PATH%' -Pattern '^[a-fA-F0-9]{64}$' | Select-Object -First 1).Line.ToLower(); if (-not $expected) { Write-Error 'Unable to parse SHA256 value from checksum file'; exit 1 }; $actual = (Get-FileHash -Path '%RG_ARCHIVE_PATH%' -Algorithm SHA256).Hash.ToLower(); if ($expected -ne $actual) { Write-Error ('SHA256 mismatch: expected ' + $expected + ', actual ' + $actual); exit 1 }"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] ripgrep package SHA256 verification failed
    exit /b 1
)

if exist "%RG_EXTRACT_DIR%" rmdir /s /q "%RG_EXTRACT_DIR%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -Path '%RG_ARCHIVE_PATH%' -DestinationPath '%RG_CACHE_DIR%' -Force"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to extract ripgrep archive
    exit /b 1
)

if not exist "%RG_EXE_PATH%" (
    echo [ERROR] ripgrep extracted, but rg.exe not found: %RG_EXE_PATH%
    exit /b 1
)

echo [OK] ripgrep ready: %RG_EXE_PATH%
exit /b 0

:error
echo.
echo ========================================
echo  Build failed! Please check error messages above
echo ========================================
cd "%PROJECT_ROOT%"
pause
exit /b 1

:end
pause
exit /b 0
