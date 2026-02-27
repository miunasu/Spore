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
set "UV_CACHE_DIR=%PROJECT_ROOT%\.uv-cache"

REM ----------------------------------------
REM Environment Check
REM ----------------------------------------
echo [CHECK] Checking build environment...

where uv >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] uv not found
    echo [ERROR] Install uv first: https://docs.astral.sh/uv/getting-started/installation/
    goto :error
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

echo Syncing Python dependencies with uv...
call uv sync
if %ERRORLEVEL% neq 0 (
    echo [ERROR] uv sync failed
    goto :error
)

echo Executing PyInstaller (uv run, onefile mode)...
call uv run pyinstaller spore_backend.spec --noconfirm
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

REM Resources are placed directly in src-tauri directory
REM After packaging, they will be in the installation root directory
REM This way cwd can directly access prompt/skills/characters without SPORE_RESOURCE_DIR

REM Clean old resources
if exist "%TAURI_DIR%\prompt" rmdir /s /q "%TAURI_DIR%\prompt"
if exist "%TAURI_DIR%\skills" rmdir /s /q "%TAURI_DIR%\skills"
if exist "%TAURI_DIR%\characters" rmdir /s /q "%TAURI_DIR%\characters"

REM Copy read-only resources to src-tauri directory
echo Copying prompt/...
xcopy /s /e /y /q "%PROJECT_ROOT%\prompt" "%TAURI_DIR%\prompt\" >nul

echo Copying skills/...
xcopy /s /e /y /q "%PROJECT_ROOT%\skills" "%TAURI_DIR%\skills\" >nul

echo Copying characters/...
xcopy /s /e /y /q "%PROJECT_ROOT%\characters" "%TAURI_DIR%\characters\" >nul

REM Copy .env (use config file from project root)
echo Copying .env...
if exist "%PROJECT_ROOT%\.env" (
    copy /y "%PROJECT_ROOT%\.env" "%TAURI_DIR%\.env" >nul
) else (
    echo [ERROR] .env does not exist, please create config file first
    goto :error
)

REM Copy ripgrep (rg.exe) - copy directly from project directory
echo Copying rg.exe (ripgrep)...
if exist "%PROJECT_ROOT%\rg.exe" (
    copy /y "%PROJECT_ROOT%\rg.exe" "%TAURI_DIR%\rg.exe" >nul
) else (
    echo [ERROR] rg.exe does not exist, please place ripgrep in project root
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

cd "%FRONTEND_DIR%"

REM Clean frontend cache
if exist "dist" rmdir /s /q "dist"
if exist ".vite" rmdir /s /q ".vite"
if exist "node_modules\.vite" rmdir /s /q "node_modules\.vite"

REM Install dependencies
echo Installing frontend dependencies...
call npm install
if %ERRORLEVEL% neq 0 (
    echo [ERROR] npm install failed
    goto :error
)

REM Build Tauri (will automatically build frontend first)
echo Building Tauri application...
call npm run tauri build
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Tauri build failed
    goto :error
)

echo [OK] Tauri build complete
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

REM Copy NSIS installer
set "BUNDLE_DIR=%TAURI_DIR%\target\release\bundle\nsis"
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
