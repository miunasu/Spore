@echo off
title Spore AI - Log Monitor
set "UV_CACHE_DIR=%~dp0.uv-cache"
uv run python base/log_monitor.py %*
pause
