@echo off
chcp 65001 >nul
title SIDIK CLI v1.0 - Interactive Security Console
cd /d "%~dp0"

if "%~1"=="" (
    python sidik.py --cli
) else (
    python sidik.py %*
    pause
)
