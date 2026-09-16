@echo off
title SIDIK - Secret Identification and Dependency Inspection Kit
cd /d "%~dp0"

if "%~1"=="" (
    python sidik.py
    pause
) else (
    python sidik.py %*
)
