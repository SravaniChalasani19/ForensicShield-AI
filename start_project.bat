@echo off
setlocal enabledelayedexpansion
title ForensicShield AI - Project 218 Launcher
cd /d "%~dp0"

echo ======================================================================
echo           ForensicShield AI - Project 218 Launcher
echo  Anti-forensic Technique Detection via Natural Language Processing
echo ======================================================================
echo.

:: 1. Detect Python command
where python >nul 2>nul
if %errorlevel% equ 0 (
    set "PYTHON_CMD=python"
) else (
    where py >nul 2>nul
    if %errorlevel% equ 0 (
        set "PYTHON_CMD=py"
    ) else (
        echo [ERROR] Python was not found on your system PATH.
        echo.
        echo To fix this:
        echo 1. Install Python 3.10+ from https://www.python.org/
        echo 2. Check the box "Add Python to PATH" during installation.
        echo 3. Re-open Command Prompt and run this launcher again.
        echo.
        pause
        exit /b 1
    )
)

:: 2. Check virtual environment if present
if exist ".venv\Scripts\python.exe" (
    echo [INFO] Detected virtual environment in .venv
    set "PYTHON_CMD=.venv\Scripts\python.exe"
)

:: 3. Launch Master Python Runner
echo [INFO] Using Python: %PYTHON_CMD%
"%PYTHON_CMD%" run.py

if %errorlevel% neq 0 (
    echo.
    echo ======================================================================
    echo [ERROR] Application terminated with exit code %errorlevel%.
    echo Please review the messages above or refer to TROUBLESHOOTING.md.
    echo ======================================================================
    echo.
    pause
)
