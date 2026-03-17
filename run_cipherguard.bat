@echo off
title CipherGuard - Secure File Encryption
color 0B

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed!
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check if required package is installed
python -c "import customtkinter" >nul 2>&1
if errorlevel 1 (
    echo [*] Installing required packages...
    pip install customtkinter cryptography
    if errorlevel 1 (
        echo [ERROR] Failed to install packages
        pause
        exit /b 1
    )
)

REM Run the application
cls
echo ===============================================
echo    CipherGuard - Secure File Encryption
echo ===============================================
echo.
echo [*] Launching application...
python frontend.py

if errorlevel 1 (
    echo.
    echo [ERROR] Application crashed!
    pause
)