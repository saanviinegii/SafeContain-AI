@echo off
title SafeContain AI - Evaluator Launcher
color 0A

echo ===============================================================================
echo                SAFECONTAIN AI - EVALUATION & DEMONSTRATION LAUNCHER
echo                 Author: Saanvi Negi  ^|  SafeContain AI Systems
echo ===============================================================================
echo.

echo [1/2] Verifying Core Engine Unit Tests (25 Tests)...
python -m pytest tests/unit -q
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Core tests encountered issues, continuing launch...
) else (
    echo [SUCCESS] Core test suite passed 100%%!
)
echo.

echo [2/2] Starting SafeContain AI Unified Application Server...
echo ===============================================================================
echo  Application is running unified (Frontend + Backend on single port):
echo  - Live Interactive Dashboard: http://127.0.0.1:8000/
echo  - Interactive API Docs:       http://127.0.0.1:8000/docs
echo  - System Health Endpoint:     http://127.0.0.1:8000/api/v1/health
echo ===============================================================================
echo.
echo Opening browser in 2 seconds...
timeout /t 2 /nobreak >nul
start http://127.0.0.1:8000/

python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
pause
