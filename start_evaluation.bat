@echo off
title SafeContain AI - Evaluator Launcher
color 0A

echo ===============================================================================
echo                SAFECONTAIN AI - EVALUATION & DEMONSTRATION LAUNCHER
echo                 Author: Saanvi Negi  ^|  SafeContain AI Systems
echo ===============================================================================
echo.

echo [1/3] Running Automated Test Suite Verification (37 Tests)...
python run_ci_tests.py
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Tests failed or dependencies not installed. Run: pip install -r requirements.txt
    pause
    exit /b %ERRORLEVEL%
)
echo [SUCCESS] Automated test suite passed 100%%!
echo.

echo [2/3] Starting SafeContain AI Backend Application Server (FastAPI)...
start "SafeContain AI - Backend Server" cmd /k "python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000"
echo [SUCCESS] Backend server launched at http://127.0.0.1:8000
echo.

echo [3/3] Serving Production Frontend Dashboard...
start "SafeContain AI - Frontend Server" cmd /k "python -m http.server 5173 --directory frontend/dist"
echo [SUCCESS] Frontend server launched at http://localhost:5173
echo.

echo ===============================================================================
echo  Application is now running!
echo  - Frontend Dashboard: http://localhost:5173
echo  - Interactive API Docs: http://127.0.0.1:8000/docs
echo ===============================================================================
echo.
echo Opening browser...
start http://localhost:5173
pause
