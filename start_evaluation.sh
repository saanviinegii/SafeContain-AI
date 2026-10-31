#!/usr/bin/env bash
# SafeContain AI - Evaluator Launcher for Linux & macOS
# Author: Saanvi Negi | SafeContain AI Systems

set -e

echo "==============================================================================="
echo "               SAFECONTAIN AI - EVALUATION & DEMONSTRATION LAUNCHER"
echo "                Author: Saanvi Negi  |  SafeContain AI Systems"
echo "==============================================================================="
echo ""

echo "[1/3] Running Automated Test Suite Verification (37 Tests)..."
python3 run_ci_tests.py
echo "[SUCCESS] Automated test suite passed 100%!"
echo ""

echo "[2/3] Starting SafeContain AI Backend Application Server..."
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
echo "[SUCCESS] Backend server launched at http://localhost:8000 (PID: $BACKEND_PID)"
echo ""

echo "[3/3] Serving Production Frontend Dashboard..."
python3 -m http.server 5173 --directory frontend/dist &
FRONTEND_PID=$!
echo "[SUCCESS] Frontend server launched at http://localhost:5173 (PID: $FRONTEND_PID)"
echo ""

echo "==============================================================================="
echo " Application is now running!"
echo " - Frontend Dashboard: http://localhost:5173"
echo " - Interactive API Docs: http://localhost:8000/docs"
echo " Press Ctrl+C to stop both servers."
echo "==============================================================================="

trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT TERM
wait
