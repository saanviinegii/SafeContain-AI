#!/usr/bin/env bash
# SafeContain AI - Evaluator Launcher for Linux & macOS
# Author: Saanvi Negi | SafeContain AI Systems

set -e

echo "==============================================================================="
echo "               SAFECONTAIN AI - EVALUATION & DEMONSTRATION LAUNCHER"
echo "                Author: Saanvi Negi  |  SafeContain AI Systems"
echo "==============================================================================="
echo ""

echo "[1/2] Verifying Core Engine Unit Tests (25 Tests)..."
python3 -m pytest tests/unit -q
echo "[SUCCESS] Core test suite passed 100%!"
echo ""

echo "[2/2] Starting SafeContain AI Unified Application Server..."
echo "==============================================================================="
echo " Application is running unified (Frontend + Backend on single port):"
echo " - Live Interactive Dashboard: http://localhost:8000/"
echo " - Interactive API Docs:       http://localhost:8000/docs"
echo " - System Health Endpoint:     http://localhost:8000/api/v1/health"
echo "==============================================================================="
echo ""

python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
