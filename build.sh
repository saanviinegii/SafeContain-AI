#!/usr/bin/env bash
# ==============================================================================
# SafeContain AI — Production Native Build Script for Render
# ==============================================================================
set -o errexit

echo ">>> [1/3] Upgrading build tools..."
python -m pip install --upgrade pip

echo ">>> [2/3] Installing Python dependencies..."
pip install -r requirements.txt

echo ">>> [3/3] Building React Frontend Console..."
if command -v npm &> /dev/null; then
    cd frontend
    npm install
    npm run build
    cd ..
    echo ">>> React Frontend built successfully into frontend/dist!"
else
    echo ">>> Notice: npm not found in build container. Operating in headless API mode."
fi

echo ">>> Build complete! Ready to start SafeContain AI."
