#!/usr/bin/env bash
# ==============================================================================
# SafeContain AI — Production Native Build Script for Render
# ==============================================================================
set -o errexit

echo ">>> [1/3] Upgrading build tools..."
python -m pip install --upgrade pip

echo ">>> [2/3] Installing Python dependencies..."
pip install -r requirements.txt

echo ">>> [3/3] Checking Node.js & Building React Frontend Console..."
if ! command -v npm &> /dev/null; then
    echo ">>> Node.js/npm not found. Downloading standalone Node.js LTS for frontend build..."
    NODE_VERSION="20.18.0"
    mkdir -p /tmp/nodejs
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.gz" | tar -xz -C /tmp/nodejs --strip-components=1
    export PATH="/tmp/nodejs/bin:$PATH"
fi

if command -v npm &> /dev/null; then
    echo ">>> Building React frontend using npm $(npm --version)..."
    cd frontend
    npm install
    npm run build
    cd ..
    echo ">>> React Frontend built successfully into frontend/dist!"
else
    echo ">>> Notice: npm could not be initialized. Operating in headless API mode."
fi

echo ">>> Build complete! Ready to start SafeContain AI."
