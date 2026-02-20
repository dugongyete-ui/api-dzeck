#!/bin/bash

set -e

echo "============================================"
echo "  FreeGPT4 Web API - Auto Install Script"
echo "============================================"
echo ""

TOTAL_PACKAGES=18
INSTALLED=0
FAILED=0
FAILED_LIST=""

install_package() {
    local pkg="$1"
    INSTALLED=$((INSTALLED + 1))
    echo "[$INSTALLED/$TOTAL_PACKAGES] Installing $pkg..."
    if pip install --quiet "$pkg" 2>/dev/null; then
        echo "  -> OK"
    else
        FAILED=$((FAILED + 1))
        FAILED_LIST="$FAILED_LIST $pkg"
        echo "  -> FAILED"
    fi
}

echo "[Step 1/3] Upgrading pip..."
pip install --quiet --upgrade pip 2>/dev/null
echo "  -> OK"
echo ""

echo "[Step 2/3] Installing dependencies (parallel batch)..."
echo ""

pip install --quiet \
    "flask[async]" \
    "g4f" \
    "werkzeug>=3.1.4" \
    "aiohttp" \
    "aiohttp_socks" \
    "curl_cffi" \
    "trio" \
    "eventlet" \
    "python-multipart" \
    "nodriver" \
    "platformdirs" \
    "uvicorn" \
    "fastapi" \
    "requests" \
    "flask-cors" \
    "psycopg2-binary" \
    "gunicorn" \
    2>&1 | tail -5

echo ""
echo "[Step 3/3] Verifying installation..."
echo ""

VERIFY_PASS=0
VERIFY_FAIL=0

verify_import() {
    local module="$1"
    local display_name="${2:-$module}"
    if python -c "import $module" 2>/dev/null; then
        echo "  [OK] $display_name"
        VERIFY_PASS=$((VERIFY_PASS + 1))
    else
        echo "  [FAIL] $display_name"
        VERIFY_FAIL=$((VERIFY_FAIL + 1))
    fi
}

verify_import "flask" "Flask"
verify_import "g4f" "g4f (GPT4Free)"
verify_import "werkzeug" "Werkzeug"
verify_import "aiohttp" "aiohttp"
verify_import "aiohttp_socks" "aiohttp_socks"
verify_import "curl_cffi" "curl_cffi"
verify_import "trio" "trio"
verify_import "eventlet" "eventlet"
verify_import "multipart" "python-multipart"
verify_import "nodriver" "nodriver"
verify_import "platformdirs" "platformdirs"
verify_import "uvicorn" "uvicorn"
verify_import "fastapi" "FastAPI"
verify_import "requests" "requests"
verify_import "flask_cors" "flask-cors"
verify_import "psycopg2" "psycopg2-binary"
verify_import "gunicorn" "gunicorn"

echo ""
echo "============================================"
echo "  Installation Summary"
echo "============================================"
echo "  Verified: $VERIFY_PASS passed, $VERIFY_FAIL failed"
echo ""

if [ $VERIFY_FAIL -eq 0 ]; then
    echo "  All dependencies installed successfully!"
    echo ""
    echo "  To start the server, run:"
    echo "    python src/FreeGPT4_Server.py --port 5000 --enable-gui --password YOUR_PASSWORD"
    echo ""
else
    echo "  Some dependencies failed to install."
    echo "  Try running: pip install -r requirements.txt"
    echo ""
fi

echo "============================================"
