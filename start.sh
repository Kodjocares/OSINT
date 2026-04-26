#!/usr/bin/env bash
# ─────────────────────────────────────────────────
# OSINT Tool v3.0 — Quick Launch Script (Linux/macOS)
# Double-click or run: ./start.sh
# ─────────────────────────────────────────────────
set -e
cd "$(dirname "$0")"

# Activate venv
if [ -d "venv" ]; then
    source venv/bin/activate
elif [ -d ".venv" ]; then
    source .venv/bin/activate
else
    echo "[!] No virtual environment found."
    echo "    Run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

# Launch mode
if [ "$1" = "cli" ]; then
    echo "[*] Launching CLI mode..."
    python main.py --interactive
else
    echo ""
    echo "  ██████╗ ███████╗██╗███╗   ██╗████████╗"
    echo " ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝"
    echo " ██║   ██║███████╗██║██╔██╗ ██║   ██║   "
    echo " ██║   ██║╚════██║██║██║╚██╗██║   ██║   "
    echo " ╚██████╔╝███████║██║██║ ╚████║   ██║   "
    echo "  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝  "
    echo ""
    echo "  v3.0 — 35 Modules | Web GUI"
    echo "  http://localhost:5000"
    echo ""
    python app.py
fi
