#!/bin/bash
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_PYTHON="$PROJECT_DIR/venv/bin/python3"
SCANNER_SCRIPT="$PROJECT_DIR/modules/scanner.py"

([ "$EUID" -ne 0 ] && sudo "$VENV_PYTHON" "$SCANNER_SCRIPT") || ([ "$EUID" -eq 0 ] && "$VENV_PYTHON" "$SCANNER_SCRIPT")