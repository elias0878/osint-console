#!/usr/bin/env bash
# تشغيل منصة OSINT Console
set -euo pipefail
cd "$(dirname "$0")"
PORT="${1:-8000}"
command -v python3 >/dev/null || { echo "✗ Python 3 مطلوب"; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3,9), "Python 3.9+ مطلوب"' || exit 1
echo "▶ OSINT Console → http://localhost:$PORT"
exec python3 server.py --port "$PORT"
