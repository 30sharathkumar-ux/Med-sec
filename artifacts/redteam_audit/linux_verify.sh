#!/usr/bin/env bash
set +e
cd /mnt/d/RAKSHA || exit 1

VENV_DIR=$(mktemp -d /tmp/raksha_venv_XXXXXX)
OUT_DIR=$(mktemp -d /tmp/raksha_out_XXXXXX)
OUT_OFF=$(mktemp -d /tmp/raksha_off_XXXXXX)

echo "=== 1. VENV & INSTALL ==="
python3 -m venv "$VENV_DIR"
RC_VENV=$?
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --upgrade pip >/dev/null 2>&1
pip install -r requirements.txt
RC_PIP=$?
echo "EXIT_VENV=$RC_VENV EXIT_PIP=$RC_PIP"

echo "=== 2. CHECK_SUBMISSION ==="
python check_submission.py --repo . --run
RC_SUB=$?
echo "EXIT_SUBMISSION=$RC_SUB"

echo "=== 3. LINUX PIPELINE ==="
export RAKSHA_SECRET="practice"
python main.py --input dev/input --output "$OUT_DIR"
RC_MAIN=$?
echo "EXIT_MAIN=$RC_MAIN"

echo "=== 4. VALIDATE_OUTPUT ==="
python validate_output.py --input dev/input --output "$OUT_DIR"
RC_VAL=$?
echo "EXIT_VALIDATE=$RC_VAL"

echo "=== 5. CHECK_DEV ==="
python check_dev.py --output "$OUT_DIR" --show 30
RC_DEV=$?
echo "EXIT_CHECK_DEV=$RC_DEV"

echo "=== 6. OFFLINE NETWORK CHECK ==="
python -c '
import socket
def blocked(*a, **kw):
    raise RuntimeError("NETWORK_CALL_ATTEMPTED")
socket.socket = blocked
socket.create_connection = blocked
from pathlib import Path
from rakshak.cli import run_pipeline
rc = run_pipeline(Path("dev/input"), Path("'"$OUT_OFF"'"))
print("OFFLINE_PIPELINE_RC=", rc)
'
RC_OFF=$?
echo "EXIT_OFFLINE=$RC_OFF"

rm -rf "$VENV_DIR" "$OUT_DIR" "$OUT_OFF"
