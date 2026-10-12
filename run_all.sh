#!/usr/bin/env bash
#
# run_all.sh
# ----------
# One-command pipeline:
#   1. verify / install dependencies
#   2. validate input files
#   3. launch background harvester (harvester.py) to keep proxy pool alive
#   4. build working-proxies.txt via the checker
#   5. launch the traffic loop (loop.py)
#
# Usage:
#   chmod +x run_all.sh
#   ./run_all.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
RAW_PROXY_FILE="free-proxy-list.txt"    # Harvester output -> checker input
WORKING_FILE="working-proxies.txt"      # Checker output -> loop input
URL_FILE="urls.txt"
CHECK_WORKERS=64
CHECK_TIMEOUT=8

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
info()  { printf '\033[1;34m[run_all]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[run_all]\033[0m %s\n' "$*"; }
fail()  { printf '\033[1;31m[run_all]\033[0m %s\n' "$*" >&2; exit 1; }

# Track background harvester PID for cleanup
HARVESTER_PID=""
cleanup() {
    if [[ -n "$HARVESTER_PID" ]]; then
        info "Stopping background proxy harvester (PID $HARVESTER_PID)..."
        kill "$HARVESTER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. DEPENDENCIES
# ---------------------------------------------------------------------------
info "Checking dependencies..."

command -v python3 >/dev/null 2>&1 || fail "python3 not found on PATH"
PY=python3

if ! "$PY" -c "import httpx" >/dev/null 2>&1; then
    info "Installing httpx and playwright..."
    "$PY" -m pip install --upgrade pip httpx playwright
fi

if ! "$PY" -c "from playwright.sync_api import sync_playwright; sync_playwright" >/dev/null 2>&1; then
    fail "playwright import failed"
fi

if ! ls ~/.cache/ms-playwright/chromium* >/dev/null 2>&1; then
    info "Installing chromium browser + system deps..."
    playwright install --with-deps chromium
else
    info "Chromium already installed."
fi

# ---------------------------------------------------------------------------
# 2. INPUT VALIDATION
# ---------------------------------------------------------------------------
info "Validating input files..."

[[ -f "$URL_FILE" ]]     || fail "Missing $URL_FILE (put your smartlink(s) in it)"
[[ -s "$URL_FILE" ]]     || fail "$URL_FILE is empty"

# Ensure proxy files exist so checks don't fail on fresh start
touch "$RAW_PROXY_FILE"
touch "$WORKING_FILE"

[[ -f "check_proxies.py" ]] || fail "Missing check_proxies.py"
[[ -f "harvester.py" ]]     || fail "Missing harvester.py"
[[ -f "loop.py" ]]          || fail "Missing loop.py"

info "Inputs OK: $(wc -l < "$URL_FILE") url(s)."

# ---------------------------------------------------------------------------
# 3. START BACKGROUND HARVESTER
# ---------------------------------------------------------------------------
info "Starting background proxy harvester (harvester.py)..."
"$PY" harvester.py &
HARVESTER_PID=$!

info "Waiting for harvester to populate initial proxies in $RAW_PROXY_FILE..."
while [[ ! -s "$RAW_PROXY_FILE" ]]; do
    sleep 3
done
info "Initial proxies found in $RAW_PROXY_FILE."

# ---------------------------------------------------------------------------
# 4. BUILD WORKING LIST
# ---------------------------------------------------------------------------
info "Testing proxies via check_proxies.py..."
"$PY" check_proxies.py \
    -i "$RAW_PROXY_FILE" \
    -o "$WORKING_FILE" \
    -t "$CHECK_TIMEOUT" \
    -w "$CHECK_WORKERS"

"$PY" geo_resolve.py

WORKING_COUNT=$(grep -cve '^\s*$' "$WORKING_FILE" || true)
if [[ "$WORKING_COUNT" -eq 0 ]]; then
    warn "No working proxies found in initial batch, but background harvester is running to fetch more."
fi
info "Built $WORKING_FILE with $WORKING_COUNT working proxy line(s)."

# ---------------------------------------------------------------------------
# 5. LAUNCH LOOP
# ---------------------------------------------------------------------------
info "Starting loop.py with background harvester running continuously (Ctrl-C to stop)..."
exec "$PY" loop.py
