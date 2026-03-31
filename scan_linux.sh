#!/bin/bash
# axios-supply-chain-scanner — Linux (detection only)
# This script ONLY detects and reports. It does NOT modify, delete, or kill anything.
#
# Reference: https://socket.dev/blog/axios-npm-package-compromised
#            https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
# Date: 2026-03-31

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'
COMPROMISED=0
FINDINGS=""

log_finding() {
  FINDINGS="${FINDINGS}\n  - $1"
  COMPROMISED=1
}

echo "========================================"
echo " axios supply chain scanner — Linux"
echo " (detection only — no changes will be made)"
echo "========================================"
echo ""

# ── 1. Global npm: axios version ──────────────────────────────
echo "=== 1. Global npm — axios version ==="
AXIOS_HIT=$(npm list -g --depth=0 2>/dev/null | grep -E "axios@(1\.14\.1|0\.30\.4)" || true)
if [ -n "$AXIOS_HIT" ]; then
  echo -e "${RED}[!] AFFECTED${NC}: $AXIOS_HIT"
  log_finding "Malicious axios globally: $AXIOS_HIT"
else
  echo -e "${GREEN}[OK] Clean${NC}"
fi
echo ""

# ── 2. Global npm: plain-crypto-js ────────────────────────────
echo "=== 2. Global npm — plain-crypto-js ==="
PCJ_HIT=$(npm list -g --depth=0 2>/dev/null | grep "plain-crypto-js" || true)
if [ -n "$PCJ_HIT" ]; then
  echo -e "${RED}[!] AFFECTED${NC}: $PCJ_HIT"
  log_finding "Malicious plain-crypto-js globally: $PCJ_HIT"
else
  echo -e "${GREEN}[OK] Clean${NC}"
fi
echo ""

# ── 3. Scan all projects for plain-crypto-js ──────────────────
echo "=== 3. Full scan — plain-crypto-js directories ==="
FOUND=$(find "$HOME" -name "plain-crypto-js" -type d 2>/dev/null || true)
if [ -n "$FOUND" ]; then
  echo -e "${RED}[!] AFFECTED${NC}:"
  echo "$FOUND"
  while IFS= read -r line; do
    log_finding "plain-crypto-js directory: $line"
  done <<< "$FOUND"
else
  echo -e "${GREEN}[OK] None found${NC}"
fi
echo ""

# ── 4. npm cache scan ─────────────────────────────────────────
echo "=== 4. npm cache — plain-crypto-js ==="
CACHE_FOUND=$(find "$HOME/.npm" -name "plain-crypto-js" 2>/dev/null || true)
if [ -n "$CACHE_FOUND" ]; then
  echo -e "${YELLOW}[!] WARNING${NC}:"
  echo "$CACHE_FOUND"
  log_finding "npm cache: $CACHE_FOUND"
else
  echo -e "${GREEN}[OK] Clean${NC}"
fi
echo ""

# ── 5. RAT artifact: /tmp/ld.py ──────────────────────────────
echo "=== 5. RAT artifact — /tmp/ld.py ==="
if [ -f "/tmp/ld.py" ]; then
  echo -e "${RED}[!!!] COMPROMISED${NC}"
  ls -la "/tmp/ld.py"
  HASH=$(sha256sum /tmp/ld.py 2>/dev/null | cut -d' ' -f1 || true)
  echo "  SHA256 : $HASH"
  echo "  Known  : fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf"
  log_finding "Linux Python RAT: /tmp/ld.py (SHA256: $HASH)"
else
  echo -e "${GREEN}[OK] Clean${NC}"
fi
echo ""

# ── 6. RAT staging directory ─────────────────────────────────
echo "=== 6. RAT staging — \$TMPDIR/6202033 and /tmp/6202033 ==="
STAGING="${TMPDIR:-/tmp}/6202033"
STAGING_FOUND=""
if [ -e "$STAGING" ]; then
  STAGING_FOUND="$STAGING"
fi
if [ -e "/tmp/6202033" ]; then
  STAGING_FOUND="${STAGING_FOUND:+$STAGING_FOUND, }/tmp/6202033"
fi
if [ -n "$STAGING_FOUND" ]; then
  echo -e "${RED}[!!!] COMPROMISED${NC}"
  ls -la "$STAGING" 2>/dev/null || true
  ls -la "/tmp/6202033" 2>/dev/null || true
  log_finding "RAT staging: $STAGING_FOUND"
else
  echo -e "${GREEN}[OK] Clean${NC}"
fi
echo ""

# ── 7. Hidden RAT stage-3 payloads in /tmp ────────────────────
echo "=== 7. Hidden payloads — /tmp/.* (dot-prefixed binaries) ==="
HIDDEN=$(find /tmp -maxdepth 1 -name ".*" -type f -executable 2>/dev/null | head -20 || true)
if [ -n "$HIDDEN" ]; then
  echo -e "${YELLOW}[?] Suspicious hidden executables:${NC}"
  echo "$HIDDEN"
  log_finding "Suspicious hidden executables in /tmp (review manually)"
else
  echo -e "${GREEN}[OK] Clean${NC}"
fi
echo ""

# ── 8. Active RAT process check ──────────────────────────────
echo "=== 8. Process check — active RAT ==="
RAT_PROCS=""
LDP=$(pgrep -a -f "ld\.py" 2>/dev/null | grep -v grep || true)
CAMP=$(pgrep -a -f "6202033" 2>/dev/null | grep -v grep || true)
if [ -n "$LDP" ]; then
  RAT_PROCS="$LDP"
fi
if [ -n "$CAMP" ]; then
  RAT_PROCS="${RAT_PROCS:+$RAT_PROCS\n}$CAMP"
fi
if [ -n "$RAT_PROCS" ]; then
  echo -e "${RED}[!!!] COMPROMISED — RAT process running:${NC}"
  echo -e "$RAT_PROCS"
  log_finding "Active RAT process detected (see process list above)"
else
  echo -e "${GREEN}[OK] No RAT processes detected${NC}"
fi
echo ""

# ── 9. Network: C2 domain resolution ─────────────────────────
echo "=== 9. Network — C2 domain check ==="
C2_RESOLVED=""
if command -v host >/dev/null 2>&1 && host sfrclak.com >/dev/null 2>&1; then
  C2_RESOLVED=$(host sfrclak.com 2>/dev/null | grep "has address" | head -1 || true)
elif command -v dig >/dev/null 2>&1; then
  C2_RESOLVED=$(dig +short sfrclak.com 2>/dev/null || true)
fi
if [ -n "$C2_RESOLVED" ]; then
  echo -e "${YELLOW}[!] WARNING${NC}: C2 domain sfrclak.com resolves — ${C2_RESOLVED}"
  log_finding "C2 domain resolves: $C2_RESOLVED"
else
  echo -e "${GREEN}[OK] C2 domain does not resolve${NC}"
fi
echo ""

# ── 10. Network: active connections to C2 ─────────────────────
echo "=== 10. Network — active C2 connections ==="
C2_CONN=$(ss -tnp 2>/dev/null | grep -E "142\.11\.206\.73|sfrclak" || true)
if [ -n "$C2_CONN" ]; then
  echo -e "${RED}[!!!] COMPROMISED — active C2 connection:${NC}"
  echo "$C2_CONN"
  log_finding "Active C2 connection detected (see output above)"
else
  echo -e "${GREEN}[OK] No active C2 connections${NC}"
fi
echo ""

# ── 11. Project lockfile scan ─────────────────────────────────
echo "=== 11. Project lockfile scan ==="
LOCKFILE_FOUND=0
for DIR in "$HOME/Projects" "$HOME/projects" "$HOME/Documents" "$HOME/repos" "$HOME/dev" "$HOME/src" "$HOME/work" "$HOME/workspace"; do
  if [ -d "$DIR" ]; then
    HITS=$(find "$DIR" -name "package-lock.json" -exec grep -lE '"(axios|plain-crypto-js)".*"(1\.14\.1|0\.30\.4|4\.2\.1)"' {} \; 2>/dev/null || true)
    if [ -n "$HITS" ]; then
      echo -e "${RED}[!] AFFECTED${NC}:"
      echo "$HITS"
      LOCKFILE_FOUND=1
      while IFS= read -r line; do
        log_finding "Affected lockfile: $line"
      done <<< "$HITS"
    fi
  fi
done
if [ "$LOCKFILE_FOUND" -eq 0 ]; then
  echo -e "${GREEN}[OK] No affected lockfiles found${NC}"
fi
echo ""

# ── Summary ───────────────────────────────────────────────────
echo "========================================"
if [ "$COMPROMISED" -eq 1 ]; then
  echo -e "${RED}${BOLD}[RESULT] POTENTIAL COMPROMISE DETECTED${NC}"
  echo ""
  echo -e "${BOLD}Detected items:${NC}"
  echo -e "$FINDINGS"
  echo ""
  echo -e "${BOLD}Related IOC:${NC}"
  echo "  C2 domain  : sfrclak[.]com"
  echo "  C2 IP      : 142.11.206.73"
  echo "  C2 port    : 8000"
  echo "  Campaign ID: 6202033"
  echo ""
  echo "See README.md for remediation guidance."
else
  echo -e "${GREEN}${BOLD}[RESULT] CLEAN — No indicators of compromise found${NC}"
fi
echo "========================================"
