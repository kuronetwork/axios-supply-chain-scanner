#!/bin/bash
# axios-supply-chain-scanner — macOS (detection only)
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
echo " axios supply chain scanner — macOS"
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
echo "=== 3. Full disk scan — plain-crypto-js directories ==="
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

# ── 5. RAT artifact: /Library/Caches/com.apple.act.mond ──────
echo "=== 5. RAT artifact — /Library/Caches/com.apple.act.mond ==="
if [ -f "/Library/Caches/com.apple.act.mond" ]; then
  echo -e "${RED}[!!!] COMPROMISED${NC}"
  ls -la "/Library/Caches/com.apple.act.mond"
  log_finding "macOS RAT binary: /Library/Caches/com.apple.act.mond"
else
  echo -e "${GREEN}[OK] Clean${NC}"
fi
echo ""

# ── 6. RAT artifact: staging directory ────────────────────────
echo "=== 6. RAT staging — \$TMPDIR/6202033 ==="
STAGING="${TMPDIR:-/tmp}/6202033"
if [ -e "$STAGING" ]; then
  echo -e "${RED}[!!!] COMPROMISED${NC}"
  ls -la "$STAGING"
  log_finding "RAT staging: $STAGING"
else
  echo -e "${GREEN}[OK] Clean${NC}"
fi
echo ""

# ── 7. Hidden RAT payloads in /private/tmp ────────────────────
echo "=== 7. Hidden RAT payloads — /private/tmp/.* ==="
HIDDEN=$(find /private/tmp -maxdepth 1 -name ".*" -type f -newer /private/tmp 2>/dev/null | head -20 || true)
if [ -n "$HIDDEN" ]; then
  echo -e "${YELLOW}[?] Suspicious hidden files:${NC}"
  echo "$HIDDEN"
  log_finding "Suspicious hidden files in /private/tmp (review manually)"
else
  echo -e "${GREEN}[OK] Clean${NC}"
fi
echo ""

# ── 8. Persistence check: launchctl ───────────────────────────
echo "=== 8. Persistence — launchctl ==="
LAUNCHCTL_HIT=$(launchctl list 2>/dev/null | grep -i "apple\.act" || true)
if [ -n "$LAUNCHCTL_HIT" ]; then
  echo -e "${RED}[!!!] COMPROMISED${NC}"
  echo "$LAUNCHCTL_HIT"
  log_finding "Suspicious launchd service: $LAUNCHCTL_HIT"
else
  echo -e "${GREEN}[OK] Clean${NC}"
fi
echo ""

# ── 9. Network: C2 domain resolution ─────────────────────────
echo "=== 9. Network — C2 domain check ==="
if host sfrclak.com >/dev/null 2>&1; then
  C2_IP=$(host sfrclak.com 2>/dev/null | grep "has address" | head -1 || true)
  echo -e "${YELLOW}[!] WARNING${NC}: C2 domain sfrclak.com resolves — ${C2_IP}"
  log_finding "C2 domain resolves: $C2_IP"
else
  echo -e "${GREEN}[OK] C2 domain does not resolve${NC}"
fi
echo ""

# ── 10. Project lockfile scan ─────────────────────────────────
echo "=== 10. Project lockfile scan ==="
LOCKFILE_FOUND=0
for DIR in "$HOME/Projects" "$HOME/Documents" "$HOME/Desktop" "$HOME/repos" "$HOME/dev" "$HOME/src" "$HOME/work"; do
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
