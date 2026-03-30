#!/bin/bash
# Pre-install safety checker for Claude Code.
# Scans packages with `riplock scan-pkg` before allowing installation.
# Also blocks npx -y / uvx without version pins (no lockfile = pin required).
#
# Install as a PreToolUse hook on Bash in .claude/settings.json:
# {
#   "hooks": {
#     "PreToolUse": [{
#       "matcher": "Bash",
#       "hooks": [{
#         "type": "command",
#         "command": "/path/to/check-install-safety.sh",
#         "timeout": 60,
#         "statusMessage": "Scanning packages for malware..."
#       }]
#     }]
#   }
# }

set -euo pipefail

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

[ -z "$CMD" ] && exit 0

# ── Collect packages to scan ──────────────────────────────────────

PKGS=()
BLOCK_REASON=""

# npx -y without version pin → hard block (no lockfile for ephemeral runs)
if echo "$CMD" | grep -qE 'npx\s+-y\s+'; then
  UNPINNED=$(echo "$CMD" | grep -oE 'npx\s+-y\s+\S+' | awk '{print $NF}' | grep -vE '@[0-9]' || true)
  if [ -n "$UNPINNED" ]; then
    BLOCK_REASON="npx -y without version pin: ${UNPINNED}. Use @<version> to pin."
  fi
  # Collect all npx packages for scanning
  for PKG in $(echo "$CMD" | grep -oE 'npx\s+-y\s+\S+' | awk '{print $NF}'); do
    PKGS+=("$PKG")
  done
fi

# uvx without version pin → hard block (no lockfile)
if echo "$CMD" | grep -qE 'uvx\s+'; then
  UNPINNED=$(echo "$CMD" | grep -oE 'uvx\s+\S+' | awk '{print $NF}' | grep -vE '(@[0-9]|==)' || true)
  if [ -n "$UNPINNED" ]; then
    BLOCK_REASON="uvx without version pin: ${UNPINNED}. Use @<version> or ==<version> to pin."
  fi
  for PKG in $(echo "$CMD" | grep -oE 'uvx\s+\S+' | awk '{print $NF}'); do
    PKGS+=("pip:$PKG")
  done
fi

# npm install <packages> (skip bare "npm install" / "npm ci")
if echo "$CMD" | grep -qE 'npm\s+install\s+\S' && ! echo "$CMD" | grep -qE 'npm\s+(ci|install)\s*($|[;&|>])'; then
  for ARG in $(echo "$CMD" | perl -ne 'if (/npm\s+install\s+(.+)/) { print $1 }'); do
    [[ "$ARG" == -* ]] && continue
    PKGS+=("$ARG")
  done
fi

# pip install <packages> (skip -r requirements.txt)
if echo "$CMD" | grep -qE 'pip3?\s+install\s+' && ! echo "$CMD" | grep -qE 'pip3?\s+install\s+(-r|--requirement)\s'; then
  for ARG in $(echo "$CMD" | perl -ne 'if (/pip3?\s+install\s+(.+)/) { print $1 }'); do
    [[ "$ARG" == -* ]] && continue
    PKGS+=("pip:$ARG")
  done
fi

# ── Block on unpinned ephemeral commands ──────────────────────────

if [ -n "$BLOCK_REASON" ]; then
  echo "$BLOCK_REASON" >&2
  echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"${BLOCK_REASON}\"}}"
  exit 0
fi

# ── Scan packages with riplock ────────────────────────────────────

if [ ${#PKGS[@]} -eq 0 ]; then
  exit 0
fi

# Find riplock binary
RIPLOCK=$(command -v riplock 2>/dev/null || echo "npx riplock")

RESULT=$($RIPLOCK scan-pkg --json "${PKGS[@]}" 2>/dev/null) || true

if [ -z "$RESULT" ]; then
  exit 0
fi

# Check for critical/high findings
HAS_CRITICAL=$(echo "$RESULT" | jq -r '.stats.critical // 0' 2>/dev/null || echo "0")
HAS_HIGH=$(echo "$RESULT" | jq -r '.stats.high // 0' 2>/dev/null || echo "0")

if [ "$HAS_CRITICAL" -gt 0 ] 2>/dev/null; then
  FINDINGS=$(echo "$RESULT" | jq -r '.findings[] | "  \(.severity): \(.title) (\(.location.filePath // "unknown"))"' 2>/dev/null || echo "  (parse error)")
  echo -e "CRITICAL supply chain findings:\n${FINDINGS}" >&2
  echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"Malware scan found CRITICAL indicators. Review findings before installing.\"}}"
  exit 0
fi

if [ "$HAS_HIGH" -gt 0 ] 2>/dev/null; then
  FINDINGS=$(echo "$RESULT" | jq -r '.findings[] | "  \(.severity): \(.title) (\(.location.filePath // "unknown"))"' 2>/dev/null || echo "  (parse error)")
  echo -e "HIGH supply chain findings:\n${FINDINGS}" >&2
  echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"ask\",\"permissionDecisionReason\":\"Malware scan found suspicious patterns. Review findings.\"}}"
  exit 0
fi

exit 0
