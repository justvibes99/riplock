#!/bin/bash
# Config file supply chain checker for Claude Code.
# Runs as a PostToolUse hook on Write|Edit — blocks if config files
# introduce supply chain risks (unpinned MCP servers, * deps, etc.).
#
# Install as a PostToolUse hook on Write|Edit in .claude/settings.json:
# {
#   "hooks": {
#     "PostToolUse": [{
#       "matcher": "Write|Edit",
#       "hooks": [{
#         "type": "command",
#         "command": "/path/to/check-supply-chain.sh",
#         "timeout": 10,
#         "statusMessage": "Checking for supply chain risks..."
#       }]
#     }]
#   }
# }

set -euo pipefail

INPUT=$(cat)
FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_response.filePath // empty')

[ -z "$FILE" ] && exit 0

BASENAME=$(basename "$FILE")

# Only check dependency and MCP config files
case "$BASENAME" in
  package.json|requirements.txt|pyproject.toml|Pipfile|.claude.json|.mcp.json|mcp.json|settings.json) ;;
  *) exit 0 ;;
esac

[ ! -f "$FILE" ] && exit 0

WARNINGS=""

# 1. npx -y or uvx without version pins in MCP configs
if grep -qE '"npx"' "$FILE" 2>/dev/null; then
  if grep -qE '"-y"' "$FILE" && grep -E '"@?[a-zA-Z]' "$FILE" | grep -qvE '@[0-9]'; then
    MATCH=$(grep -nE '"(-y|npx)"' "$FILE" | head -3)
    WARNINGS="${WARNINGS}\n[SUPPLY CHAIN] npx -y without version pin in MCP/config:\n${MATCH}\n"
  fi
fi
if grep -qE '"uvx"' "$FILE" 2>/dev/null; then
  if grep -E '"[a-zA-Z]' "$FILE" | grep -qvE '(@[0-9]|==)'; then
    MATCH=$(grep -nE '"uvx"' "$FILE" | head -3)
    WARNINGS="${WARNINGS}\n[SUPPLY CHAIN] uvx without version pin in MCP/config:\n${MATCH}\n"
  fi
fi
# Inline command strings
if grep -qE 'npx\s+-y\s+\S+' "$FILE" 2>/dev/null; then
  if grep -E 'npx\s+-y\s+\S+' "$FILE" | grep -qvE '@[0-9]'; then
    MATCH=$(grep -nE 'npx\s+-y\s+\S+' "$FILE" | grep -vE '@[0-9]' | head -3)
    WARNINGS="${WARNINGS}\n[SUPPLY CHAIN] npx -y without version pin:\n${MATCH}\n"
  fi
fi

# 2. npm "*" or "latest" version specs
if [[ "$BASENAME" == "package.json" ]]; then
  if grep -qE ':\s*"\s*(\*|latest)\s*"' "$FILE" 2>/dev/null; then
    MATCH=$(grep -nE ':\s*"\s*(\*|latest)\s*"' "$FILE" | head -5)
    WARNINGS="${WARNINGS}\n[SUPPLY CHAIN] npm dependency using * or latest:\n${MATCH}\n"
  fi
fi

# 3. postinstall/preinstall scripts
if [[ "$BASENAME" == "package.json" ]]; then
  if grep -qE '"(postinstall|preinstall|install)"' "$FILE" 2>/dev/null; then
    MATCH=$(grep -nE '"(postinstall|preinstall|install)"' "$FILE" | head -3)
    WARNINGS="${WARNINGS}\n[SUPPLY CHAIN] Install hook scripts detected:\n${MATCH}\n"
  fi
fi

if [ -n "$WARNINGS" ]; then
  echo -e "$WARNINGS" >&2
  echo "{\"decision\":\"block\",\"reason\":\"Supply chain risk detected in ${BASENAME}. Review the warnings above.\"}"
  exit 0
fi

exit 0
