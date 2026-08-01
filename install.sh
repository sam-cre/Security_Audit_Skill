#!/usr/bin/env bash
# Installs the security-audit skill into ~/.claude/skills so it is available
# in every project, in Claude Code and in the Claude desktop app.
#
#   ./install.sh          copy (default, safe everywhere)
#   ./install.sh --link   symlink, so repo edits take effect immediately
#   ./install.sh --force  replace an existing install without prompting

set -euo pipefail

LINK=0
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --link)  LINK=1 ;;
    --force) FORCE=1 ;;
    -h|--help)
      sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$REPO_ROOT/skill/security-audit"
SKILLS_DIR="$HOME/.claude/skills"
TARGET="$SKILLS_DIR/security-audit"

printf '\nSecurity Audit Skill - installer\n\n'

# --- Validate source -------------------------------------------------------
if [ ! -d "$SOURCE" ]; then
  echo "ERROR: source not found at $SOURCE" >&2
  echo "Run this script from the repository root." >&2
  exit 1
fi
if [ ! -f "$SOURCE/SKILL.md" ]; then
  echo "ERROR: SKILL.md missing from $SOURCE" >&2
  exit 1
fi

# --- Handle existing install ----------------------------------------------
if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
  if [ "$FORCE" -ne 1 ]; then
    kind="directory"; [ -L "$TARGET" ] && kind="symlink"
    echo "An installation already exists ($kind):"
    echo "  $TARGET"
    printf 'Replace it? [y/N] '
    read -r reply
    case "$reply" in
      [Yy]*) ;;
      *) echo "Cancelled. Nothing changed."; exit 0 ;;
    esac
  fi
  # Remove the link itself, never what it points at.
  if [ -L "$TARGET" ]; then rm "$TARGET"; else rm -rf "$TARGET"; fi
  echo "Removed previous installation."
fi

mkdir -p "$SKILLS_DIR"

# --- Install ---------------------------------------------------------------
if [ "$LINK" -eq 1 ]; then
  ln -s "$SOURCE" "$TARGET"
  MODE="symlinked"
else
  cp -R "$SOURCE" "$TARGET"
  MODE="copied"
fi

# --- Verify ----------------------------------------------------------------
MISSING=0
for f in \
  "SKILL.md" \
  "references/rules.md" \
  "references/phases/phase-0-recon.md" \
  "references/phases/phase-8-hardening.md" \
  "references/domains/web-api.md" \
  "references/domains/auth-identity.md" \
  "references/setup/tool-install.md"
do
  if [ ! -f "$TARGET/$f" ]; then
    echo "ERROR: missing $f" >&2
    MISSING=1
  fi
done
[ "$MISSING" -eq 0 ] || { echo "Installation incomplete." >&2; exit 1; }

FILE_COUNT=$(find "$TARGET" -type f | wc -l | tr -d ' ')
DOMAIN_COUNT=$(find "$TARGET/references/domains" -type f | wc -l | tr -d ' ')
PHASE_COUNT=$(find "$TARGET/references/phases" -type f | wc -l | tr -d ' ')

cat <<EOF

Installed ($MODE).
  Location : $TARGET
  Files    : $FILE_COUNT  ($PHASE_COUNT phases, $DOMAIN_COUNT domain guides)

Usage - from any project directory:
  /security-audit             full audit (standard)
  /security-audit quick       fast read-only triage
  /security-audit deep        + CI/CD guardrails + guided hardening
  /security-audit setup       install security scanners
  /security-audit diff        re-audit only what changed

It also triggers on plain requests such as "audit this project for
vulnerabilities" or "review my auth flow".

Restart Claude Code or the Claude desktop app to pick it up.

EOF
