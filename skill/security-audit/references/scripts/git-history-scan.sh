#!/bin/bash
# =============================================================================
# Git History Forensics Scanner for Security Audit Phase 0
# Scans git commit history for accidentally committed secrets, credentials,
# and sensitive data.
#
# Attempts gitleaks first (preferred). Falls back to structured regex scanning
# of git log output.
#
# Usage:
#   chmod +x git-history-scan.sh
#   ./git-history-scan.sh [project-root] [output-file]
#
# Arguments:
#   project-root  - Root directory of the project being audited (default: .)
#   output-file   - Path to write results (default: .security-audit/dependency-cve-report.md)
# =============================================================================

set -euo pipefail

PROJECT_ROOT="${1:-.}"
OUTPUT_FILE="${2:-.security-audit/dependency-cve-report.md}"

cd "$PROJECT_ROOT"

# --- Secret pattern definitions ---
# Each entry: "PatternName:::RegexPattern"
SECRET_PATTERNS=(
    "AWS Access Key:::AKIA[0-9A-Z]{16}"
    "AWS Secret Key:::(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}"
    "Generic API Key:::(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"\s]*[A-Za-z0-9_\-]{20,}"
    "Generic Secret:::(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"\s]*[^\s'\"]{8,}"
    "Private Key Header:::-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    "GitHub Token:::(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"
    "Slack Token:::xox[bporas]-[0-9]{10,}-[A-Za-z0-9-]+"
    "Generic Bearer Token:::(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}"
    "Connection String:::(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s'\"]+@[^\s'\"]+"
    "Base64 JWT:::eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
)

# Skip patterns for false positive reduction
SKIP_PATTERNS="node_modules|vendor/|\.min\.js|package-lock|yarn\.lock|go\.sum"

FINDINGS=()
USED_GITLEAKS=false

# --- Redaction helper ---
# rules.md sec.8/9: record location and TYPE, never the value. Emit at most a
# 4-char identifying prefix plus the length so a reviewer can disambiguate hits
# WITHOUT the entropy body ever landing in an on-disk artifact.
redact_secret() {
    local v="$1"
    # trim surrounding whitespace
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    local len=${#v}
    if [[ $len -eq 0 ]]; then echo "<empty>"; return; fi
    echo "${v:0:4}... [redacted, len=${len}]"
}

# --- Attempt 1: Use gitleaks if available ---
try_gitleaks() {
    if command -v gitleaks &>/dev/null; then
        local version
        version=$(gitleaks version 2>&1 || true)
        if [[ "$version" =~ [0-9]+\.[0-9]+ ]]; then
            echo "[+] gitleaks detected ($version). Running scan..."
            local report_path
            report_path=$(mktemp /tmp/gitleaks-report-XXXXXX.json)

            gitleaks detect --source . --report-path "$report_path" --report-format json --no-banner 2>&1 || true

            if [[ -f "$report_path" && -s "$report_path" ]]; then
                # Parse gitleaks JSON output
                while IFS= read -r line; do
                    local rule_id file start_line commit author date match
                    rule_id=$(echo "$line" | jq -r '.RuleID // "unknown"')
                    file=$(echo "$line" | jq -r '.File // "unknown"')
                    start_line=$(echo "$line" | jq -r '.StartLine // 0')
                    commit=$(echo "$line" | jq -r '.Commit // "unknown"' | head -c 8)
                    author=$(echo "$line" | jq -r '.Author // "unknown"')
                    date=$(echo "$line" | jq -r '.Date // "unknown"')
                    # Prefer gitleaks' specific .Secret; fall back to .Match. Always redact.
                    match=$(redact_secret "$(echo "$line" | jq -r '.Secret // .Match // ""')")
                    FINDINGS+=("gitleaks|${rule_id}|${file}|${start_line}|${commit}|${match}")
                done < <(jq -c '.[]' "$report_path" 2>/dev/null)
            fi

            rm -f "$report_path"
            USED_GITLEAKS=true
            return 0
        fi
    fi
    return 1
}

# --- Attempt 2: Structured git log regex scan ---
run_git_log_scan() {
    echo "[*] gitleaks not found. Falling back to git log regex scan..."

    if ! git rev-parse --is-inside-work-tree &>/dev/null; then
        echo "[-] Not a git repository or git not available. Skipping history scan."
        return
    fi

    local commit_count=500
    local current_commit=""
    local current_file=""
    local line_num=0

    while IFS= read -r line; do
        if [[ "$line" =~ ^commit\ ([0-9a-f]{40}) ]]; then
            current_commit="${BASH_REMATCH[1]:0:8}"
        fi
        if [[ "$line" =~ ^diff\ --git\ a/.+\ b/(.+)$ ]]; then
            current_file="${BASH_REMATCH[1]}"
            line_num=0
        fi
        if [[ "$line" =~ ^\+ ]]; then
            ((line_num++)) || true

            # Skip known false positive paths
            if [[ "$current_file" =~ $SKIP_PATTERNS ]]; then
                continue
            fi

            for pattern_entry in "${SECRET_PATTERNS[@]}"; do
                local pat_name="${pattern_entry%%:::*}"
                local pat_regex="${pattern_entry##*:::}"

                # Extract ONLY the matched token (never the raw diff line) and redact it.
                match_token=$(echo "$line" | grep -oP "$pat_regex" 2>/dev/null | head -n1 || true)
                if [[ -n "$match_token" ]]; then
                    redacted=$(redact_secret "$match_token")
                    FINDINGS+=("regex-scan|${pat_name}|${current_file}|${line_num}|${current_commit}|${redacted}")
                fi
            done
        fi
    done < <(git log --all -p -n "$commit_count" --diff-filter=ACM --no-color 2>&1)
}

# --- Execute scan ---
echo "=== Git History Forensics Scanner ==="
echo "Project: $PROJECT_ROOT"
echo ""

if ! try_gitleaks; then
    run_git_log_scan
fi

# --- Output results ---
echo ""
echo "=== Results ==="
echo "Potential secrets found: ${#FINDINGS[@]}"

if [[ ${#FINDINGS[@]} -gt 0 ]]; then
    # Deduplicate by file + type
    declare -A seen
    DEDUPED=()
    for f in "${FINDINGS[@]}"; do
        IFS='|' read -r source type file line commit match <<< "$f"
        key="${file}|${type}"
        if [[ -z "${seen[$key]+x}" ]]; then
            seen[$key]=1
            DEDUPED+=("$f")
        fi
    done

    scanner_name="git log regex fallback"
    if $USED_GITLEAKS; then
        scanner_name="gitleaks"
    fi

    REPORT_CONTENT="
---

## Committed Secrets History (Git Forensics)

_Scanned via ${scanner_name} on $(date '+%Y-%m-%d %H:%M')._

| # | Type | File | Line | Commit | Redacted Match |
|---|---|---|---|---|---|"

    i=1
    for f in "${DEDUPED[@]}"; do
        IFS='|' read -r source type file line commit match <<< "$f"
        REPORT_CONTENT="${REPORT_CONTENT}
| ${i} | ${type} | \`${file}\` | ${line} | \`${commit}\` | \`${match}\` |"
        ((i++)) || true
    done

    REPORT_CONTENT="${REPORT_CONTENT}

> [!WARNING]
> These secrets may still be recoverable from git history even if the files have been modified or deleted.
> Rotate all detected credentials immediately. Consider using \`git filter-repo\` to purge sensitive history,
> but coordinate with your team first — history rewriting affects all collaborators."

    if [[ -f "$OUTPUT_FILE" ]]; then
        echo "$REPORT_CONTENT" >> "$OUTPUT_FILE"
        echo "[+] Appended findings to $OUTPUT_FILE"
    else
        echo "[!] $OUTPUT_FILE not found. Printing to console:"
        echo "$REPORT_CONTENT"
    fi
else
    echo "[+] No secrets detected in git history."
fi
