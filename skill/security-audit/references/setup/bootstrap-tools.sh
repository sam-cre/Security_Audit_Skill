#!/bin/bash
# =============================================================================
# Security Audit Pre-Flight Environment Bootstrapper (macOS/Linux)
# Checks for all recommended security scanning tools and optionally installs
# missing ones.
#
# Usage:
#   chmod +x bootstrap-tools.sh
#   ./bootstrap-tools.sh              # Interactive mode
#   ./bootstrap-tools.sh --auto       # Auto-install missing tools
#   ./bootstrap-tools.sh --report     # Report only, no installation
# =============================================================================

set -euo pipefail

AUTO_INSTALL=false
REPORT_ONLY=false

for arg in "$@"; do
    case $arg in
        --auto)    AUTO_INSTALL=true ;;
        --report)  REPORT_ONLY=true ;;
        *)         echo "Usage: $0 [--auto|--report]"; exit 1 ;;
    esac
done

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=== Security Audit Pre-Flight Bootstrapper ===${NC}"
echo ""

# --- Detect OS and package manager ---
OS="unknown"
PKG_MGR="none"

if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
    if command -v brew &>/dev/null; then
        PKG_MGR="brew"
    fi
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
    fi
fi

HAS_PIP=$(command -v pip3 &>/dev/null || command -v pip &>/dev/null && echo true || echo false)
HAS_NPM=$(command -v npm &>/dev/null && echo true || echo false)
HAS_GO=$(command -v go &>/dev/null && echo true || echo false)

PIP_CMD="pip3"
command -v pip3 &>/dev/null || PIP_CMD="pip"

echo -e "${YELLOW}System: $OS | Package Manager: $PKG_MGR${NC}"
echo "  pip:  $(if $HAS_PIP; then echo 'Available'; else echo 'NOT FOUND'; fi)"
echo "  npm:  $(if $HAS_NPM; then echo 'Available'; else echo 'NOT FOUND'; fi)"
echo "  go:   $(if $HAS_GO; then echo 'Available'; else echo 'NOT FOUND'; fi)"
echo ""

# --- Tool definitions ---
# Format: name|category|check_command|install_brew|install_pip|install_npm
TOOLS=(
    "semgrep|SAST|semgrep --version|brew install semgrep|$PIP_CMD install semgrep|"
    "bandit|SAST|bandit --version||$PIP_CMD install bandit|"
    "eslint|SAST|eslint --version|||npm install -g eslint"
    "trivy|SCA|trivy --version|brew install trivy||"
    "pip-audit|SCA|pip-audit --version||$PIP_CMD install pip-audit|"
    "osv-scanner|SCA|osv-scanner --version|brew install osv-scanner||"
    "gitleaks|Secrets|gitleaks version|brew install gitleaks||"
    "checkov|IaC|checkov --version||$PIP_CMD install checkov|"
    "nuclei|DAST|nuclei --version|brew install nuclei||"
    "syft|SBOM|syft --version|brew install syft||"
    "git|Core|git --version|brew install git||"
)

INSTALLED=()
MISSING=()
MISSING_DETAILS=()

# --- Scan tools ---
for tool_entry in "${TOOLS[@]}"; do
    IFS='|' read -r name category check_cmd install_brew install_pip install_npm <<< "$tool_entry"

    if eval "$check_cmd" &>/dev/null; then
        version=$(eval "$check_cmd" 2>&1 | head -1 | grep -oP '\d+\.\d+[\.\d]*' | head -1 || echo "unknown")
        INSTALLED+=("$name ($category) — v$version")
    else
        MISSING+=("$name")

        # Determine best install command
        install_cmd=""
        if [[ -n "$install_brew" ]] && [[ "$PKG_MGR" == "brew" ]]; then
            install_cmd="$install_brew"
        elif [[ -n "$install_pip" ]] && $HAS_PIP; then
            install_cmd="$install_pip"
        elif [[ -n "$install_npm" ]] && $HAS_NPM; then
            install_cmd="$install_npm"
        fi

        MISSING_DETAILS+=("$name|$category|$install_cmd")
    fi
done

# --- Report ---
echo -e "${CYAN}=== Readiness Report ===${NC}"
echo ""
echo -e "${GREEN}INSTALLED (${#INSTALLED[@]}):${NC}"
for t in "${INSTALLED[@]}"; do
    echo "  [OK] $t"
done

echo ""
if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo -e "${RED}MISSING (${#MISSING[@]}):${NC}"
    for detail in "${MISSING_DETAILS[@]}"; do
        IFS='|' read -r name category install_cmd <<< "$detail"
        if [[ -n "$install_cmd" ]]; then
            echo "  [!!] $name ($category) — Install: $install_cmd"
        else
            echo "  [!!] $name ($category) — No automatic installer available for $OS"
        fi
    done
else
    echo -e "${GREEN}All tools are installed! Environment is ready for security audit.${NC}"
    exit 0
fi

# --- Install missing ---
if ! $REPORT_ONLY && [[ ${#MISSING[@]} -gt 0 ]]; then
    echo ""

    if ! $AUTO_INSTALL; then
        read -p "Would you like to install missing tools? (Y/n) " response
        if [[ "$response" == "n" || "$response" == "N" ]]; then
            echo "Skipping installation."
            exit 0
        fi
    fi

    for detail in "${MISSING_DETAILS[@]}"; do
        IFS='|' read -r name category install_cmd <<< "$detail"

        if [[ -n "$install_cmd" ]]; then
            echo ""
            echo -e "${YELLOW}Installing $name...${NC}"
            if eval "$install_cmd"; then
                echo -e "  ${GREEN}[OK] $name installed successfully.${NC}"
            else
                echo -e "  ${RED}[FAIL] Failed to install $name.${NC}"
            fi
        else
            echo -e "  ${YELLOW}[SKIP] Cannot auto-install $name on $OS.${NC}"
        fi
    done
fi

echo ""
echo -e "${CYAN}=== Pre-Flight Complete ===${NC}"
