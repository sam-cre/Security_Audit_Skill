<#
.SYNOPSIS
    Security Audit Pre-Flight Environment Bootstrapper (Windows/PowerShell)
    Checks for all recommended security scanning tools and optionally installs missing ones.

.DESCRIPTION
    Scans the local environment for security tools needed by the security-audit skill.
    Reports what's installed, what's missing, and offers to install missing tools.

.PARAMETER AutoInstall
    If set, automatically installs missing tools without prompting (requires admin for some tools).

.PARAMETER ReportOnly
    If set, only generates a readiness report without offering installation.
#>

param(
    [switch]$AutoInstall,
    [switch]$ReportOnly
)

$ErrorActionPreference = "Continue"

# --- Tool definitions ---
$Tools = @(
    @{ Name = "semgrep";     Category = "SAST";    CheckCmd = "semgrep --version";     InstallCmd = "pip install semgrep";                   PackageManager = "pip" }
    @{ Name = "bandit";      Category = "SAST";    CheckCmd = "bandit --version";      InstallCmd = "pip install bandit";                    PackageManager = "pip" }
    @{ Name = "eslint";      Category = "SAST";    CheckCmd = "eslint --version";      InstallCmd = "npm install -g eslint";                 PackageManager = "npm" }
    @{ Name = "trivy";       Category = "SCA";     CheckCmd = "trivy --version";       InstallCmd = "scoop install trivy";                   PackageManager = "scoop" }
    @{ Name = "pip-audit";   Category = "SCA";     CheckCmd = "pip-audit --version";   InstallCmd = "pip install pip-audit";                 PackageManager = "pip" }
    @{ Name = "osv-scanner"; Category = "SCA";     CheckCmd = "osv-scanner --version"; InstallCmd = "scoop install osv-scanner";             PackageManager = "scoop" }
    @{ Name = "gitleaks";    Category = "Secrets";  CheckCmd = "gitleaks version";      InstallCmd = "scoop install gitleaks";                PackageManager = "scoop" }
    @{ Name = "checkov";     Category = "IaC";     CheckCmd = "checkov --version";     InstallCmd = "pip install checkov";                   PackageManager = "pip" }
    @{ Name = "nuclei";      Category = "DAST";    CheckCmd = "nuclei --version";      InstallCmd = "scoop install nuclei";                  PackageManager = "scoop" }
    @{ Name = "syft";        Category = "SBOM";    CheckCmd = "syft --version";        InstallCmd = "scoop install syft";                    PackageManager = "scoop" }
    @{ Name = "git";         Category = "Core";    CheckCmd = "git --version";         InstallCmd = "winget install --id Git.Git -e";        PackageManager = "winget" }
    @{ Name = "python";      Category = "Core";    CheckCmd = "python --version";      InstallCmd = "winget install --id Python.Python.3 -e"; PackageManager = "winget" }
    @{ Name = "node";        Category = "Core";    CheckCmd = "node --version";        InstallCmd = "winget install --id OpenJS.NodeJS -e";  PackageManager = "winget" }
)

# --- Check package managers ---
Write-Host "=== Security Audit Pre-Flight Bootstrapper ===" -ForegroundColor Cyan
Write-Host ""

$hasPip = $null -ne (Get-Command pip -ErrorAction SilentlyContinue)
$hasNpm = $null -ne (Get-Command npm -ErrorAction SilentlyContinue)
$hasScoop = $null -ne (Get-Command scoop -ErrorAction SilentlyContinue)
$hasWinget = $null -ne (Get-Command winget -ErrorAction SilentlyContinue)

Write-Host "Package Managers:" -ForegroundColor Yellow
Write-Host "  pip:    $(if ($hasPip) { 'Available' } else { 'NOT FOUND' })"
Write-Host "  npm:    $(if ($hasNpm) { 'Available' } else { 'NOT FOUND' })"
Write-Host "  scoop:  $(if ($hasScoop) { 'Available' } else { 'NOT FOUND' })"
Write-Host "  winget: $(if ($hasWinget) { 'Available' } else { 'NOT FOUND' })"
Write-Host ""

# --- Scan tools ---
$installed = @()
$missing = @()

foreach ($tool in $Tools) {
    try {
        $result = Invoke-Expression $tool.CheckCmd 2>&1
        if ($LASTEXITCODE -eq 0 -or $result -match '\d+\.\d+') {
            $version = ($result | Select-Object -First 1) -replace '[^0-9\.]', '' | ForEach-Object { $_.Trim() }
            $installed += [PSCustomObject]@{
                Name     = $tool.Name
                Category = $tool.Category
                Version  = $version
                Status   = "Installed"
            }
        } else {
            throw "Not found"
        }
    } catch {
        $missing += $tool
    }
}

# --- Report ---
Write-Host "=== Readiness Report ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "INSTALLED ($($installed.Count)):" -ForegroundColor Green
foreach ($t in $installed) {
    Write-Host "  [OK] $($t.Name) ($($t.Category)) — v$($t.Version)"
}

Write-Host ""
if ($missing.Count -gt 0) {
    Write-Host "MISSING ($($missing.Count)):" -ForegroundColor Red
    foreach ($t in $missing) {
        Write-Host "  [!!] $($t.Name) ($($t.Category)) — Install: $($t.InstallCmd)"
    }
} else {
    Write-Host "All tools are installed! Environment is ready for security audit." -ForegroundColor Green
}

# --- Install missing (if requested) ---
if (-not $ReportOnly -and $missing.Count -gt 0) {
    Write-Host ""

    if (-not $AutoInstall) {
        $response = Read-Host "Would you like to install missing tools? (Y/n)"
        if ($response -eq 'n' -or $response -eq 'N') {
            Write-Host "Skipping installation. You can install manually using the commands above."
            exit 0
        }
    }

    foreach ($tool in $missing) {
        # Check if the required package manager is available
        $pmAvailable = switch ($tool.PackageManager) {
            "pip"    { $hasPip }
            "npm"    { $hasNpm }
            "scoop"  { $hasScoop }
            "winget" { $hasWinget }
            default  { $false }
        }

        if ($pmAvailable) {
            Write-Host ""
            Write-Host "Installing $($tool.Name) via $($tool.PackageManager)..." -ForegroundColor Yellow
            try {
                Invoke-Expression $tool.InstallCmd
                Write-Host "  [OK] $($tool.Name) installed successfully." -ForegroundColor Green
            } catch {
                Write-Host "  [FAIL] Failed to install $($tool.Name): $_" -ForegroundColor Red
            }
        } else {
            Write-Host "  [SKIP] Cannot install $($tool.Name) — $($tool.PackageManager) is not available." -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host "=== Pre-Flight Complete ===" -ForegroundColor Cyan
