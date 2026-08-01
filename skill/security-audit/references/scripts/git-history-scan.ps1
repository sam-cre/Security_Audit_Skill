<#
.SYNOPSIS
    Git History Forensics Scanner for Security Audit Phase 0.
    Scans git commit history for accidentally committed secrets, credentials, and sensitive data.

.DESCRIPTION
    Attempts gitleaks first (preferred). Falls back to structured regex scanning of git log output.
    Output is appended to .security-audit/dependency-cve-report.md under "Committed Secrets History".

.PARAMETER ProjectRoot
    The root directory of the project being audited. Defaults to current directory.

.PARAMETER OutputFile
    Path to write results. Defaults to .security-audit/dependency-cve-report.md (append mode).
#>

param(
    [string]$ProjectRoot = ".",
    [string]$OutputFile = ".security-audit/dependency-cve-report.md"
)

$ErrorActionPreference = "Stop"
Set-Location $ProjectRoot

# --- High-entropy and secret pattern definitions ---
$SecretPatterns = @(
    @{ Name = "AWS Access Key";         Pattern = 'AKIA[0-9A-Z]{16}' }
    @{ Name = "AWS Secret Key";         Pattern = '(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}' }
    @{ Name = "Generic API Key";        Pattern = '(?i)(api[_-]?key|apikey)\s*[=:]\s*[''"\s]*[A-Za-z0-9_\-]{20,}' }
    @{ Name = "Generic Secret";         Pattern = '(?i)(secret|password|passwd|pwd)\s*[=:]\s*[''"\s]*[^\s''"]{8,}' }
    @{ Name = "Private Key Header";     Pattern = '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----' }
    @{ Name = "GitHub Token";           Pattern = '(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}' }
    @{ Name = "Slack Token";            Pattern = 'xox[bporas]-[0-9]{10,}-[A-Za-z0-9-]+' }
    @{ Name = "Generic Bearer Token";   Pattern = '(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}' }
    @{ Name = "Connection String";      Pattern = '(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s''"]+@[^\s''"]+' }
    @{ Name = "Hex-Encoded High Entropy"; Pattern = '(?i)(key|secret|token|password|credential|api_key)\s*[=:]\s*[''"]?[0-9a-fA-F]{40,}' }
    @{ Name = "Base64 JWT";             Pattern = 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' }
)

$findings = @()

# --- Redaction helper ---
# rules.md sec.8/9: record location and TYPE, never the value. Emit at most a
# 4-char identifying prefix plus the length so a reviewer can tell two hits apart
# WITHOUT the entropy body ever landing in an on-disk artifact. Given a raw
# matched token (or the line/fragment a scanner returns), this keeps only the
# leading 4 chars — enough to disambiguate, useless to an attacker.
function Get-RedactedSecret {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '<empty>' }
    $v = $Value.Trim()
    $len = $v.Length
    $prefix = $v.Substring(0, [Math]::Min(4, $len))
    return "${prefix}... [redacted, len=$len]"
}

# --- Attempt 1: Use gitleaks if available ---
function Try-Gitleaks {
    try {
        $version = & gitleaks version 2>&1
        if ($LASTEXITCODE -eq 0 -or $version -match '\d+\.\d+') {
            Write-Host "[+] gitleaks detected ($version). Running scan..."
            $reportPath = Join-Path $env:TEMP "gitleaks-report.json"
            & gitleaks detect --source . --report-path $reportPath --report-format json --no-banner 2>&1
            
            if (Test-Path $reportPath) {
                $report = Get-Content $reportPath -Raw | ConvertFrom-Json
                foreach ($leak in $report) {
                    $script:findings += [PSCustomObject]@{
                        Source    = "gitleaks"
                        Type     = $leak.RuleID
                        File     = $leak.File
                        Line     = $leak.StartLine
                        Commit   = $leak.Commit
                        Author   = $leak.Author
                        Date     = $leak.Date
                        # Prefer gitleaks' specific .Secret; fall back to .Match. Always redact.
                        Match    = (Get-RedactedSecret ($(if ($leak.Secret) { $leak.Secret } else { $leak.Match })))
                    }
                }
                Remove-Item $reportPath -Force
            }
            return $true
        }
    } catch {
        # gitleaks not found
    }
    return $false
}

# --- Attempt 2: Structured git log regex scan ---
function Run-GitLogScan {
    Write-Host "[*] gitleaks not found. Falling back to git log regex scan..."
    
    # Scan last 500 commits to avoid unbounded runtime
    $commitCount = 500
    $logOutput = & git log --all -p -n $commitCount --diff-filter=ACM --no-color 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[-] Not a git repository or git not available. Skipping history scan."
        return
    }
    
    $currentCommit = ""
    $currentFile = ""
    $lineNum = 0
    
    foreach ($line in $logOutput -split "`n") {
        if ($line -match '^commit ([0-9a-f]{40})') {
            $currentCommit = $Matches[1].Substring(0, 8)
        }
        if ($line -match '^diff --git a/.+ b/(.+)$') {
            $currentFile = $Matches[1]
            $lineNum = 0
        }
        if ($line -match '^\+') {
            $lineNum++
            foreach ($pat in $SecretPatterns) {
                if ($line -match $pat.Pattern) {
                    # Capture the matched token NOW — the false-positive skip check
                    # below runs another -match that would clobber $Matches.
                    $matchToken = $Matches[0]
                    # Avoid matching on common false positives
                    $skipPatterns = @('node_modules', 'vendor/', '.min.js', 'package-lock', 'yarn.lock', 'go.sum')
                    $skip = $false
                    foreach ($sp in $skipPatterns) {
                        if ($currentFile -match [regex]::Escape($sp)) { $skip = $true; break }
                    }
                    if (-not $skip) {
                        $script:findings += [PSCustomObject]@{
                            Source    = "regex-scan"
                            Type     = $pat.Name
                            File     = $currentFile
                            Line     = $lineNum
                            Commit   = $currentCommit
                            Author   = "unknown"
                            Date     = "unknown"
                            # Redact the matched token — never write the raw diff line.
                            Match    = (Get-RedactedSecret $matchToken)
                        }
                    }
                }
            }
        }
    }
}

# --- Execute scan ---
Write-Host "=== Git History Forensics Scanner ==="
Write-Host "Project: $ProjectRoot"
Write-Host ""

$usedGitleaks = Try-Gitleaks
if (-not $usedGitleaks) {
    Run-GitLogScan
}

# --- Output results ---
Write-Host ""
Write-Host "=== Results ==="
Write-Host "Potential secrets found: $($findings.Count)"

if ($findings.Count -gt 0) {
    # Deduplicate by file + type
    $deduped = $findings | Sort-Object File, Type -Unique
    
    $reportContent = @"

---

## Committed Secrets History (Git Forensics)

_Scanned via $(if ($usedGitleaks) { 'gitleaks' } else { 'git log regex fallback' }) on $(Get-Date -Format 'yyyy-MM-dd HH:mm')._

| # | Type | File | Line | Commit | Redacted Match |
|---|---|---|---|---|---|
"@
    
    $i = 1
    foreach ($f in $deduped) {
        $reportContent += "`n| $i | $($f.Type) | ``$($f.File)`` | $($f.Line) | ``$($f.Commit)`` | ``$($f.Match)`` |"
        $i++
    }
    
    $reportContent += @"

> [!WARNING]
> These secrets may still be recoverable from git history even if the files have been modified or deleted.
> Rotate all detected credentials immediately. Consider using `git filter-repo` to purge sensitive history,
> but coordinate with your team first — history rewriting affects all collaborators.
"@
    
    # Append to dependency CVE report
    if (Test-Path $OutputFile) {
        Add-Content -Path $OutputFile -Value $reportContent
        Write-Host "[+] Appended findings to $OutputFile"
    } else {
        Write-Host "[!] $OutputFile not found. Printing to console:"
        Write-Host $reportContent
    }
} else {
    Write-Host "[+] No secrets detected in git history."
}
