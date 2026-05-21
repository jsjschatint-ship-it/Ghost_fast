#requires -Version 5.0
# Secure push to a private GitHub repo.
# - PAT is entered as SecureString (no echo, no shell history, no git config).
# - Credential is stored only in git's in-memory cache (5 min) and cleaned up.
#
# Usage:
#   .\scripts\push-to-github.ps1
#   .\scripts\push-to-github.ps1 -Repo Ghsot
#   .\scripts\push-to-github.ps1 -Tag v0.1.0

[CmdletBinding()]
param(
    [string]$Owner = "hquip",
    [string]$Repo  = "Ghost",
    [string]$Tag   = ""
)

$ErrorActionPreference = "Stop"

Write-Host "===== Push to GitHub private repo =====" -ForegroundColor Cyan
Write-Host ("Target: https://github.com/{0}/{1}.git" -f $Owner, $Repo)
Write-Host ""

# Step 1: probe whether the repo URL resolves anonymously
Write-Host "[1/4] Probing repo visibility..." -ForegroundColor Yellow
$probeUrl = "https://github.com/$Owner/$Repo"
try {
    $resp = Invoke-WebRequest -Uri $probeUrl -UseBasicParsing -MaximumRedirection 0 -ErrorAction Stop
    Write-Host ("    Public (HTTP {0}). PAT still used for auth." -f $resp.StatusCode) -ForegroundColor Green
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 404) {
        Write-Host "    HTTP 404 to anonymous request -- private repo expected, continuing." -ForegroundColor DarkYellow
    } else {
        Write-Host ("    Probe HTTP {0} -- continuing anyway." -f $code) -ForegroundColor DarkYellow
    }
}

# Step 2: set the local remote URL
Write-Host ""
Write-Host "[2/4] Setting remote URL..." -ForegroundColor Yellow
$remoteUrl = "https://github.com/$Owner/$Repo.git"
& git remote set-url origin $remoteUrl
& git remote -v | Select-String origin

# Step 3: prompt for PAT (hidden input)
Write-Host ""
Write-Host "[3/4] PAT input" -ForegroundColor Yellow
Write-Host "  Paste your GitHub PAT (input will NOT be echoed)."
Write-Host "  No PAT yet?  https://github.com/settings/tokens/new  --  scope 'repo'"
$secure = Read-Host "  PAT" -AsSecureString
$bstr   = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
$pat    = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

if (-not $pat) {
    Write-Host "    PAT empty, aborting." -ForegroundColor Red
    exit 1
}

# Step 4: push using a transient credential cache
Write-Host ""
Write-Host "[4/4] Pushing main..." -ForegroundColor Yellow

# 5-minute in-memory cache (no disk write)
& git config --local credential.helper "cache --timeout=300" | Out-Null

# Inject PAT into the cache via `git credential approve`
$inject = "protocol=https`nhost=github.com`nusername=$Owner`npassword=$pat`n`n"
$inject | & git credential approve

# Push main
& git push -u origin main
$pushExit = $LASTEXITCODE

# Optional: push tag to trigger CI release workflow
$tagExit = 0
if ($Tag -and $pushExit -eq 0) {
    Write-Host ""
    Write-Host ("    Creating tag {0}..." -f $Tag) -ForegroundColor Yellow
    & git tag -a $Tag -m ("release " + $Tag) 2>$null
    & git push origin $Tag
    $tagExit = $LASTEXITCODE
}

# Cleanup: drop the credential helper config and zero out PAT in memory
& git config --local --unset credential.helper 2>$null
$pat = $null
[System.GC]::Collect()

Write-Host ""
if ($pushExit -ne 0) {
    Write-Host "[X] Push failed. Common causes:" -ForegroundColor Red
    Write-Host "    - Wrong repo name. Try: .\scripts\push-to-github.ps1 -Repo <actual_name>"
    Write-Host "    - PAT missing 'repo' scope or expired."
    Write-Host "    - You typed an account password instead of a PAT (passwords no longer work)."
    exit $pushExit
}

Write-Host "[OK] Main pushed." -ForegroundColor Green
Write-Host ("    Repo:     https://github.com/{0}/{1}" -f $Owner, $Repo)
if ($Tag) {
    if ($tagExit -eq 0) {
        Write-Host ("    Tag:      v{0}  (pushed)" -f $Tag.TrimStart('v'))
        Write-Host ("    Actions:  https://github.com/{0}/{1}/actions" -f $Owner, $Repo)
        Write-Host ("    Releases: https://github.com/{0}/{1}/releases  -- wait 3-5 min for CI" -f $Owner, $Repo)
    } else {
        Write-Host ("    Tag push FAILED (exit {0}). Main is up though." -f $tagExit) -ForegroundColor Red
    }
}
