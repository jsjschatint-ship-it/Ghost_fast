#requires -Version 5.0
# Cross-platform build: windows/mac/linux x amd64/arm64
# Output:    dist/ghost_<os>_<arch>[.exe]
# Checksums: dist/SHA256SUMS.txt
#
# Usage:
#   .\scripts\build-all.ps1
#   .\scripts\build-all.ps1 -Version v0.1.0
#   .\scripts\build-all.ps1 -Filter linux        # only linux targets
#   .\scripts\build-all.ps1 -Filter darwin
#   .\scripts\build-all.ps1 -Filter windows

[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$OutDir  = "dist",
    [ValidateSet("", "windows", "darwin", "linux")]
    [string]$Filter  = ""
)

$ErrorActionPreference = "Stop"

# Resolve metadata. Don't let "no git history" errors abort the whole script:
# we just fall back to "dev"/"unknown" when git refuses to answer.
function Try-Git([string]$ArgsLine) {
    try {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $out = & cmd /c "git $ArgsLine 2>NUL"
        $ErrorActionPreference = $prev
        if ($LASTEXITCODE -ne 0) { return "" }
        return ($out -join "").Trim()
    } catch {
        return ""
    }
}
if (-not $Version) {
    $v = Try-Git "describe --tags --always --dirty"
    if (-not $v) { $v = "dev" }
    $Version = $v
}
$buildTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$commit = Try-Git "rev-parse --short HEAD"
if (-not $commit) { $commit = "unknown" }

# Target matrix
$matrix = @(
    @{ os = "windows"; arch = "amd64"; ext = ".exe" },
    @{ os = "windows"; arch = "arm64"; ext = ".exe" },
    @{ os = "darwin";  arch = "amd64"; ext = ""     },
    @{ os = "darwin";  arch = "arm64"; ext = ""     },
    @{ os = "linux";   arch = "amd64"; ext = ""     },
    @{ os = "linux";   arch = "arm64"; ext = ""     }
)
if ($Filter) {
    $matrix = $matrix | Where-Object { $_.os -eq $Filter }
}

# Prepare output dir
if (Test-Path $OutDir) {
    Remove-Item -Recurse -Force "$OutDir\*" -ErrorAction SilentlyContinue
} else {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}

Write-Host "===== Build =====" -ForegroundColor Cyan
Write-Host "Version:   $Version"
Write-Host "Commit:    $commit"
Write-Host "BuildTime: $buildTime"
Write-Host "OutDir:    $OutDir"
Write-Host "Targets:   $($matrix.Count)"
Write-Host ""

$ldflags = "-s -w -X main.Version=$Version -X main.Commit=$commit -X main.BuildTime=$buildTime"
$env:CGO_ENABLED = "0"

$results = @()
foreach ($t in $matrix) {
    $os   = $t.os
    $arch = $t.arch
    $ext  = $t.ext
    $name = "ghost_${os}_${arch}${ext}"
    $path = Join-Path $OutDir $name

    Write-Host "[*] $os/$arch -> $name" -ForegroundColor Yellow
    $env:GOOS = $os
    $env:GOARCH = $arch

    $sw = [Diagnostics.Stopwatch]::StartNew()
    & go build -trimpath -ldflags "$ldflags" -o $path .\cmd\enscan
    $exit = $LASTEXITCODE
    $sw.Stop()

    if ($exit -ne 0) {
        Write-Host "    FAIL (exit $exit)" -ForegroundColor Red
        $results += [pscustomobject]@{ Target = "$os/$arch"; Status = "FAIL"; Size = 0; Sec = [int]$sw.Elapsed.TotalSeconds }
        continue
    }
    $sz = (Get-Item $path).Length
    $mb = [math]::Round($sz / 1MB, 2)
    Write-Host "    OK  $mb MB ($([int]$sw.Elapsed.TotalSeconds)s)" -ForegroundColor Green
    $results += [pscustomobject]@{ Target = "$os/$arch"; Status = "OK"; Size = $sz; Sec = [int]$sw.Elapsed.TotalSeconds }
}

Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "===== Summary =====" -ForegroundColor Cyan
$results | Format-Table -AutoSize

# Generate SHA256SUMS.txt
$shaFile = Join-Path $OutDir "SHA256SUMS.txt"
$lines = @()
Get-ChildItem $OutDir -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    $lines += "$hash  $($_.Name)"
}
Set-Content -Encoding ASCII -Path $shaFile -Value $lines
Write-Host "Wrote $shaFile" -ForegroundColor Cyan

$failCount = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
if ($failCount -gt 0) {
    Write-Host "$failCount target(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "All builds OK" -ForegroundColor Green
