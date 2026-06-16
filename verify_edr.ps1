#!/usr/bin/env pwsh
# verify_edr.ps1 — NetDash EXE signature and integrity verification

param([string]$ExePath = "dist\netdash.exe")

Write-Host "=== NetDash EXE Verification ===" -ForegroundColor Cyan

# Verify file exists
if (-not (Test-Path $ExePath)) {
    Write-Error "File not found: $ExePath"
    exit 1
}

# 1. Signature check
$sig = Get-AuthenticodeSignature $ExePath
Write-Host "`nSignature Status:" -ForegroundColor Green
Write-Host "  Status: $($sig.Status)"
$signerSubject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "No signer" }
Write-Host "  SignerCertificate: $signerSubject" -ForegroundColor $(if ($sig.Status -eq "Valid") { "Green" } else { "Yellow" })

# 2. File hash
$hash = (certutil -hashfile $ExePath SHA256)[1].Trim()
Write-Host "`nFile Hash (SHA256):" -ForegroundColor Green
Write-Host "  $hash"

# 3. File info
$file = Get-Item $ExePath
Write-Host "`nFile Info:" -ForegroundColor Green
Write-Host "  Path: $($file.FullName)"
Write-Host "  Size: $('{0:N0}' -f $file.Length) bytes"
Write-Host "  Modified: $($file.LastWriteTime)"

# 4. EDR/Security checks
Write-Host "`nSecurity Checks:" -ForegroundColor Green
# Try to get version info with absolute path
$absPath = (Resolve-Path $ExePath -ErrorAction SilentlyContinue).Path
if ($absPath) {
    $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($absPath)
    Write-Host "  ProductVersion: $($versionInfo.ProductVersion)"
    Write-Host "  FileVersion: $($versionInfo.FileVersion)"
    Write-Host "  CompanyName: $($versionInfo.CompanyName)"
}

Write-Host "`n✓ Verification Complete" -ForegroundColor Green
