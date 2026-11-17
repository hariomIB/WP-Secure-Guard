# WP Secure Guard Packaging Script
# Uses PHP ZipArchive to ensure standard forward slashes (/) required by WordPress and ZIP specifications

Write-Host "Packaging WP Secure Guard using PHP ZipArchive..." -ForegroundColor Cyan

& php (Join-Path $PSScriptRoot "build-zip.php")
