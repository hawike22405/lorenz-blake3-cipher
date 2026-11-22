# One-command installer for lrz (Lorenz-BLAKE3 cipher CLI) on Windows
# Usage: irm https://raw.githubusercontent.com/hawike22405/lorenz-blake3-cipher/master/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo  = "hawike22405/lorenz-blake3-cipher"
$Asset = "lrz-windows-x86_64.exe"
$Dir   = Join-Path $env:LOCALAPPDATA "lrz"
$Exe   = Join-Path $Dir "lrz.exe"

New-Item -ItemType Directory -Force -Path $Dir | Out-Null

$Url = "https://github.com/$Repo/releases/latest/download/$Asset"
Write-Host "Downloading $Url"
Invoke-WebRequest -Uri $Url -OutFile $Exe

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($UserPath -split ";") -notcontains $Dir) {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$Dir", "User")
    Write-Host "Added $Dir to your PATH. Open a new terminal to use it."
}

Write-Host "Installed. Try: lrz --help"
