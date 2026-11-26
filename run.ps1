# ForensicShield AI - PowerShell Launcher (Project 218)
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "          ForensicShield AI - Project 218 PowerShell Launcher" -ForegroundColor White
Write-Host "  Anti-forensic Technique Detection via Natural Language Processing" -ForegroundColor Gray
Write-Host "======================================================================" -ForegroundColor Cyan

# Detect Python
$pythonCmd = "python"
if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    if (Get-Command "py" -ErrorAction SilentlyContinue) {
        $pythonCmd = "py"
    } else {
        Write-Host "`n[ERROR] Python is not installed or not on your system PATH." -ForegroundColor Red
        Write-Host "Please install Python 3.10+ from https://www.python.org/ with 'Add Python to PATH'." -ForegroundColor Yellow
        Read-Host "`nPress Enter to exit..."
        exit 1
    }
}

if (Test-Path ".venv\Scripts\python.exe") {
    $pythonCmd = ".venv\Scripts\python.exe"
    Write-Host "[INFO] Using virtual environment Python: $pythonCmd" -ForegroundColor Green
}

try {
    & $pythonCmd run.py
} catch {
    Write-Host "`n[ERROR] An error occurred during execution: $_" -ForegroundColor Red
    Read-Host "`nPress Enter to exit..."
}
