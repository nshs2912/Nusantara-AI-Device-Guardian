$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw "Python virtual environment not found. Create .venv with Python 3.11 first."
}

& $Python -m pip install --upgrade pyinstaller

& $Python -m PyInstaller --noconfirm --clean --name "Nusantara-AI-Device-Guardian" --onedir --windowed --collect-all streamlit --collect-all altair --collect-all pydeck --collect-all watchdog --add-data "app.py;." --add-data "src;src" "packaging\windows_launcher.py"

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed."
}

Write-Host ""
Write-Host "Build complete:"
Write-Host (Join-Path $Root "dist\Nusantara-AI-Device-Guardian")
