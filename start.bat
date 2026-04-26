@echo off
:: ─────────────────────────────────────────────────
:: OSINT Tool v3.0 — Quick Launch Script (Windows)
:: Double-click start.bat to launch
:: ─────────────────────────────────────────────────
cd /d "%~dp0"

if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
) else if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else (
    echo [!] No virtual environment found.
    echo     Run: python -m venv venv
    echo          venv\Scripts\activate
    echo          pip install -r requirements.txt
    pause
    exit /b 1
)

echo.
echo   OSINT Tool v3.0 - 35 Modules
echo   Web GUI: http://localhost:5000
echo.
python app.py
pause
