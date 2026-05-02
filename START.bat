@echo off
setlocal

echo.
echo ====================================================
echo   Locked Firewall Rule Reviewer
echo ====================================================
echo.

:: ── Backend ────────────────────────────────────────────────────
echo [Backend] Starting FastAPI ...

if not exist ".env" (
    copy .env.example .env
    echo    Created .env from .env.example
)

if "%PORT%"=="" set "PORT=8000"
if "%VITE_PORT%"=="" set "VITE_PORT=5173"
set "VITE_API_URL=http://127.0.0.1:%PORT%"

:: Check for python/pip
set "PY_CMD="
python --version >nul 2>&1
if not errorlevel 1 (
    set "PY_CMD=python"
) else (
    py -3 --version >nul 2>&1
    if not errorlevel 1 set "PY_CMD=py -3"
)

if not defined PY_CMD (
    echo    Error: Python not found. Please install Python 3.10+ and add to PATH.
    pause
    exit /b 1
)

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" --version >nul 2>&1
    if errorlevel 1 (
        echo    Existing virtual environment is invalid. Recreating it...
        rmdir /s /q ".venv"
    )
)

if not exist ".venv\Scripts\python.exe" (
    echo    Creating virtual environment...
    %PY_CMD% -m venv .venv
)

call .venv\Scripts\activate.bat

echo    Installing Python dependencies...
pip install -r requirements.txt --quiet --disable-pip-version-check

start "Firewall Backend" cmd /k "python main.py"

:: Wait a bit for backend
timeout /t 5 >nul

:: ── Frontend ───────────────────────────────────────────────────
echo.
echo [Frontend] Starting React on http://localhost:%VITE_PORT% ...
cd fortress-lens-main

if not exist "node_modules" (
    echo    Installing Node dependencies...
    call npm install --silent
)

start "Firewall Frontend" cmd /k "npm run dev"

:: ── Done ───────────────────────────────────────────────────────
echo.
echo ====================================================
echo   Both services are starting...
echo.
echo   Frontend  -  http://localhost:%VITE_PORT%
echo   Backend   -  http://127.0.0.1:%PORT%
echo   API Docs  -  http://127.0.0.1:%PORT%/docs
echo.
echo   Close the opened command windows to stop services.
echo ====================================================
echo.
pause
