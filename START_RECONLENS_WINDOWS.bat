@echo off
setlocal
cd /d "%~dp0"
echo.
echo ============================================
echo  ReconLens - Windows Local Security Test
echo ============================================
echo.
where py >nul 2>nul
if %errorlevel%==0 (
  set "PY=py -3"
) else (
  set "PY=python"
)
echo Preparing local environment...
%PY% prepare_local_env.py
if errorlevel 1 goto :failed
if not exist ".venv\Scripts\python.exe" (
  echo [1/4] Creating virtual environment...
  %PY% -m venv .venv
  if errorlevel 1 goto :failed
)
echo [2/4] Installing dependencies (internet needed the first time)...
".venv\Scripts\python.exe" -m pip install -r requirements-dev.txt
if errorlevel 1 goto :failed
echo [3/4] Checking admin account...
".venv\Scripts\python.exe" -m flask --app app:create_app check-local-admin
if errorlevel 1 goto :failed
echo.
echo [4/4] Starting ReconLens at http://127.0.0.1:5000/login
echo Press Ctrl+C to stop the server.
".venv\Scripts\python.exe" app.py
pause
exit /b 0
:failed
echo.
echo Setup failed. Copy the error above when asking for help.
pause
exit /b 1
