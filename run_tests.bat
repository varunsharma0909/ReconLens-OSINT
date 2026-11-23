@echo off
REM ------------------------------------------------------------
REM  Run the automated test suite (no internet needed)
REM ------------------------------------------------------------
cd /d "%~dp0"
call venv\Scripts\activate.bat
python -m pip show pytest >nul 2>nul
if errorlevel 1 (
  echo pytest is not installed. Run setup.bat or install requirements-dev.txt first.
  pause
  exit /b 1
)
python -m pytest -v
pause
