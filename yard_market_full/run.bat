@echo off
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (echo Python not found. Install Python 3.10+ and try again.& pause & exit /b 1)
if not exist .venv py -m venv .venv
call .venv\Scripts\activate.bat
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
py app.py
pause
