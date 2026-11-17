@echo off
title ThreatLens Backend (Django)
cd /d "%~dp0backend"
call ".\env\Scripts\activate.bat"
echo Starting ThreatLens Django backend on http://127.0.0.1:8000 ...
python manage.py runserver 127.0.0.1:8000
pause
