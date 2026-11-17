@echo off
title ThreatLens Launch Orchestrator
echo ===================================================
echo           Starting ThreatLens Platform
echo ===================================================
echo [1/3] Launching Django Backend Server (Port 8000)...
start "ThreatLens Backend" "%~dp0run_backend.bat"

echo [2/3] Launching Mock ML Service (Port 8001)...
start "ThreatLens ML Service" "%~dp0run_ml.bat"

timeout /t 3 /nobreak >nul

echo [3/3] Launching Frontend Console (Port 5173)...
start "ThreatLens Frontend" "%~dp0run_frontend.bat"

timeout /t 4 /nobreak >nul

echo Opening browser at http://localhost:5173 ...
start http://localhost:5173

echo ===================================================
echo ThreatLens services are starting in separate windows.
echo Superuser Credentials:
echo   Username: admin
echo   Password: Password123!
echo ===================================================
pause
