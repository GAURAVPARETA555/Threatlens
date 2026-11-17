@echo off
title ThreatLens Mock ML Service
cd /d "%~dp0backend"
call ".\env\Scripts\activate.bat"
echo Starting Mock ML Service on http://127.0.0.1:8001/predict/ ...
python mock_ml.py
pause
