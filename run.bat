@echo off
cd /d "%~dp0"
if not exist logs mkdir logs

start "antiscan-signature" /min cmd /c "python workers\signature_engine.py > logs\signature.log 2>&1"
start "antiscan-yara"      /min cmd /c "python workers\yara_engine.py > logs\yara.log 2>&1"
start "antiscan-heuristic" /min cmd /c "python workers\heuristic_engine.py > logs\heuristic.log 2>&1"
start "antiscan-hashrep"   /min cmd /c "python workers\hash_engine.py > logs\hash.log 2>&1"

timeout /t 2 >nul
echo Workers started. Starting web server on :5000 ...
python server.py