# Run IDS demo: starts Backend and Frontend
# Usage: .\scripts\run-demo.ps1
# Open http://localhost:5173 in browser after both start

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host "Starting IDS Demo (Backend + Frontend)..." -ForegroundColor Cyan
Write-Host ""

# Start backend in new window
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\Backend\ids_backend'; Write-Host 'Backend starting on http://localhost:5000' -ForegroundColor Green; python run.py"

Start-Sleep -Seconds 3

# Start frontend in new window
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\Frontend\ids-control-panel'; Write-Host 'Frontend starting on http://localhost:5173' -ForegroundColor Green; npm run dev"

Write-Host ""
Write-Host "Backend:  http://localhost:5000" -ForegroundColor Yellow
Write-Host "Frontend: http://localhost:5173" -ForegroundColor Yellow
Write-Host "Open http://localhost:5173 in your browser" -ForegroundColor Cyan
