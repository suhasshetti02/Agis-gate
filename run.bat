@echo off
echo Starting Aegis-Gate...

IF NOT EXIST .env (
    echo [WARNING] .env file not found.
    echo Please copy .env.example to .env and configure your secrets.
    pause
    exit /b 1
)

IF NOT EXIST venv (
    echo Creating virtual environment...
    python -m venv venv
)

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Installing dependencies...
pip install -r requirements.txt

echo Launching Aegis-Gate...
python app.py

pause
