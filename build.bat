@echo off
REM pydpi.exe uretir -> dist\pydpi.exe (yonetici izni ister)
python -m pip install -r requirements.txt pyinstaller || exit /b 1
pyinstaller --onefile --uac-admin --name pydpi --collect-all pydivert main.py || exit /b 1
echo.
echo Hazir: dist\pydpi.exe
