@echo off
setlocal

REM Create a temporary directory
set TMP_DIR=%TEMP%\devops_bot
mkdir %TMP_DIR%
echo Created temporary directory at %TMP_DIR%

REM Copy the wheel file to the temporary directory
copy devops_bot-0.1-py3-none-any.whl %TMP_DIR%

REM Create a virtual environment
python -m venv %TMP_DIR%\env
call %TMP_DIR%\env\Scripts\activate.bat

REM Upgrade pip and install the wheel file
pip install --upgrade pip
pip install %TMP_DIR%\devops_bot-0.1-py3-none-any.whl

REM Deactivate the virtual environment
call %TMP_DIR%\env\Scripts\deactivate.bat

REM Cleanup
rmdir /S /Q %TMP_DIR%
echo Installation completed successfully.

endlocal

