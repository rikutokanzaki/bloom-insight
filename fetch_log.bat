@echo off
setlocal enabledelayedexpansion

set ENV_FILE=%~dp0.env

if not exist "%ENV_FILE%" (
    echo [ERROR] .env file not found: %ENV_FILE%
    exit /b 1
)

set USERNAME=
set SERVER=
set DIRECTRY=
set MODE=
set REMOTE_PATH=

for /f "usebackq tokens=1* delims==" %%A in ("%ENV_FILE%") do (
    set "key=%%A"
    set "value=%%B"

    for /f "tokens=* delims= " %%K in ("!key!") do set "key=%%K"
    for /f "tokens=* delims= " %%V in ("!value!") do set "value=%%V"

    if not "!key!"=="" (
        if not "!key:~0,1!"=="#" (
            if /i "!key!"=="USERNAME" set "USERNAME=!value!"
            if /i "!key!"=="SERVER"   set "SERVER=!value!"
            if /i "!key!"=="PORT"   set "PORT=!value!"
            if /i "!key!"=="DIRECTRY" set "DIRECTRY=!value!"
            if /i "!key!"=="MODE"     set "MODE=!value!"
            if /i "!key!"=="REMOTE_PATH"     set "REMOTE_PATH=!value!"
        )
    )
)

if "%USERNAME%"=="" (
    echo [ERROR] USERNAME is not set.
    exit /b 1
)
if "%SERVER%"=="" (
    echo [ERROR] SERVER is not set.
    exit /b 1
)
if "%PORT%"=="" (
    echo [ERROR] PORT is not set.
    exit /b 1
)
if "%DIRECTRY%"=="" (
    echo [ERROR] DIRECTRY is not set.
    exit /b 1
)
if "%MODE%"=="" (
    echo [ERROR] MODE is not set.
    exit /b 1
)
if "%REMOTE_PATH%"=="" (
    echo [ERROR] REMOTE_PATH (remote path) is not set.
    exit /b 1
)

set "COPY_FOR=%~dp0log\raw\"

set "REMOTE_FULL=%DIRECTRY%/%MODE%%REMOTE_PATH%"

echo Assembled SCP command:
echo scp -r "%USERNAME%@%SERVER%:%REMOTE_FULL%" "%COPY_FOR%"
echo.

scp -r -P "%PORT%" "%USERNAME%@%SERVER%:%REMOTE_FULL%" "%COPY_FOR%"
if %errorlevel% neq 0 (
    echo [ERROR] scp failed with exit code %errorlevel%.
    endlocal
    exit /b %errorlevel%
)

echo [SUCCESS] File(s) copied to %COPY_FOR%
endlocal
exit /b 0
