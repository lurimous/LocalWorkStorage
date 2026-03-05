@echo off
setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "PYTHON_VERSION=3.11.9"
set "PYTHON_URL=https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
set "PYTHON_INSTALLER=%TEMP%\python-3.11.9-amd64.exe"
set "VENV_DIR=%SCRIPT_DIR%venv"
set "FFMPEG_URL=https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip"
set "FFMPEG_ZIP=%TEMP%\ffmpeg.zip"
set "FFMPEG_DIR=%SCRIPT_DIR%ffmpeg"

:: Candidate install locations (user install first, then system)
set "PYTHON_USER=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
set "PYTHON_SYS=C:\Python311\python.exe"

echo.
echo  File Share Server - Installer
echo  ================================
echo.

:: ── Step 1: Find or install Python 3.11.9 ─────────────────────────────────────
set "PYTHON_EXE="

:: Check user install path
if exist "%PYTHON_USER%" (
    "%PYTHON_USER%" --version 2>nul | findstr /C:"3.11" >nul
    if !errorlevel! == 0 (
        set "PYTHON_EXE=%PYTHON_USER%"
        echo [OK] Found Python 3.11 at: !PYTHON_EXE!
        goto :create_venv
    )
)

:: Check system install path
if exist "%PYTHON_SYS%" (
    "%PYTHON_SYS%" --version 2>nul | findstr /C:"3.11" >nul
    if !errorlevel! == 0 (
        set "PYTHON_EXE=%PYTHON_SYS%"
        echo [OK] Found Python 3.11 at: !PYTHON_EXE!
        goto :create_venv
    )
)

:: Check PATH
where python >nul 2>&1
if !errorlevel! == 0 (
    python --version 2>nul | findstr /C:"3.11" >nul
    if !errorlevel! == 0 (
        for /f "delims=" %%i in ('where python') do (
            set "PYTHON_EXE=%%i"
            goto :found_in_path
        )
        :found_in_path
        echo [OK] Found Python 3.11 in PATH: !PYTHON_EXE!
        goto :create_venv
    )
)

:: ── Download and install Python 3.11.9 ────────────────────────────────────────
echo [..] Python 3.11.9 not found. Downloading installer...
echo      URL: %PYTHON_URL%
echo.

powershell -NoProfile -Command ^
  "Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%PYTHON_INSTALLER%' -UseBasicParsing"

if !errorlevel! neq 0 (
    echo.
    echo [ERROR] Download failed. Check your internet connection and try again.
    pause
    exit /b 1
)

echo [OK] Download complete.
echo [..] Installing Python 3.11.9 (user install, no admin required)...
echo.

"%PYTHON_INSTALLER%" /quiet ^
    InstallAllUsers=0 ^
    PrependPath=1 ^
    Include_test=0 ^
    Include_launcher=1

if !errorlevel! neq 0 (
    echo.
    echo [ERROR] Python installation failed (exit code: !errorlevel!).
    echo         Try running the installer manually: %PYTHON_INSTALLER%
    pause
    exit /b 1
)

del /q "%PYTHON_INSTALLER%" 2>nul
echo [OK] Python 3.11.9 installed.

:: After install, resolve the path
if exist "%PYTHON_USER%" (
    set "PYTHON_EXE=%PYTHON_USER%"
) else (
    echo.
    echo [ERROR] Installation finished but python.exe was not found at expected location:
    echo         %PYTHON_USER%
    echo         Please restart this script or install Python manually.
    pause
    exit /b 1
)

:: ── Step 2: Create virtual environment ────────────────────────────────────────
:create_venv
echo.
echo [..] Creating virtual environment in: %VENV_DIR%

if exist "%VENV_DIR%" (
    echo [..] Existing venv found, removing it...
    rmdir /s /q "%VENV_DIR%"
)

"%PYTHON_EXE%" -m venv "%VENV_DIR%"
if !errorlevel! neq 0 (
    echo [ERROR] Failed to create virtual environment.
    pause
    exit /b 1
)
echo [OK] Virtual environment created.

:: ── Step 3: Install dependencies ──────────────────────────────────────────────
echo.
echo [..] Installing dependencies from requirements.txt...

"%VENV_DIR%\Scripts\python.exe" -m pip install --upgrade pip --quiet
"%VENV_DIR%\Scripts\pip.exe" install -r "%SCRIPT_DIR%requirements.txt" --quiet

if !errorlevel! neq 0 (
    echo [ERROR] pip install failed.
    pause
    exit /b 1
)
echo [OK] Dependencies installed.

:: ── Step 4: Download ffmpeg ───────────────────────────────────────────────────
echo.
if exist "%FFMPEG_DIR%\ffmpeg.exe" (
    echo [OK] ffmpeg already present, skipping download.
    goto :create_start
)

echo [..] Downloading ffmpeg...
powershell -NoProfile -Command ^
  "Invoke-WebRequest -Uri '%FFMPEG_URL%' -OutFile '%FFMPEG_ZIP%' -UseBasicParsing"

if !errorlevel! neq 0 (
    echo [WARN] ffmpeg download failed. Video thumbnails will not work.
    echo        You can manually place ffmpeg.exe in: %FFMPEG_DIR%
    goto :create_start
)

echo [..] Extracting ffmpeg...
mkdir "%FFMPEG_DIR%" 2>nul
powershell -NoProfile -Command ^
  "Add-Type -Assembly System.IO.Compression.FileSystem; $z = [IO.Compression.ZipFile]::OpenRead('%FFMPEG_ZIP%'); $entry = $z.Entries | Where-Object { $_.Name -eq 'ffmpeg.exe' } | Select-Object -First 1; [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, '%FFMPEG_DIR%\ffmpeg.exe', $true); $z.Dispose()"

del /q "%FFMPEG_ZIP%" 2>nul

if exist "%FFMPEG_DIR%\ffmpeg.exe" (
    echo [OK] ffmpeg installed.
) else (
    echo [WARN] ffmpeg extraction failed. Video thumbnails will not work.
)

:: ── Step 5: Create start.bat ───────────────────────────────────────────────────
:create_start
echo.
echo [..] Creating start.bat...

(
    echo @echo off
    echo title File Share Server
    echo cd /d "%%~dp0"
    echo call "%%~dp0venv\Scripts\activate.bat"
    echo python server.py
    echo pause
) > "%SCRIPT_DIR%start.bat"

echo [OK] start.bat created.

:: ── Done ──────────────────────────────────────────────────────────────────────
echo.
echo  ================================
echo  Installation complete!
echo.
echo  To start the server, run:  start.bat
echo  ================================
echo.
pause
endlocal
