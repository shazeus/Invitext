@echo off
setlocal
cd /d "%~dp0"
title Invitext Portable
echo.
echo   Invitext Portable
echo   Folder: %CD%
echo.
echo   Try: itx --help
echo   Example: itx inspect photo.jpg
echo.
cmd /k "set PATH=%CD%;%PATH%"

