@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem Компилятор C#, встроенный в Windows (.NET Framework 4.x) - ничего устанавливать не нужно
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" (
  echo Не найден csc.exe .NET Framework 4.x
  pause
  exit /b 1
)

if not exist "bin" mkdir bin

"%CSC%" /nologo /codepage:65001 /target:winexe /platform:anycpu /optimize+ ^
  /out:bin\VpnGuard.exe /win32manifest:src\app.manifest ^
  /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll ^
  /r:System.Web.Extensions.dll /r:Accessibility.dll ^
  src\*.cs

if errorlevel 1 (
  echo.
  echo ОШИБКА СБОРКИ - см. текст выше
  pause
  exit /b 1
)

if not exist "bin\appsettings.json" copy /y "src\appsettings.json" "bin\appsettings.json" >nul
echo.
echo Готово: bin\VpnGuard.exe
pause
