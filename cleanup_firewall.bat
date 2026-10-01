@echo off
chcp 65001 >nul
rem VpnGuard: удаляет правила блокировки из Windows Firewall.
rem Нужен, только если VpnGuard был аварийно завершён и приложение осталось без сети.
net session >nul 2>&1
if errorlevel 1 (
  echo Запусти этот файл правой кнопкой - "Запуск от имени администратора"
  pause
  exit /b 1
)
netsh advfirewall firewall delete rule name="VpnGuard_Block_Target"
netsh advfirewall firewall delete rule name="VpnGuard_Block_Target_IN"
echo.
echo Готово. Правила VpnGuard удалены (сообщение "No rules match" значит, что их и не было).
pause
