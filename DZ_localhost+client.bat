@echo off
@cls
@%windir%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -command "%CD%\DZ_server.ps1 -removeLogFiles"