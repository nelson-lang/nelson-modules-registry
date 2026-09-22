@echo off
rem Signs registry.json with the Ed25519 private key passed as an argument.
rem Windows wrapper around sign_registry.ps1. Requires openssl in PATH.
rem
rem   scripts\sign_registry.cmd <cle_privee.pem>
rem
setlocal
if "%~1"=="" (
  echo usage: sign_registry.cmd ^<cle_privee.pem^>>&2
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sign_registry.ps1" "%~1"
exit /b %ERRORLEVEL%
