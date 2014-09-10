@echo off
set /p pth="Enter path to a writeable directory [c:\temp]:"
if "%pth%" == "" (
set pth=c:\temp
)
set pth=%pth%\
set cmd_file="%pth%ftp_cmd.txt"
set output_file="%pth%ftp_output.txt"

:loop
set /p cmd="[%cd%] "
if "%cmd%" == "exit" (
if exist %cmd_file% del /f %cmd_file% 
if exist %output_file% del /f %output_file%
set pth=
goto :eof
)
if %cmd:~0,2% == cd (
pushd %cmd:~2%
goto loop
)
if "%cmd%" == "" (
goto loop
)
echo !%cmd%^> %output_file% > %cmd_file%
echo bye>> %cmd_file%
ftp -s:%cmd_file% > nul
type %output_file% | findstr /V /R /C:"^ftp> " | findstr /V /R /C:"^bye$"
goto loop
