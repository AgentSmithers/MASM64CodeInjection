@echo off
setlocal

REM --- Configuration ---
REM Set the base path for your MASM64 installation if it's not in the system PATH
SET MASM_PATH=\masm64
REM Set the path to your Windows SDK libraries (adjust if necessary)
REM Common locations might be within Program Files (x86)\Windows Kits\10\Lib\
REM Or sometimes included with the assembler/linker distribution.
REM If PoLink finds them automatically, you might not need this explicit path.
SET SDK_LIB_PATH=%MASM_PATH%\lib64
REM Or potentially a full path like: "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
SET LIB_FILES=\masm64\lib64\kernel32.lib \masm64\lib64\user32.lib \masm64\lib64\msvcrt.lib \masm64\lib64\winmm.lib


REM --- Cleanup ---
if exist "InjectSpeed.obj" del "InjectSpeed.obj"
if exist "InjectSpeed.exe" del "InjectSpeed.exe"

REM --- Assemble ---
echo Assembling main.asm...
"%MASM_PATH%\bin64\ml64.exe" /c "main.asm" /Fo"main.obj"
if errorlevel 1 (
    echo.
    echo *** Assembly Error ***
	pause
    goto TheEnd
)

REM --- Link ---
echo Linking InjectSpeed.obj...
REM PoLink typically takes libraries directly. Add /LIBPATH if needed.

"%MASM_PATH%\bin64\PoLink.exe" /SUBSYSTEM:CONSOLE /ENTRY:main "InjectSpeed.obj" %LIB_FILES% /OUT:"main.exe"



REM If PoLink complains about /LIBPATH or finds libs automatically, you might remove /LIBPATH:"%SDK_LIB_PATH%"
REM Or if PoLink is different, check its documentation for library path syntax.

if errorlevel 1 (
    echo.
    echo *** Link Error ***
pause
    goto TheEnd
)

REM --- Success ---
echo.
echo Build successful!
dir "main.*"
echo.

REM --- Optional: Copy and Run ---
echo Running main.exe...
main.exe

:TheEnd
echo.
endlocal
