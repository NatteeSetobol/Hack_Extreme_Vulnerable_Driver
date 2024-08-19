echo off
set OUTPUT=poc.exe
set MAIN_FILES=../main.cpp

REM use ^ for line break

set SUPPORT_FILES=

set FLAGS= /Zi
set LIB_FILES=
set MACROS=-DDEBUG=1


if exist build (
    del build
)

mkdir build
pushd build

cl.exe /Fe:%OUTPUT% %MAIN_FILES% %SUPPORT_FILES% %MACROS% %FLAGS% %LIB_FILES%  

popd