@echo off
cd /d "%~dp0"

rem Ensure MSVC environment is loaded for standard headers
if not defined INCLUDE (
  if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" (
    call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
  )
)

set "CARGO_BUILD_JOBS=1"
set "NUM_JOBS=1"
set "CARGO_MAKEFLAGS="
set "MAKEFLAGS="
set "CMAKE_BUILD_PARALLEL_LEVEL=1"
if not defined CMAKE_BUILD_ARGS set "CMAKE_BUILD_ARGS="
set "CMAKE_GENERATOR="

rem Use Ninja to avoid MSBuild -j errors
for /f "delims=" %%I in ('where ninja 2^>nul') do (
  set "CMAKE_MAKE_PROGRAM=%%I"
  goto :ninja_found
)
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" (
  set "CMAKE_MAKE_PROGRAM=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
  goto :ninja_found
)
for /f "delims=" %%I in ('dir /b /s "C:\vcpkg\downloads\tools\ninja\ninja.exe" 2^>nul') do (
  set "CMAKE_MAKE_PROGRAM=%%I"
  goto :ninja_found
)
echo Ninja not found. Install: C:\vcpkg\vcpkg install ninja
echo Then make sure ninja.exe is in PATH or under C:\vcpkg\downloads\tools\ninja
exit /b 1

:ninja_found

set "CMAKE_ARGS=-G Ninja -DCMAKE_MAKE_PROGRAM=%CMAKE_MAKE_PROGRAM%"

set "PKG_CONFIG=C:\vcpkg\installed\x64-windows\tools\pkgconf\pkgconf.exe"
set "PKG_CONFIG_PATH=C:\vcpkg\installed\x64-windows\lib\pkgconfig;C:\vcpkg\installed\x64-windows\share\pkgconfig"

set "OPENSSL_ROOT_DIR=C:\vcpkg\installed\x64-windows"
set "OPENSSL_INCLUDE_DIR=C:\vcpkg\installed\x64-windows\include"
set "OPENSSL_CRYPTO_LIBRARY=C:\vcpkg\installed\x64-windows\lib\libcrypto.lib"
set "OPENSSL_SSL_LIBRARY=C:\vcpkg\installed\x64-windows\lib\libssl.lib"

set "ZLIB_ROOT=C:\vcpkg\installed\x64-windows"
set "ZLIB_INCLUDE_DIR=C:\vcpkg\installed\x64-windows\include"
set "ZLIB_LIBRARY=C:\vcpkg\installed\x64-windows\lib\zlib.lib"

set "SODIUM_ROOT=C:\vcpkg\installed\x64-windows"
set "SODIUM_INCLUDE_DIR=C:\vcpkg\installed\x64-windows\include"
set "SODIUM_LIBRARY=C:\vcpkg\installed\x64-windows\lib\libsodium.lib"

rem Clear cached generator from previous MSBuild runs
for /d %%D in ("target\debug\build\tonlib-sys-*") do (
  rmdir /s /q "%%D"
)

cargo build
