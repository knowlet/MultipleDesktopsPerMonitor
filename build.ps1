<#
.SYNOPSIS
  Configures and builds vdprobe with the repo-local, no-admin toolchain.

.DESCRIPTION
  The toolchain lives under .toolchain/ (portable CMake + winlibs MinGW-w64) so
  the project builds without Visual Studio and without administrator rights.
  Pass -Msvc to use a Visual Studio toolchain instead, if one is available.
#>
[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$Msvc,
    [string]$Config = 'RelWithDebInfo'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$tc = Join-Path $root '.toolchain'
$build = Join-Path $root 'build'

if ($Clean -and (Test-Path $build)) { Remove-Item -Recurse -Force $build }

$cmakeLocal = Join-Path $tc 'cmake-4.4.2-windows-x86_64\bin\cmake.exe'
$cmake = if (Test-Path $cmakeLocal) { $cmakeLocal } else { 'cmake' }

if ($Msvc) {
    & $cmake -S $root -B $build -DCMAKE_BUILD_TYPE=$Config
} else {
    $mingwBin = Join-Path $tc 'mingw64\bin'
    if (-not (Test-Path (Join-Path $mingwBin 'g++.exe'))) {
        throw "MinGW toolchain not found at $mingwBin. See README.md for provisioning."
    }
    $env:Path = "$mingwBin;$env:Path"
    # The project enables CXX only, so no C compiler is passed (it would be
    # reported by CMake as an unused command-line option).
    & $cmake -S $root -B $build -G 'MinGW Makefiles' `
        -DCMAKE_BUILD_TYPE=$Config `
        -DCMAKE_CXX_COMPILER="$mingwBin\g++.exe" `
        -DCMAKE_MAKE_PROGRAM="$mingwBin\mingw32-make.exe"
}
if ($LASTEXITCODE -ne 0) { throw "configure failed ($LASTEXITCODE)" }

& $cmake --build $build --parallel
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }

$exe = Join-Path $build 'vdprobe.exe'
if (-not (Test-Path $exe)) { throw "vdprobe.exe not produced" }
Write-Host "built: $exe" -ForegroundColor Green
