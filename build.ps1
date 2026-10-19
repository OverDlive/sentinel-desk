param(
    [string]$Python = 'python',
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not $SkipTests) {
    & $Python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw '테스트에 실패하여 빌드를 중지했습니다.' }
}
$toolDirectory = Join-Path $PSScriptRoot '.build-tools'
if (-not (Test-Path -LiteralPath (Join-Path $toolDirectory 'PyInstaller'))) {
    & $Python -m pip install --target $toolDirectory 'pyinstaller==6.22.3'
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller 설치에 실패했습니다.' }
}
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = $toolDirectory
    $iconPath = Join-Path $PSScriptRoot 'assets/sentinel.ico'
    $versionPath = Join-Path $PSScriptRoot 'assets/version.txt'
    $mainPath = Join-Path $PSScriptRoot 'main.py'
    $env:PYINSTALLER_CONFIG_DIR = Join-Path $PSScriptRoot 'build/cache'
    $assetsPath = Join-Path $PSScriptRoot 'assets'
    & $Python -m PyInstaller --noconfirm --clean --onefile --windowed --name SentinelDesk --icon $iconPath --add-data "$assetsPath;assets" --version-file $versionPath --distpath dist --workpath build --specpath build $mainPath
    if ($LASTEXITCODE -ne 0) { throw 'EXE 빌드에 실패했습니다.' }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination (Join-Path $PSScriptRoot 'dist/사용안내.md') -Force
    Compress-Archive -LiteralPath @((Join-Path $PSScriptRoot 'dist/SentinelDesk.exe'), (Join-Path $PSScriptRoot 'dist/사용안내.md')) -DestinationPath (Join-Path $PSScriptRoot 'dist/SentinelDesk-v1.0.0-Windows-x64.zip') -Force
} finally {
    $env:PYTHONPATH = $previousPythonPath
}
Write-Host '완료: dist/SentinelDesk.exe'
