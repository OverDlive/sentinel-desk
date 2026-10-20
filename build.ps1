param(
    [string]$Python = 'python',
    [switch]$SkipTests,
    [string]$OutputName = 'SentinelDesk'
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if ($OutputName -notmatch '^[A-Za-z0-9_-]+$') { throw '올바른 실행 파일 이름을 입력하세요.' }
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.captcha-tools/manifest.json')) {
    & $Python (Join-Path $PSScriptRoot 'tools/prepare_captcha_models.py')
    if ($LASTEXITCODE -ne 0) { throw '모델 작업 프로그램 준비에 실패했습니다.' }
}
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
    & $Python -m PyInstaller --noconfirm --clean --onefile --windowed --name $OutputName --icon $iconPath --add-data "$assetsPath;assets" --version-file $versionPath --distpath dist --workpath build --specpath build $mainPath
    if ($LASTEXITCODE -ne 0) { throw 'EXE 빌드에 실패했습니다.' }
    $guideName = if ($OutputName -eq 'SentinelDesk') { '사용안내.md' } else { "사용안내-$OutputName.md" }
    $guidePath = Join-Path (Join-Path $PSScriptRoot 'dist') $guideName
    $guide = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Raw -Encoding UTF8).Replace('SentinelDesk.exe', "$OutputName.exe")
    [System.IO.File]::WriteAllText($guidePath, $guide, [System.Text.UTF8Encoding]::new($false))
    $packagePaths = @((Join-Path (Join-Path $PSScriptRoot 'dist') "$OutputName.exe"), $guidePath)
    $captchaRuntime = Join-Path $PSScriptRoot 'dist/captcha-runtime'
    if (Test-Path -LiteralPath (Join-Path $captchaRuntime 'manifest.json')) {
        $packagePaths += $captchaRuntime
    }
    Compress-Archive -LiteralPath $packagePaths -DestinationPath (Join-Path (Join-Path $PSScriptRoot 'dist') "$OutputName-v1.0.0-Windows-x64.zip") -Force
} finally {
    $env:PYTHONPATH = $previousPythonPath
}
Write-Host "완료: dist/$OutputName.exe"
