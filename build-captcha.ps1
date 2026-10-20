param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$runtimePython = Join-Path $PSScriptRoot '.captcha-tools/venv/Scripts/python.exe'
$originalPath = $env:PYTHONPATH
try {
    & $Python (Join-Path $PSScriptRoot 'tools/prepare_captcha_models.py')
    if ($LASTEXITCODE -ne 0) { throw '모델 정보 준비 실패' }
    $env:PYTHONPATH = Join-Path $PSScriptRoot '.build-tools'
    $env:PYINSTALLER_CONFIG_DIR = Join-Path $PSScriptRoot 'build/captcha-cache'
    $env:YOLO_CONFIG_DIR = Join-Path $PSScriptRoot '.captcha-tools/config/yolo'
    $env:YOLO_AUTOINSTALL = 'false'
    & $runtimePython -m PyInstaller --noconfirm --clean --onedir --console --name CaptchaWorker --collect-data playwright --collect-submodules ultralytics.nn --collect-data ultralytics --distpath build/captcha-package --workpath build/captcha-worker --specpath build .captcha-tools/worker/captcha_worker.py
    if ($LASTEXITCODE -ne 0) { throw '모델 작업 프로그램 빌드 실패' }
    $destination = Join-Path $PSScriptRoot 'dist/captcha-runtime'
    New-Item -ItemType Directory -Path (Join-Path $destination 'worker') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'build/captcha-package/CaptchaWorker') -Destination (Join-Path $destination 'worker') -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '.captcha-tools/manifest.json') -Destination $destination -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '.captcha-tools/licenses') -Destination $destination -Recurse -Force
    $manifest = Get-Content -LiteralPath (Join-Path $destination 'manifest.json') -Raw | ConvertFrom-Json
    foreach ($relative in $manifest.sha256.PSObject.Properties.Name) {
        $target = Join-Path $destination $relative
        New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path (Join-Path $PSScriptRoot '.captcha-tools') $relative) -Destination $target -Force
    }
} finally {
    $env:PYTHONPATH = $originalPath
}
Write-Host '완료: dist/captcha-runtime'
