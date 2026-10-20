param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$runtime = Join-Path $PSScriptRoot '.captcha-tools'
New-Item -ItemType Directory -Path (Join-Path $runtime 'sources') -Force | Out-Null
$repositories = @(
    @('Breaking-reCAPTCHAv2', 'https://github.com/aplesner/Breaking-reCAPTCHAv2.git', 'b5fc91a83b55b797229ab59f02a09f578552e843'),
    @('rotate-captcha-solver', 'https://github.com/yixiaowang2001/rotate-captcha-solver.git', 'ada84124204372d3a7c9016e73b77e0e081bab7f'),
    @('rotate-captcha-crack', 'https://github.com/lumina37/rotate-captcha-crack.git', '4a1c0b8792c9a658e74436066349cd340ca9de59')
)
foreach ($repository in $repositories) {
    $destination = Join-Path (Join-Path $runtime 'sources') $repository[0]
    if (-not (Test-Path -LiteralPath $destination)) {
        & git clone $repository[1] $destination
        if ($LASTEXITCODE -ne 0) { throw '원본 저장소 다운로드 실패' }
        & git -C $destination checkout --detach $repository[2]
        if ($LASTEXITCODE -ne 0) { throw '원본 커밋 선택 실패' }
    } else {
        $revision = & git -C $destination rev-parse HEAD
        if ($revision -ne $repository[2]) { throw '기존 원본 커밋이 다릅니다. 자동으로 덮어쓰지 않습니다.' }
    }
}
$runtimePython = Join-Path $runtime 'venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $runtimePython)) {
    & $Python -m venv (Join-Path $runtime 'venv')
    if ($LASTEXITCODE -ne 0) { throw '모델 가상환경 생성 실패' }
}
& $runtimePython -m pip install torch==2.6.0 torchvision==0.21.0 --index-url https://download.pytorch.org/whl/cpu
if ($LASTEXITCODE -ne 0) { throw 'CPU 런타임 설치 실패' }
& $runtimePython -m pip install ultralytics==8.3.0 numpy==1.26.4 opencv-python==4.10.0.84 pandas==2.2.3 playwright==1.58.0 gdown==5.2.0
if ($LASTEXITCODE -ne 0) { throw '모델 의존성 설치 실패' }
$modelDirectory = Join-Path $runtime 'baidu-models'
New-Item -ItemType Directory -Path $modelDirectory -Force | Out-Null
$model = Join-Path $modelDirectory 'conv_0203_ft_0205_pl_0206.pth'
if (-not (Test-Path -LiteralPath $model)) {
    & (Join-Path $runtime 'venv/Scripts/gdown.exe') 'https://drive.google.com/uc?id=1nOLhSK-lPu0bYdvuF8GTwSEA877pIMul' -O $model
    if ($LASTEXITCODE -ne 0) { throw '사전학습 모델 다운로드 실패' }
}
& $Python (Join-Path $PSScriptRoot 'tools/install_baidu_alternative.py')
if ($LASTEXITCODE -ne 0) { throw 'RotNetR 모델 설치 실패' }
$expectedModels = @{
    'sources/Breaking-reCAPTCHAv2/models/YOLO_Classification/train4/weights/best.pt' = '07d447e1ff4c21178f8acd7b55bb8f026f4e00105fd172faed851c7583abe8f7'
    'sources/Breaking-reCAPTCHAv2/yolov8n-seg.pt' = 'd39e867b2c3a5dbc1aa764411544b475cb14727bf6af1ec46c238f8bb1351ab9'
    'baidu-models/conv_0203_ft_0205_pl_0206.pth' = '159927b0ffa7d165b9ae562a00b1a4a1c5358623b40c6f2798f321188478408d'
    'baidu-models/RotNetR-v0.5.1.pth' = 'f3546e2c91d13f3747e3b916f291f40981426374ddee7c1a50d22dc62158613b'
}
foreach ($relative in $expectedModels.Keys) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $runtime $relative) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expectedModels[$relative]) { throw '모델 파일이 검증한 버전과 다릅니다.' }
}
& $Python (Join-Path $PSScriptRoot 'tools/prepare_captcha_models.py')
if ($LASTEXITCODE -ne 0) { throw '모델 설치 기록 실패' }
Write-Host '모델 준비 완료'
