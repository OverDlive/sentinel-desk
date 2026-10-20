"""Launch the optional ML runtime without loading torch into the desktop process."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


MODEL_FILES = {
    "google": ["sources/Breaking-reCAPTCHAv2/models/YOLO_Classification/train4/weights/best.pt",
               "sources/Breaking-reCAPTCHAv2/yolov8n-seg.pt"],
    "baidu": ["baidu-models/conv_0203_ft_0205_pl_0206.pth", "baidu-models/RotNetR-v0.5.1.pth"],
}


def runtime_directory():
    configured = os.environ.get("SENTINEL_CAPTCHA_RUNTIME")
    roots = [Path(configured)] if configured else []
    if getattr(sys, "frozen", False):
        roots.extend([Path(sys.executable).parent / "captcha-runtime", Path(sys.executable).parent / ".captcha-tools", Path(sys.executable).parent.parent / ".captcha-tools"])
    roots.append(Path(__file__).resolve().parents[1] / ".captcha-tools")
    return next((path for path in roots if (path / "manifest.json").is_file()), None)


def runtime_status(engine):
    root = runtime_directory()
    if root is None:
        return "모델 런타임 미설치"
    if not (root / "worker/CaptchaWorker/CaptchaWorker.exe").is_file() and not (root / "venv/Scripts/python.exe").is_file():
        return "모델 Python 런타임 없음"
    if any(not (root / relative).is_file() for relative in MODEL_FILES.get(engine, [])):
        return "사전학습 모델 파일 없음"
    return "로컬 CPU 모델 준비됨"


def attempt_captcha(engine, endpoint, target_id, stop, artifacts=None, timeout=115):
    root = runtime_directory()
    if root is None or runtime_status(engine) != "로컬 CPU 모델 준비됨":
        return dict(status="unavailable", reason=runtime_status(engine))
    source = Path(__file__).with_name("captcha_worker.py")
    worker = source if not getattr(sys, "frozen", False) and source.exists() else root / "worker/captcha_worker.py"
    executable = root / "worker/CaptchaWorker/CaptchaWorker.exe"
    if not executable.is_file() and not worker.is_file():
        return dict(status="unavailable", reason="모델 작업 프로그램이 없습니다.")
    request = dict(runtime=str(root.resolve()), engine=engine, endpoint=endpoint, target_id=target_id)
    if artifacts:
        request["artifacts"] = str(artifacts)
    payload = json.dumps(request).encode()
    command = [str(executable)] if executable.is_file() else [str(root / "venv/Scripts/python.exe"), "-u", str(worker)]
    process = subprocess.Popen(command,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    deadline = time.monotonic() + timeout
    first = True
    while True:
        if stop.is_set() or time.monotonic() >= deadline:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=10)
            process.communicate(timeout=10)
            return dict(status="cancelled" if stop.is_set() else "timeout", reason="모델 작업 중단")
        try:
            output, _error = process.communicate(payload if first else None, timeout=0.25)
            break
        except subprocess.TimeoutExpired:
            first = False
    prefix = b"SENTINEL_CAPTCHA_RESULT="
    for line in reversed(output.splitlines()):
        if line.startswith(prefix):
            try:
                result = json.loads(line[len(prefix):])
                if isinstance(result, dict) and isinstance(result.get("status"), str):
                    return result
            except (ValueError, UnicodeError):
                break
    return dict(status="error", reason="모델 작업 응답을 확인하지 못했습니다.")
