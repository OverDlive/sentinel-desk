"""Verify both real models using the standalone, Python-free worker package."""
import base64
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    runtime = root / "dist/captcha-runtime"
    executable = runtime / "worker/CaptchaWorker/CaptchaWorker.exe"
    samples = root / ".captcha-tools/sources"
    requests = [dict(engine="google", image=next((samples / "Breaking-reCAPTCHAv2/temp").glob("*.png")), prompt="traffic lights", grid=3),
                dict(engine="baidu", image=next((samples / "rotate-captcha-solver/caps/raw_labeled_caps").glob("*.png")))]
    report = {}
    for request in requests:
        request["image"] = base64.b64encode(request["image"].read_bytes()).decode("ascii")
        request.update(mode="infer", runtime=str(runtime))
        completed = subprocess.run([str(executable)], input=json.dumps(request).encode(), capture_output=True, timeout=90,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        lines = [line for line in completed.stdout.splitlines() if line.startswith(b"SENTINEL_CAPTCHA_RESULT=")]
        if not lines:
            raise RuntimeError("Packaged worker did not return a result: " + completed.stderr.decode(errors="replace")[-1500:])
        result = json.loads(lines[-1].split(b"=", 1)[1])
        assert result["status"] == "predicted", result
        if request["engine"] == "baidu":
            assert result["augmentation_count"] == 8, result
        report[request["engine"]] = result
    target = options.output or root / "test-artifacts/captcha-models/packaged-report.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
