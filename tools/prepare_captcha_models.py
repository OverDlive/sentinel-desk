"""Record downloaded checkpoint identities and stage the separate ML worker."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    project = Path(__file__).resolve().parents[1]
    runtime = project / ".captcha-tools"
    models = ["sources/Breaking-reCAPTCHAv2/models/YOLO_Classification/train4/weights/best.pt",
              "sources/Breaking-reCAPTCHAv2/yolov8n-seg.pt",
              "baidu-models/conv_0203_ft_0205_pl_0206.pth",
              "baidu-models/RotNetR-v0.5.1.pth"]
    manifest = dict(sha256={}, sources={})
    for relative in models:
        path = runtime / relative
        if path.is_file():
            manifest["sha256"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ("Breaking-reCAPTCHAv2", "rotate-captcha-solver", "rotate-captcha-crack"):
        path = runtime / "sources" / name
        if path.is_dir():
            manifest["sources"][name] = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    worker = runtime / "worker"
    worker.mkdir(exist_ok=True)
    for name in ("captcha_models.py", "captcha_worker.py", "baidu_captcha.py", "devtools.py"):
        if (project / "app" / name).exists():
            shutil.copy2(project / "app" / name, worker / name)
    licenses = runtime / "licenses"
    licenses.mkdir(exist_ok=True)
    license_file = project / "assets/licenses/RotNetR-Unlicense.txt"
    if license_file.exists():
        shutil.copy2(license_file, licenses / license_file.name)
    (runtime / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
