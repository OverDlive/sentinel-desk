"""Explicit real-checkpoint smoke test, kept separate from lightweight unit tests."""
import json
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.captcha_models import Models


def main():
    root = Path(__file__).resolve().parents[1] / ".captcha-tools"
    import os
    os.environ["YOLO_CONFIG_DIR"] = str(root / "config/yolo")
    os.environ["MPLCONFIGDIR"] = str(root / "config/matplotlib")
    models = Models(root)
    google_image = next((root / "sources/Breaking-reCAPTCHAv2/temp").glob("*.png"))
    report = dict(google_classification=models.google(google_image.read_bytes(), "traffic lights", 3),
                  google_segmentation=models.google(google_image.read_bytes(), "traffic lights", 4), baidu=[])
    folder = root / "sources/rotate-captcha-solver/caps/raw_labeled_caps"
    for image in sorted(folder.glob("*.png"))[:12]:
        truth = float(image.stem.split("_rot")[1].rsplit("_", 1)[0].replace("_", "."))
        prediction = models.baidu(image.read_bytes())
        error = abs((prediction["angle"] - truth + 180) % 360 - 180)
        report["baidu"].append(dict(image=image.name, expected_angle=truth, predicted_angle=prediction["angle"], angular_error=error))
    report["baidu_mean_angular_error"] = sum(item["angular_error"] for item in report["baidu"]) / len(report["baidu"])
    report["site_acceptance_tested"] = False
    target = Path("test-artifacts/captcha-models")
    target.mkdir(parents=True, exist_ok=True)
    (target / "offline-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
