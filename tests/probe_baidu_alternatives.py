"""Compare both local orientation models on author samples and saved failures."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.captcha_models import Models, choose_baidu_prediction


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=24)
    options = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    runtime = root / ".captcha-tools"
    os.environ["YOLO_CONFIG_DIR"] = str(runtime / "config/yolo")
    os.environ["YOLO_AUTOINSTALL"] = "false"
    models = Models(runtime)
    rows = []
    for image in sorted((runtime / "sources/rotate-captcha-solver/caps/raw_labeled_caps").glob("*.png"))[:options.samples]:
        truth = float(image.stem.split("_rot")[1].rsplit("_", 1)[0].replace("_", "."))
        predictions = dict(convnext=models.baidu_convnext(image.read_bytes()), rotnet=models.baidu_rotnet(image.read_bytes()))
        predictions["consensus"] = choose_baidu_prediction(predictions["rotnet"], predictions["convnext"])
        rows.append(dict(image=image.name, expected_angle=truth, predictions=predictions,
            error={name: abs((item["angle"] - truth + 180) % 360 - 180) for name, item in predictions.items()}))
    result = dict(author_samples_not_independent_test=True, count=len(rows),
        mae={name: sum(row["error"][name] for row in rows) / len(rows) for name in ("convnext", "rotnet", "consensus")}, rows=rows)
    destination = root / "test-artifacts/captcha-models/revision-3/model-comparison.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "rows"}), flush=True)


if __name__ == "__main__":
    main()
