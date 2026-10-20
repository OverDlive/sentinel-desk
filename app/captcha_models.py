"""CPU inference adapters for the two user-selected research checkpoints.

Imported only by the separate ML worker, never by the desktop UI process.
"""
import hashlib
import io
import math
from pathlib import Path


GOOGLE_CLASSIFIER = "sources/Breaking-reCAPTCHAv2/models/YOLO_Classification/train4/weights/best.pt"
GOOGLE_SEGMENTER = "sources/Breaking-reCAPTCHAv2/yolov8n-seg.pt"
BAIDU_MODEL = "baidu-models/conv_0203_ft_0205_pl_0206.pth"
BAIDU_ROTNETR = "baidu-models/RotNetR-v0.5.1.pth"

LABELS = {
    "bicycle": ("bicycle", "자전거", "自行车"),
    "bridge": ("bridge", "다리", "교량", "桥"),
    "bus": ("bus", "버스", "公交", "巴士"),
    "car": ("cars", "car", "자동차", "汽车", "小轿车"),
    "chimney": ("chimney", "chimneys", "굴뚝", "烟囱"),
    "crosswalk": ("crosswalk", "횡단보도", "人行横道", "斑马线"),
    "hydrant": ("hydrant", "소화전", "消防栓"),
    "motorcycle": ("motorcycle", "오토바이", "摩托"),
    "mountain": ("mountain", "산", "山"),
    "palm": ("palm", "야자", "棕榈"),
    "stairs": ("stairs", "계단", "楼梯"),
    "traffic": ("traffic light", "traffic lights", "신호등", "红绿灯", "交通信号灯"),
}
COCO = {"bicycle": 1, "car": 2, "motorcycle": 3, "bus": 5, "traffic": 9, "hydrant": 10}


def target_label(prompt):
    prompt = prompt.casefold()
    # Specific compound names first, so a substring cannot select a different class.
    candidates = [(len(term), label) for label, terms in LABELS.items() for term in terms if term.casefold() in prompt]
    return max(candidates)[1] if candidates else None


def choose_baidu_prediction(primary, legacy, strategy="consensus"):
    gap = (primary["angle"] - legacy["angle"] + 180) % 360 - 180
    if strategy == "rotnet":
        chosen = dict(primary)
        if primary["rotation_consistency"] < .95:
            chosen["angle"] = primary["single_angle"]
            chosen["clockwise_correction"] = (360 - chosen["angle"]) % 360
            chosen["strategy"] = "rotnet_author_single"
    else:
        chosen = dict(legacy)
        if strategy != "convnext" and abs(gap) <= 12 and primary["rotation_consistency"] >= .95:
            chosen["angle"] = (legacy["angle"] + .25 * gap) % 360
            chosen["clockwise_correction"] = (360 - chosen["angle"]) % 360
            chosen["model"] = "ConvNeXt+RotNetR"
            chosen["strategy"] = "agreement_blend"
    chosen["candidate_predictions"] = {"rotnet": primary, "convnext": legacy}
    chosen["model_disagreement"] = abs(gap)
    return chosen


def verified_file(root, relative):
    import json
    path = Path(root) / relative
    manifest = json.loads((Path(root) / "manifest.json").read_text(encoding="utf-8"))
    expected = manifest.get("sha256", {}).get(relative)
    if not expected or not path.is_file():
        raise ValueError("모델 파일 또는 검증 정보가 없습니다.")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError("모델 파일 해시가 설치 기록과 다릅니다.")
    return path


class Models:
    def __init__(self, root):
        import torch
        self.root = Path(root)
        self.models = {}
        torch.set_num_threads(min(4, torch.get_num_threads()))

    def yolo(self, relative):
        if relative not in self.models:
            import torch
            from ultralytics import YOLO
            from unittest.mock import patch
            path = verified_file(self.root, relative)
            load = torch.load
            # These original YOLO checkpoints serialize modules, rather than state_dicts.
            # Permit that only for files checked against the installed source manifest.
            def trusted_load(file, *args, **kwargs):
                if Path(file).resolve() != path.resolve():
                    raise ValueError("설치된 모델 외의 역직렬화 요청을 거부했습니다.")
                kwargs["weights_only"] = False
                return load(file, *args, **kwargs)
            with patch("torch.load", trusted_load):
                self.models[relative] = YOLO(str(path))
        return self.models[relative]

    def google(self, image_bytes, prompt, grid):
        import torch
        import numpy as np
        from PIL import Image
        from torchvision import transforms
        label = target_label(prompt)
        if label is None:
            return dict(status="unsupported", reason="지원하지 않는 reCAPTCHA 대상", label=None)
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        selected, scores = [], []
        if grid == 3:
            model = self.yolo(GOOGLE_CLASSIFIER)
            index = next((i for i, name in model.names.items() if name.casefold().replace("traffic light", "traffic") == label), None)
            if index is None:
                return dict(status="unsupported", reason="학습 클래스에 없는 대상", label=label)
            tiles = []
            for row in range(3):
                for column in range(3):
                    tile = image.crop((column * image.width // 3, row * image.height // 3,
                                       (column + 1) * image.width // 3, (row + 1) * image.height // 3))
                    tiles.append(transforms.ToTensor()(tile.resize((128, 128))))
            # Match the original project's tensor preprocessing and 0.2 threshold.
            predictions = model.predict(torch.stack(tiles), device="cpu", verbose=False)
            scores = [float(result.probs.data[index]) for result in predictions]
            selected = [i for i, score in enumerate(scores) if score > 0.2]
            # The tile classifier misses small objects (observed on a green hydrant).
            # Reuse the installed segmenter on the whole board as an independent vote.
            detector_tiles = []
            if label in COCO:
                detections = self.yolo(GOOGLE_SEGMENTER).predict(
                    image, device="cpu", imgsz=640, conf=0.45, verbose=False)
                for result in detections:
                    for detected, box in zip(result.boxes.cls, result.boxes.xyxy):
                        if int(detected) != COCO[label]:
                            continue
                        x1, y1, x2, y2 = (float(value) for value in box)
                        column = min(2, max(0, int((x1 + x2) / 2 * 3 / image.width)))
                        row = min(2, max(0, int((y1 + y2) / 2 * 3 / image.height)))
                        detector_tiles.append(row * 3 + column)
                selected = sorted(set(selected + detector_tiles))
        elif grid == 4:
            if label not in COCO:
                return dict(status="unsupported", reason="분할 모델에 없는 대상", label=label)
            import cv2
            predictions = self.yolo(GOOGLE_SEGMENTER).predict(image, device="cpu", imgsz=320, conf=0.5, verbose=False)
            mask = np.zeros((image.height, image.width), dtype=np.uint8)
            for result in predictions:
                if result.masks is None:
                    continue
                for index, detected in enumerate(result.boxes.cls):
                    if int(detected) == COCO[label]:
                        polygon = np.asarray(result.masks[index].xy[0], dtype=np.int32)
                        cv2.fillPoly(mask, [polygon], 1)
            selected = [row * 4 + column for row in range(4) for column in range(4)
                        if np.any(mask[row * image.height // 4:(row + 1) * image.height // 4,
                                       column * image.width // 4:(column + 1) * image.width // 4])]
        else:
            return dict(status="unsupported", reason="지원하지 않는 격자 크기", label=label)
        result = dict(status="predicted", label=label, selected=selected, scores=scores, grid=grid)
        if grid == 3:
            result["detector_selected"] = sorted(set(detector_tiles))
        return result

    def baidu_convnext(self, image_bytes):
        import torch
        from torch import nn
        from torchvision import models, transforms
        from PIL import Image
        if "baidu" not in self.models:
            checkpoint = verified_file(self.root, BAIDU_MODEL)
            model = models.convnext_tiny(weights=None)
            # Architecture and preprocessing specified by rotate-captcha-solver.
            model.classifier = nn.Sequential(nn.AdaptiveAvgPool2d((1, 1)), nn.Flatten(),
                nn.Linear(768, 512), nn.GELU(), nn.Dropout(0.5), nn.Linear(512, 2))
            model.load_state_dict(torch.load(checkpoint, map_location="cpu", weights_only=True))
            self.models["baidu"] = model.eval()
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB").resize((152, 152))
        transform = transforms.Compose([transforms.ToTensor(), transforms.Normalize(
            [0.485, 0.456, 0.406], [0.229, 0.224, 0.225])])
        rotations = list(range(0, 360, 45))
        batch = torch.stack([transform(image.rotate(-rotation, resample=Image.Resampling.BICUBIC,
            fillcolor=(255, 255, 255))) for rotation in rotations])
        with torch.inference_mode():
            vectors = self.models["baidu"](batch)
        estimates = [(math.atan2(float(vector[0]), float(vector[1])) - math.radians(rotation))
                     for vector, rotation in zip(vectors, rotations)]
        sine = sum(math.sin(angle) for angle in estimates) / len(estimates)
        cosine = sum(math.cos(angle) for angle in estimates) / len(estimates)
        angle = math.degrees(math.atan2(sine, cosine)) % 360
        return dict(status="predicted", angle=angle, clockwise_correction=(360 - angle) % 360,
                    model="ConvNeXt-Tiny-0206",
                    rotation_consistency=math.hypot(sine, cosine),
                    single_angle=math.degrees(estimates[0]) % 360, augmentation_count=len(rotations),
                    augmentation_angles=[math.degrees(value) % 360 for value in estimates])

    def baidu_rotnet(self, image_bytes):
        """RotNetR v0.5.1: RegNetY + 128 circular orientation classes."""
        import torch
        from torch import nn
        from torchvision import models, transforms
        from torchvision.transforms import functional as F
        from PIL import Image
        if "rotnet" not in self.models:
            state = torch.load(verified_file(self.root, BAIDU_ROTNETR), map_location="cpu", weights_only=True)
            model = models.regnet_y_3_2gf(weights=None)
            model.fc = nn.Linear(model.fc.in_features, 128)
            model.load_state_dict({key.removeprefix("backbone."): value for key, value in state.items()})
            self.models["rotnet"] = model.eval()
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB").resize((152, 152))
        normalizer = transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
        rotations = list(range(0, 360, 45))
        # Match the author's process_captcha: inscribed square, 224px, ImageNet norm.
        batch = torch.stack([normalizer(F.resize(F.center_crop(F.to_tensor(
            image.rotate(-rotation, resample=Image.Resampling.BICUBIC, fillcolor="white")),
            round(152 / math.sqrt(2))), [224, 224], antialias=True)) for rotation in rotations])
        with torch.inference_mode():
            probabilities = self.models["rotnet"](batch).softmax(dim=1)
        classes = probabilities.argmax(dim=1).tolist()
        estimates = [math.radians(index * 360 / 128 + rotation) for index, rotation in zip(classes, rotations)]
        sine = sum(math.sin(angle) for angle in estimates) / len(estimates)
        cosine = sum(math.cos(angle) for angle in estimates) / len(estimates)
        # This checkpoint predicts CCW orientation; recovering it requires CW rotation.
        correction = math.degrees(math.atan2(sine, cosine)) % 360
        return dict(status="predicted", model="RotNetR-v0.5.1", angle=(360 - correction) % 360,
            clockwise_correction=correction, rotation_consistency=math.hypot(sine, cosine),
            single_angle=(360 - classes[0] * 360 / 128) % 360, augmentation_count=len(rotations),
            mean_peak_probability=float(probabilities.max(dim=1).values.mean()),
            augmentation_angles=[(360 - math.degrees(value)) % 360 for value in estimates],
            augmentation_confidences=probabilities.max(dim=1).values.tolist())

    def baidu(self, image_bytes, strategy="consensus"):
        primary = self.baidu_rotnet(image_bytes)
        legacy = self.baidu_convnext(image_bytes)
        return choose_baidu_prediction(primary, legacy, strategy)
