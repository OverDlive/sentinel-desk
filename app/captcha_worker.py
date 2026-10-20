"""One bounded CAPTCHA attempt in a separate Python/ML process.

Uses the existing app-owned tab, not the research repositories' demo browser loops.
"""
import base64
import contextlib
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlsplit

try:
    from .captcha_models import Models
except ImportError:
    from captcha_models import Models


def allowed_endpoint(endpoint):
    parts = urlsplit(endpoint)
    return parts.scheme == "ws" and parts.hostname == "127.0.0.1" and parts.path.startswith("/devtools/browser/")


def allowed_page(url, engine):
    host = urlsplit(url).hostname or ""
    domain = "google.com" if engine == "google" else "baidu.com"
    return host == domain or host.endswith("." + domain)


def evidence_image(request, name, data):
    directory = request.get("artifacts")
    if directory:
        folder = Path(directory)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / name).write_bytes(data)


def evidence_json(request, name, data):
    if request.get("artifacts"):
        evidence_image(request, name, json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))


def verification_fields(body):
    """Keep response codes/messages, never challenge IDs, tokens or request URLs."""
    try:
        value = json.loads(body[body.index("{"):body.rindex("}") + 1])
    except (ValueError, TypeError):
        return {}
    def visit(item, depth=0):
        result = {}
        if not isinstance(item, dict) or depth > 3:
            return result
        for key, value in item.items():
            if key.casefold() in ("errno", "err_no", "error", "code", "status", "msg", "message", "errmsg", "errormsg", "result", "success", "reason", "error_code", "sub_code", "verify_status", "op", "type", "action", "verify", "pass"):
                if isinstance(value, (int, float, bool)) or value is None:
                    result[key] = value
                elif isinstance(value, str) and len(value) < 180 and not re.search(r"https?://|[A-Za-z0-9+/=_-]{35,}", value):
                    result[key] = value
            if isinstance(value, dict):
                child = visit(value, depth + 1)
                if child:
                    result[key] = child
        return result
    return visit(value)


GOOGLE_STATE = r'''() => {
  const tiles = Array.from(document.querySelectorAll('.rc-imageselect-tile'));
  const images = tiles.map(tile => tile.querySelector('img'));
  const marked = tile => tile.matches('.rc-imageselect-tileselected, .rc-imageselect-dynamic-selected') ||
    tile.querySelector('.rc-imageselect-tileselected, .rc-imageselect-dynamic-selected');
  return {
    count: tiles.length,
    classes: tiles.map(tile => tile.className),
    selected: tiles.flatMap((tile, i) => marked(tile) ? [i] : []),
    ready: images.length > 0 && images.every(img => img && img.complete && img.naturalWidth > 0 &&
      Number(getComputedStyle(img).opacity) > .99) && tiles.every(tile =>
        !tile.getAnimations({subtree:true}).some(animation => animation.playState === 'running')),
    signature: images.map(img => img ? [img.currentSrc, img.style.cssText, img.naturalWidth] : null),
    dynamic: images.some(img => img && img.classList.contains('rc-image-tile-11')),
    feedback: Array.from(document.querySelectorAll('.rc-imageselect-error-select-more, .rc-imageselect-error-dynamic-more, .rc-imageselect-incorrect-response'))
      .filter(el => getComputedStyle(el).display !== 'none').map(el => el.innerText).join(' ').slice(0, 180)
  };
}'''


def google_stable(frame, page, deadline, unselected=False):
    """Wait for replaced tiles, not a fixed sleep that races dynamic challenges."""
    previous, repeats = None, 0
    while time.monotonic() < deadline:
        state = frame.evaluate(GOOGLE_STATE)
        signature = json.dumps(state, sort_keys=True)
        if state["ready"] and (not unselected or not state["selected"]):
            repeats = repeats + 1 if signature == previous else 0
            if repeats >= 2:
                return state
        else:
            repeats = 0
        previous = signature
        page.wait_for_timeout(300)
    return None


def cached_image(page, frame, source):
    """Read the browser's already-loaded image; a second HTTP request returns JSON."""
    client = page.context.new_cdp_session(page if frame == page.main_frame else frame)
    try:
        client.send("Page.enable")
        tree = client.send("Page.getResourceTree")["frameTree"]
        def find(node):
            if any(resource.get("url") == source for resource in node.get("resources", [])):
                return node["frame"]["id"]
            return next((value for child in node.get("childFrames", []) if (value := find(child))), None)
        frame_id = find(tree)
        if frame_id is None:
            raise ValueError("Image is not in the owned frame resource tree")
        resource = client.send("Page.getResourceContent", dict(frameId=frame_id, url=source))
        if not resource.get("base64Encoded") or len(resource["content"]) > 1400000:
            raise ValueError("Invalid image resource")
        return base64.b64decode(resource["content"], validate=True)
    finally:
        client.detach()


def google_frame(page, selector):
    for frame in page.frames:
        host = urlsplit(frame.url).hostname or ""
        if host not in ("www.google.com", "www.recaptcha.net", "recaptcha.google.com"):
            continue
        element = frame.locator(selector).first
        if element.count() and element.is_visible():
            return frame
    return None


def google(page, models, request):
    events = []
    anchor = google_frame(page, "#recaptcha-anchor")
    if anchor:
        checkbox = anchor.locator("#recaptcha-anchor")
        if checkbox.get_attribute("aria-checked") == "true":
            return dict(status="widget_verified", events=[])
        checkbox.click(timeout=4000)
        page.wait_for_timeout(2000)
    deadline = time.monotonic() + 85
    previous = None
    repeated = 0
    reloads = 0
    for attempt in range(16):
        if time.monotonic() >= deadline:
            break
        if urlsplit(page.url).path == "/search":
            return dict(status="navigation_resumed", events=events)
        frame = google_frame(page, "#rc-imageselect")
        if frame is None:
            rejected = google_frame(page, ".rc-doscaptcha-body-text")
            if rejected:
                return dict(status="server_rejected", events=events, reason="reCAPTCHA가 추가 시도를 거부했습니다.")
            page.wait_for_timeout(1000)
            continue
        state = google_stable(frame, page, min(deadline, time.monotonic() + 10))
        if state is None:
            return dict(status="image_transition_timeout", events=events, reason="CAPTCHA 이미지 교체가 완료되지 않았습니다.")
        tiles = frame.locator(".rc-imageselect-tile")
        count = state["count"]
        if count not in (9, 16):
            return dict(status="unsupported", events=events, reason="지원하지 않는 CAPTCHA 배치입니다.")
        prompt = frame.locator(".rc-imageselect-desc-wrapper").inner_text(timeout=3000)
        data = frame.locator(".rc-imageselect-table-33" if count == 9 else ".rc-imageselect-table-44").screenshot(timeout=4000)
        digest = hashlib.sha256(data).hexdigest()
        repeated = repeated + 1 if previous == digest else 0
        if repeated >= 2:
            return dict(status="not_accepted", events=events, reason="이미지 교체 대기 후에도 같은 CAPTCHA가 반복되어 중단했습니다.")
        previous = digest
        evidence_image(request, f"google-{attempt}.png", data)
        evidence_json(request, f"google-{attempt}-state.json",
            {key: state[key] for key in ("count", "classes", "selected", "ready", "dynamic", "feedback")})
        prediction = models.google(data, prompt, 3 if count == 9 else 4)
        prediction.update(attempt=attempt, board_sha256=digest, feedback_before=state["feedback"])
        events.append(prediction)
        if prediction["status"] != "predicted":
            reload_button = frame.locator("#recaptcha-reload-button")
            if reloads < 2 and reload_button.is_visible():
                reloads += 1
                prediction["challenge_reloaded"] = True
                reload_button.click(timeout=3000)
                page.wait_for_timeout(1800)
                previous = None
                continue
            return dict(status="unsupported", events=events, reason=prediction.get("reason"))
        # Inference takes time; don't apply a prediction to a replaced board.
        current = frame.evaluate(GOOGLE_STATE)
        if current["signature"] != state["signature"] or not current["ready"]:
            prediction["discarded"] = "board_changed_during_inference"
            continue
        for index in prediction["selected"]:
            tile = tiles.nth(index)
            if not tile.evaluate("tile => tile.matches('.rc-imageselect-tileselected, .rc-imageselect-dynamic-selected')"):
                tile.click(timeout=3000)
                page.wait_for_timeout(150)
        dynamic = state["dynamic"] or any(word in prompt.casefold() for word in ("none left", "new images", "새 이미지", "더 이상", "没有", "新图片"))
        prediction["dynamic"] = dynamic
        if dynamic and prediction["selected"]:
            settled = google_stable(frame, page, min(deadline, time.monotonic() + 12), unselected=True)
            prediction["replacement_completed"] = settled is not None
            if settled is None:
                return dict(status="image_transition_timeout", events=events, reason="선택한 CAPTCHA 이미지가 교체되지 않았습니다.")
            continue
        verify = frame.locator("#recaptcha-verify-button")
        if verify.is_visible():
            verify.click(timeout=3000)
        page.wait_for_timeout(2000)
        if request.get("artifacts"):
            evidence_image(request, f"google-{attempt}-after.png", page.screenshot(timeout=4000))
        anchor = google_frame(page, "#recaptcha-anchor")
        if anchor and anchor.locator("#recaptcha-anchor").get_attribute("aria-checked") == "true":
            return dict(status="widget_verified", events=events)
    return dict(status="not_accepted", events=events, reason="제한된 시도 내에 인증 승인을 확인하지 못했습니다.")


def baidu(page, models, request):
    events = []
    previous_source = None
    for attempt in range(3):
        frame = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            for candidate in page.frames:
                if not allowed_page(candidate.url, "baidu"):
                    continue
                element = candidate.locator(".passMod_spin-background").first
                if (element.count() and element.is_visible() and
                        element.evaluate("image => image.complete && image.naturalWidth > 20") and
                        element.get_attribute("src") != previous_source):
                    button = candidate.locator(".passMod_slide-btn").first
                    if button.count() and button.is_visible() and button.bounding_box():
                        frame = candidate
                        break
            if frame is not None:
                break
            if urlsplit(page.url).hostname == "www.baidu.com" and urlsplit(page.url).path == "/s":
                return dict(status="navigation_resumed", events=events)
            page.wait_for_timeout(500)
        if frame is None:
            if request.get("artifacts"):
                evidence_image(request, "baidu-unloaded.png", page.screenshot(timeout=4000))
            return dict(status="challenge_not_loaded", events=events, reason="Baidu 회전 CAPTCHA 이미지·슬라이더가 20초 안에 준비되지 않았습니다.")
        image = frame.locator(".passMod_spin-background").first
        data = image.screenshot(timeout=4000)
        previous_source = image.get_attribute("src")
        image_source = "rendered"
        payload_diagnostics = {}
        # The current page overlays an AI watermark on the image. Read the image
        # the browser already loaded, without replaying the CAPTCHA image request.
        parts = urlsplit(previous_source or "")
        if parts.scheme == "https" and allowed_page(previous_source, "baidu") and parts.path == "/cap/img":
            try:
                payload = cached_image(page, frame, previous_source)
                from PIL import Image, ImageDraw
                source = Image.open(io.BytesIO(payload)).convert("RGB").resize((152, 152))
                mask = Image.new("L", source.size)
                ImageDraw.Draw(mask).ellipse((0, 0, 152, 152), fill=255)
                source = Image.composite(source, Image.new("RGB", source.size, "white"), mask)
                output = io.BytesIO()
                source.save(output, format="PNG")
                data, image_source = output.getvalue(), "browser_cached_payload"
            except Exception as exc:
                payload_diagnostics["error"] = type(exc).__name__
                payload_diagnostics["detail"] = re.sub(r"(?:https?|wss?)://\S+", "[URL]", str(exc).splitlines()[0])[:180]
        evidence_image(request, f"baidu-{attempt}.png", data)
        if request.get("artifacts"):
            evidence_image(request, f"baidu-{attempt}-before.png", page.screenshot(timeout=4000))
        prediction = models.baidu(data)
        prediction.update(attempt=attempt, image_source=image_source, payload_diagnostics=payload_diagnostics,
            image_sha256=hashlib.sha256(data).hexdigest())
        events.append(prediction)
        slider = frame.locator(".passMod_slide-btn").first
        track = frame.locator(".passMod_slide-control").first
        knob, rail = slider.bounding_box(), track.bounding_box()
        if not knob or not rail or rail["width"] <= knob["width"]:
            return dict(status="unsupported", events=events, reason="회전 슬라이더 이동 범위를 확인하지 못했습니다.")
        travel = rail["width"] - knob["width"]
        distance = prediction["clockwise_correction"] / 360 * travel
        prediction.update(travel=travel, drag_distance=distance)
        x, y = knob["x"] + knob["width"] / 2, knob["y"] + knob["height"] / 2
        rotation_expression = r'''image => {
          const matrix = getComputedStyle(image).transform;
          if (!matrix || matrix === 'none') return 0;
          const values = matrix.match(/matrix\(([^)]+)\)/);
          if (!values) return null;
          const parts = values[1].split(',').map(Number);
          return (Math.atan2(parts[1], parts[0]) * 180 / Math.PI + 360) % 360;
        }'''
        initial_rotation = image.evaluate(rotation_expression)
        page.mouse.move(x, y)
        page.mouse.down()
        try:
            probe = min(30, distance / 2)
            for step in range(1, 6):
                page.mouse.move(x + probe * step / 5, y)
                page.wait_for_timeout(40)
            current_rotation = image.evaluate(rotation_expression)
            if probe >= 2 and initial_rotation is not None and current_rotation is not None:
                delta = (current_rotation - initial_rotation) % 360
                if 1 < delta < 180:
                    measured_travel = probe * 360 / delta
                    if 0.7 * travel < measured_travel < 1.3 * travel:
                        distance = prediction["clockwise_correction"] / 360 * measured_travel
                        prediction.update(measured_travel=measured_travel, drag_distance=distance)
            distance = max(0, min(travel, distance))
            for step in range(1, 21):
                t = step / 20
                eased = t * t * (3 - 2 * t)
                page.mouse.move(x + probe + (distance - probe) * eased, y)
                page.wait_for_timeout(60)
            page.wait_for_timeout(300)
            target_rotation = ((initial_rotation or 0) + prediction["clockwise_correction"]) % 360
            for _ in range(3):
                actual_rotation = image.evaluate(rotation_expression)
                if actual_rotation is None:
                    break
                error = (target_rotation - actual_rotation + 180) % 360 - 180
                prediction.update(applied_rotation=actual_rotation, rotation_error=error)
                if abs(error) < 0.8:
                    break
                distance = max(0, min(travel, distance + error / 360 * prediction.get("measured_travel", travel)))
                page.mouse.move(x + distance, y)
                page.wait_for_timeout(300)
            actual_rotation = image.evaluate(rotation_expression)
            if actual_rotation is not None:
                prediction.update(applied_rotation=actual_rotation,
                    rotation_error=(target_rotation - actual_rotation + 180) % 360 - 180)
            if request.get("artifacts"):
                evidence_image(request, f"baidu-{attempt}-aligned.png", page.screenshot(timeout=4000))
        finally:
            page.mouse.up()
        page.wait_for_timeout(4000)
        if urlsplit(page.url).hostname == "www.baidu.com" and urlsplit(page.url).path == "/s":
            return dict(status="navigation_resumed", events=events)
        result_bar = frame.locator(".passMod_slide-grand").first
        if result_bar.count() and "passMod_slide-grand-success" in (result_bar.get_attribute("class") or ""):
            return dict(status="widget_verified", events=events)
        message = frame.locator(".passMod_spin-msg").first
        prediction["site_message"] = message.inner_text(timeout=1500)[:180] if message.count() else ""
        if request.get("artifacts"):
            evidence_image(request, f"baidu-{attempt}-after.png", page.screenshot(timeout=4000))
        if "安全风险" in prediction["site_message"]:
            return dict(status="server_rejected", events=events,
                reason="Baidu가 보안 위험 메시지로 인증을 거부했습니다. 각도 오류와 구분해 기록했습니다.")
    return dict(status="not_accepted", events=events, reason="회전 모델 적용 후 사이트의 인증 승인을 확인하지 못했습니다.")


def run(request):
    runtime = Path(request["runtime"])
    os.environ["YOLO_CONFIG_DIR"] = str(runtime / "config" / "yolo")
    os.environ["MPLCONFIGDIR"] = str(runtime / "config" / "matplotlib")
    os.environ["YOLO_AUTOINSTALL"] = "false"
    models = Models(runtime)
    engine = request["engine"]
    if request.get("mode") == "infer":
        data = base64.b64decode(request["image"], validate=True)
        return models.google(data, request.get("prompt", ""), int(request.get("grid", 3))) if engine == "google" else models.baidu(data)
    endpoint = request["endpoint"]
    if not allowed_endpoint(endpoint) or engine not in ("google", "baidu"):
        raise ValueError("허용되지 않은 브라우저 연결 요청입니다.")
    if engine == "baidu":
        try:
            from .baidu_captcha import solve
        except ImportError:
            from baidu_captcha import solve
        return solve(models, request, evidence_image, evidence_json, verification_fields)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as playwright:
        browser = playwright.chromium.connect_over_cdp(endpoint, timeout=10000)
        page = None
        for context in browser.contexts:
            for candidate in context.pages:
                session = context.new_cdp_session(candidate)
                try:
                    info = session.send("Target.getTargetInfo")["targetInfo"]
                    if info["targetId"] == request["target_id"]:
                        page = candidate
                finally:
                    session.detach()
        if page is None or not allowed_page(page.url, engine):
            raise ValueError("앱 전용 검색 탭을 찾지 못했습니다.")
        verification = []
        def record(response):
            parts = urlsplit(response.url)
            if engine != "baidu" or not allowed_page(response.url, "baidu") or not parts.path.startswith("/cap/"):
                return
            entry = dict(host=parts.hostname, path=parts.path, http_status=response.status,
                content_type=response.headers.get("content-type", ""))
            if "image/" not in response.headers.get("content-type", ""):
                try:
                    body = response.text()
                    if len(body) < 65536:
                        entry.update(verification_fields(body))
                except Exception:
                    pass
            verification.append(entry)
        page.on("response", record)
        outcome = google(page, models, request) if engine == "google" else baidu(page, models, request)
        outcome["verification_responses"] = verification[-20:]
        evidence_json(request, "worker-report.json", outcome)
        return outcome


def main():
    try:
        request = json.loads(sys.stdin.buffer.read(1024 * 1024))
        with contextlib.redirect_stdout(sys.stderr):
            result = run(request)
    except Exception as exc:
        # No request URLs, cookies, browser endpoint tokens or raw exception text in logs.
        result = dict(status="error", reason="모델 작업 실패: " + type(exc).__name__)
    print("SENTINEL_CAPTCHA_RESULT=" + json.dumps(result, ensure_ascii=True), flush=True)


if __name__ == "__main__":
    main()
