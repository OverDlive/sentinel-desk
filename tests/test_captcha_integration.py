import hashlib
import base64
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from app.captcha_models import target_label, verified_file
from app.captcha_runtime import attempt_captcha
from app.captcha_worker import allowed_endpoint, allowed_page, verification_fields, google_stable, cached_image
from app.search_browser import SearchSession, RenderError
from test_search_html import GOOGLE


URL = "https://www.google.com/search?q=Acme"


class CaptchaIntegrationTests(unittest.TestCase):
    def session(self, outcome, html=GOOGLE):
        session = SearchSession("test-artifacts/captcha-unit", "google", threading.Event(), interactive=False)
        session.endpoint, session.target_id, session.session = "ws://127.0.0.1:1234/devtools/browser/test", "owned-tab", "owned-session"
        session.start = Mock()
        session.client = Mock()
        session.client.call.return_value = {}
        session.snapshot = Mock(side_effect=[dict(url=URL, html="<title>CAPTCHA</title>", ready="complete"),
                                            dict(url=URL, html=html, ready="complete"),
                                            dict(url=URL, html=html, ready="complete")])
        return session

    def test_successful_model_attempt_still_requires_original_search_results(self):
        outcome = dict(status="widget_verified", events=[dict(status="predicted", grid=3, selected=[1, 2])])
        session = self.session(outcome)
        with patch("app.search_browser.attempt_captcha", return_value=outcome) as solver, patch.object(session.stop, "wait", return_value=False):
            self.assertEqual(len(session.results(URL)[0]), 1)
        solver.assert_called_once()
        self.assertEqual(session.captcha_attempts, [outcome])
        self.assertEqual(session.snapshot.call_count, 3)

    def test_unsupported_model_is_auth_required_and_attempted_once(self):
        session = self.session(dict(status="unsupported"))
        with patch("app.search_browser.attempt_captcha", return_value=dict(status="unsupported", reason="unsupported challenge")) as solver:
            with self.assertRaises(RenderError) as error:
                session.results(URL)
        self.assertEqual(error.exception.code, "auth_required")
        solver.assert_called_once()

    def test_model_success_waits_for_delayed_search_redirect_in_scheduled_run(self):
        outcome = dict(status="widget_verified", events=[dict(status="predicted")])
        session = self.session(outcome)
        challenge = dict(url=URL, html="<title>CAPTCHA</title>", ready="complete")
        results = dict(url=URL, html=GOOGLE, ready="complete")
        session.snapshot.side_effect = [challenge, challenge, challenge, results, results]
        with patch("app.search_browser.attempt_captcha", return_value=outcome), patch.object(session.stop, "wait", return_value=False):
            self.assertEqual(len(session.results(URL)[0]), 1)
        self.assertEqual(session.snapshot.call_count, 5)

    def test_cancelled_model_job_cancels_collection(self):
        session = self.session(dict(status="cancelled"))
        with patch("app.search_browser.attempt_captcha", return_value=dict(status="cancelled")):
            with self.assertRaises(RenderError) as error:
                session.results(URL)
        self.assertEqual(error.exception.code, "cancelled")

    def test_model_file_hash_checked_before_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "model.pt").write_bytes(b"known-model")
            (root / "manifest.json").write_text(json.dumps(dict(sha256={"model.pt": hashlib.sha256(b"known-model").hexdigest()})))
            self.assertEqual(verified_file(root, "model.pt"), root / "model.pt")
            (root / "model.pt").write_bytes(b"modified")
            with self.assertRaises(ValueError):
                verified_file(root, "model.pt")

    def test_prompt_labels_cover_actual_model_targets(self):
        self.assertEqual(target_label("Select all images with traffic lights"), "traffic")
        self.assertEqual(target_label("자동차가 있는 이미지를 선택하세요"), "car")
        self.assertEqual(target_label("请选择所有包含自行车的图片"), "bicycle")
        self.assertIsNone(target_label("Select all images with cats"))

    def test_worker_endpoint_and_target_scope(self):
        self.assertFalse(allowed_endpoint("ws://remote.example/devtools/browser/a"))
        self.assertFalse(allowed_endpoint("http://127.0.0.1:1234/"))
        self.assertTrue(allowed_endpoint("ws://127.0.0.1:1234/devtools/browser/a"))
        self.assertFalse(allowed_page("https://google.com.evil.example/", "google"))
        self.assertTrue(allowed_page("https://wappass.baidu.com/static/captcha", "baidu"))

    def test_missing_runtime_is_explicit_and_does_not_launch_process(self):
        with patch("app.captcha_runtime.runtime_directory", return_value=None), patch("app.captcha_runtime.subprocess.Popen") as process:
            outcome = attempt_captcha("google", "", "", threading.Event())
        self.assertEqual(outcome["status"], "unavailable")
        process.assert_not_called()

    def test_verification_response_keeps_errors_without_challenge_tokens(self):
        body = 'callback({"data":{"errno":104,"msg":"security risk","token":"private-value"},"id":"private-challenge"})'
        self.assertEqual(verification_fields(body), {"data": {"errno": 104, "msg": "security risk"}})
        self.assertEqual(verification_fields('{"code":0,"data":{"code":401,"result":false}}'),
            {"code": 0, "data": {"code": 401, "result": False}})
        self.assertEqual(verification_fields('callback({"msg":"https://site.test/?token=private"})'), {})

    def test_google_waits_for_selected_dynamic_tile_to_be_replaced(self):
        ready = dict(ready=True, selected=[], dynamic=True, signature=["replacement"], feedback="")
        frame = Mock()
        frame.evaluate.side_effect = [dict(ready=True, selected=[1], dynamic=True, signature=["old"], feedback=""),
            dict(ready=False, selected=[], dynamic=True, signature=["replacement"], feedback=""), ready, ready, ready]
        page = Mock()
        self.assertEqual(google_stable(frame, page, time.monotonic() + 5, unselected=True), ready)
        self.assertEqual(frame.evaluate.call_count, 5)

    def test_google_static_selection_is_not_mistaken_for_pending_replacement(self):
        state = dict(ready=True, selected=[1, 2], dynamic=False, signature=["static"], feedback="")
        frame = Mock()
        frame.evaluate.return_value = state
        self.assertEqual(google_stable(frame, Mock(), time.monotonic() + 5), state)

    def test_google_waits_before_first_dynamic_tile_has_changed_its_image_class(self):
        state = dict(ready=True, selected=[], dynamic=True, signature=["replacement"], feedback="")
        frame = Mock()
        frame.evaluate.side_effect = [dict(ready=True, selected=[1], dynamic=False, signature=["old-board"], feedback=""),
            state, state, state]
        self.assertEqual(google_stable(frame, Mock(), time.monotonic() + 5, unselected=True), state)
        self.assertEqual(frame.evaluate.call_count, 4)

    def test_baidu_reads_already_loaded_image_without_another_http_request(self):
        page = Mock()
        frame = page.main_frame
        client = page.context.new_cdp_session.return_value
        source = "https://passport.baidu.com/cap/img?id=private-challenge"
        client.send.side_effect = [{}, {"frameTree": {"frame": {"id": "owned"}, "resources": [{"url": source}]}},
                                  {"base64Encoded": True, "content": base64.b64encode(b"image-pixels").decode()}]
        self.assertEqual(cached_image(page, frame, source), b"image-pixels")
        page.context.new_cdp_session.assert_called_once_with(page)
        page.request.get.assert_not_called()
        client.detach.assert_called_once()

    def test_baidu_does_not_infer_from_a_different_cached_resource(self):
        page = Mock()
        client = page.context.new_cdp_session.return_value
        client.send.side_effect = [{}, {"frameTree": {"frame": {"id": "owned"}, "resources": []}}]
        with self.assertRaises(ValueError):
            cached_image(page, page.main_frame, "https://passport.baidu.com/cap/img?id=other")
        client.detach.assert_called_once()


if __name__ == "__main__":
    unittest.main()
