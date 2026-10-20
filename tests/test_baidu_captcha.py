import itertools
import json
import random
import unittest
from unittest.mock import Mock, MagicMock, patch

from app.baidu_captcha import motion_points, Page, solve
from app.captcha_models import choose_baidu_prediction
from app.search_browser import local_debugger_endpoint


class BaiduCaptchaTests(unittest.TestCase):
    def test_model_disagreement_does_not_average_opposite_orientations(self):
        legacy = dict(angle=5, clockwise_correction=355, model="convnext", rotation_consistency=.99)
        other = dict(angle=185, clockwise_correction=175, model="rotnet", rotation_consistency=.99, single_angle=185)
        self.assertEqual(choose_baidu_prediction(other, legacy)["angle"], 5)

    def test_model_agreement_wraps_across_zero_degrees(self):
        legacy = dict(angle=359, clockwise_correction=1, model="convnext", rotation_consistency=.99)
        other = dict(angle=1, clockwise_correction=359, model="rotnet", rotation_consistency=.99, single_angle=1)
        result = choose_baidu_prediction(other, legacy)
        self.assertAlmostEqual(result["angle"], 359.5)
        self.assertAlmostEqual(result["clockwise_correction"], .5)

    def test_pointer_path_stays_in_owned_slider_and_finishes_exactly(self):
        points = motion_points((100, 100), (344, 100), 1.4, random.Random(42))
        self.assertEqual(points[-1][:2], (344, 100))
        self.assertTrue(all(100 <= x <= 344 and abs(y-100) <= 1.8 and delay > 0 for x, y, delay in points))
        self.assertAlmostEqual(sum(point[2] for point in points), 1.4)

    def test_local_browser_metadata_cannot_redirect_to_another_host_or_port(self):
        for endpoint in ("ws://other.example:1234/devtools/browser/a", "ws://127.0.0.1:9999/devtools/browser/a",
                         "ws://user@127.0.0.1:1234/devtools/browser/a"):
            opener = MagicMock()
            opener.open.return_value.__enter__.return_value.read.return_value = json.dumps(dict(webSocketDebuggerUrl=endpoint)).encode()
            with patch("app.search_browser.build_opener", return_value=opener), self.assertRaises(ValueError):
                local_debugger_endpoint(1234)

    def test_direct_controller_does_not_read_an_outside_image(self):
        page = Page.__new__(Page)
        page.call = Mock()
        with self.assertRaises(ValueError):
            page.image(dict(source="https://unrelated.example/image"))
        page.call.assert_not_called()

    def test_response_callback_queues_body_read_without_reentrant_cdp(self):
        page = Page.__new__(Page)
        page.responses, page.pending, page.requests = [], [], {}
        page.call = Mock()
        page.record(dict(method="Network.responseReceived", params=dict(requestId="private-id",
            response=dict(url="https://wappass.baidu.com/cap/c?token=private", status=200))))
        self.assertEqual(page.responses, [dict(host="wappass.baidu.com", path="/cap/c", http_status=200)])
        self.assertEqual(len(page.pending), 1)
        page.call.assert_not_called()

    def test_search_gate_distinguishes_success_payload_from_transport_success(self):
        page = Page.__new__(Page)
        entry = {}
        page.pending = [("private-request", entry)]
        page.call = Mock(return_value=dict(body=json.dumps(dict(code=0, data=dict(f=dict(reason="risk"))))))
        page.read_verification(lambda body: dict(code=0))
        self.assertFalse(entry["gate_success"])
        self.assertEqual(entry["code"], 0)

    def test_authentication_request_logging_keeps_presence_without_token_values(self):
        page = Page.__new__(Page)
        page.responses, page.pending, page.requests = [], [], {}
        page.record(dict(method="Network.requestWillBeSent", params=dict(requestId="r", request=dict(
            url="https://wappass.baidu.com/cap/c?ak=private", postData=json.dumps(dict(tk="private-ticket", ds="private-device"))))))
        page.record(dict(method="Network.responseReceived", params=dict(requestId="r", response=dict(
            url="https://wappass.baidu.com/cap/c?ak=private", status=200))))
        self.assertNotIn("private", json.dumps(page.responses))
        self.assertTrue(page.responses[0]["request_fields"]["ds"]["present"])

    def test_temporary_green_success_does_not_count_as_search_navigation(self):
        page = Mock()
        page.responses = []
        page.state.return_value = dict(search=False, verified=True, ready=True, source="one-image", webdriver=False,
            rotation=0, message="security risk", refresh=None,
            knob=dict(x=100, y=100, width=46, height=46), track=dict(x=100, y=100, width=290, height=53))
        page.image.return_value = b"image"
        page.move.return_value = 20
        models = Mock()
        models.baidu.return_value = dict(status="predicted", angle=180, clockwise_correction=180)
        clock = itertools.count()
        with patch("app.baidu_captcha.Page", return_value=page), patch("app.baidu_captcha.time.sleep"), \
                patch("app.baidu_captcha.time.monotonic", side_effect=lambda: next(clock)):
            result = solve(models, {}, Mock(), Mock(), Mock())
        self.assertNotIn(result["status"], ("widget_verified", "navigation_resumed"))
        self.assertTrue(result["events"][0]["widget_success_observed"])
        page.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
