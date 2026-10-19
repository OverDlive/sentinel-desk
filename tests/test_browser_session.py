import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from app.collectors import Collectors
from app.devtools import DevTools, DevToolsError
from app.search_browser import SearchSession, RenderError
from app.search_html import parse_search_html
from app.store import Store
from test_monitor import exhaust, target_data, FixtureTransport
from test_search_html import GOOGLE


URL = "https://www.google.com/search?q=Acme&hl=ko&gl=kr&start=0"


def snapshot(html, url=URL):
    return dict(html=html, url=url, ready="complete")


class BrowserSessionTests(unittest.TestCase):
    def session(self, snapshots, interactive=True):
        session = SearchSession(Path("test-artifacts/session-unit"), "google", threading.Event(), interactive, Mock())
        session.start = Mock()
        session.client = Mock()
        session.client.call.return_value = {}
        session.session = "fixture-session"
        session.snapshot = Mock(side_effect=snapshots)
        return session

    def test_manual_challenge_waits_then_resumes_same_navigation(self):
        session = self.session([snapshot("<title>CAPTCHA</title>"), snapshot(GOOGLE), snapshot(GOOGLE)])
        with patch.object(session.stop, "wait", return_value=False):
            items, more = session.results(URL)
        self.assertEqual(len(items), 1)
        self.assertTrue(more)
        session.client.call.assert_called_once_with("Page.navigate", dict(url=URL), session="fixture-session")
        self.assertTrue(any("인증 대기" in call.args[0] for call in session.progress.call_args_list))

    def test_scheduled_run_reports_auth_without_waiting(self):
        session = self.session([snapshot("<title>CAPTCHA</title>")], interactive=False)
        with self.assertRaises(RenderError) as error:
            session.results(URL)
        self.assertEqual(error.exception.code, "auth_required")
        self.assertEqual(session.snapshot.call_count, 1)

    def test_auth_timeout_is_distinct(self):
        session = self.session([snapshot("<title>CAPTCHA</title>")])
        with self.assertRaises(RenderError) as error:
            session.results(URL, auth_timeout=0)
        self.assertEqual(error.exception.code, "auth_required")

    def test_cancel_does_not_open_browser(self):
        session = self.session([])
        session.stop.set()
        with self.assertRaises(RenderError) as error:
            session.results(URL)
        self.assertEqual(error.exception.code, "cancelled")
        session.start.assert_not_called()

    def test_wrong_query_and_outside_navigation_rejected(self):
        for response in [snapshot(GOOGLE, "https://www.google.com/search?q=Other"),
                         dict(url="https://example.org/personal", outside=True)]:
            session = self.session([response])
            with self.assertRaises(RenderError):
                session.results(URL)

    def test_no_arbitrary_target_navigation(self):
        session = self.session([])
        with self.assertRaises(RenderError):
            session.results("https://example.com/")
        session.start.assert_not_called()

    def test_page_loading_timeout(self):
        session = self.session([dict(url="about:blank", outside=True)])
        with patch("app.search_browser.time.monotonic", side_effect=[0, 41]):
            with self.assertRaises(RenderError) as error:
                session.results(URL)
        self.assertEqual(error.exception.code, "schema")

    def test_verification_redirect_is_waitable(self):
        session = self.session([snapshot("<html>verification</html>", "https://wappass.baidu.com/static/captcha"), snapshot(GOOGLE), snapshot(GOOGLE)])
        with patch.object(session.stop, "wait", return_value=False):
            self.assertEqual(len(session.results(URL)[0]), 1)

    def test_result_snippet_mentions_captcha_without_false_block(self):
        self.assertEqual(len(parse_search_html(GOOGLE.replace("검색 결과", "CAPTCHA 검색 결과"), "google")[0]), 1)

    def test_devtools_rejects_remote_endpoint_before_connect(self):
        with patch("app.devtools.socket.create_connection") as connect:
            for url in ("ws://example.com/devtools/browser/a", "ws://127.0.0.1/other", "https://localhost/devtools/browser/a"):
                with self.assertRaises(DevToolsError):
                    DevTools(url)
            connect.assert_not_called()

    def test_collector_reuses_browser_and_counts_navigation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            target = store.save_target(target_data())
            collector = Collectors(store, threading.Event(), FixtureTransport([]))
            collector.interactive = True
            config = dict(pages=1, browser_session=True)
            rule = dict(provider="google", query="Acme", kind="brand")
            result = ([dict(url="https://example.com/a", title="Acme", description="")], False)
            with patch("app.collectors.SearchSession") as browser, patch.object(collector.stop, "wait", return_value=False):
                browser.return_value.results.return_value = result
                self.assertEqual(len(exhaust(collector.collect(rule, target, config))[0]), 1)
                exhaust(collector.collect(rule, target, config))
                self.assertEqual(browser.call_count, 1)
                self.assertEqual(browser.return_value.results.call_count, 2)
                self.assertEqual(next(p for p in store.providers() if p["id"] == "google")["used_today"], 2)
                collector.close()
                browser.return_value.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
