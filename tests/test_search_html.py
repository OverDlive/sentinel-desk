import json
import tempfile
import threading
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from app.collectors import Collectors, CollectionError, Transport
from app.engine import Engine
from app.search_html import parse_search_html, SearchPageError
from app.store import Store
from test_monitor import FixtureTransport, exhaust, target_data


GOOGLE = '''<html><title>검색 결과</title><body><div id="search">
<div class="MjjYud"><div class="g"><div class="tF2Cxc">
<a href="/url?q=https%3A%2F%2Fexample.com%2Fa.pdf%3Fid%3D1&amp;sa=U"><h3>Acme &amp; 공개 문서</h3></a>
<div class="VwiC3b">공개 <em>example.com</em> 문서 요약<script>secret()</script></div>
</div></div></div>
<div class="g"><a href="https://example.com/a.pdf?id=1"><h3>중복</h3></a></div>
<div id="tads"><div class="g"><a href="https://example.com/ad"><h3>광고</h3></a></div></div>
</div><a id="pnnext" href="/search?q=Acme&amp;start=10">다음</a></body></html>'''
BAIDU = '''<html><title>百度搜索</title><body><div id="content_left">
<div class="result c-container" data-tools='{"url":"https://example.com/中文"}'>
<h3><a href="https://www.baidu.com/link?url=opaque">Acme 中文</a></h3>
<div class="c-abstract">中文 <em>摘要</em> &amp; 조직</div></div>
<div class="result c-container"><h3><a href="https://www.baidu.com/link?url=unknown">Acme 重定向</a></h3><div class="c-abstract">Acme</div></div>
</div><a href="/s?wd=Acme&amp;pn=10">下一页</a></body></html>'''


class ParserTests(unittest.TestCase):
    def test_google_entities_redirect_duplicate_ads_and_next(self):
        items, more = parse_search_html(GOOGLE, "google")
        self.assertTrue(more)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["url"], "https://example.com/a.pdf?id=1")
        self.assertEqual(items[0]["title"], "Acme & 공개 문서")
        self.assertEqual(items[0]["description"], "공개 example.com 문서 요약")
        self.assertFalse(parse_search_html(GOOGLE, "google", 10)[1])

    def test_baidu_original_and_opaque_redirect(self):
        items, more = parse_search_html(BAIDU, "baidu")
        self.assertTrue(more)
        self.assertEqual(items[0]["url"], "https://example.com/中文")
        self.assertEqual(items[0]["description"], "中文 摘要 & 조직")
        self.assertEqual(items[1]["url"], "https://www.baidu.com/link?url=unknown")

    def test_rendered_google_retains_opaque_result_link(self):
        html = '''<meta content="0;url=/httpservice/retry/enablejs"><div class="tF2Cxc">
        <a href="/goto?url=opaque"><h3>Example Domains</h3></a><cite>https://www.iana.org › help</cite>
        <div class="VwiC3b">example.com documentation</div></div>'''
        items, _ = parse_search_html(html, "google")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["url"], "https://www.google.com/goto?url=opaque")
        self.assertIn("iana.org", items[0]["description"])

    def test_empty_blocked_and_unknown_are_distinct(self):
        for engine, html in [("google", "<p>Your search did not match any documents.</p>"),
                             ("baidu", "<p>抱歉，没有找到与此相关的网页。</p>")]:
            self.assertEqual(parse_search_html(html, engine), ([], False))
        for html in ['<title>百度安全验证</title>', '<form action="/sorry/index"></form>',
                     '<title>Before you continue to Google</title>']:
            with self.assertRaises(SearchPageError) as error:
                parse_search_html(html, "google")
            self.assertEqual(error.exception.code, "blocked")
        with self.assertRaises(SearchPageError) as error:
            parse_search_html("<html>unexpected layout</html>", "google")
        self.assertEqual(error.exception.code, "schema")


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.target = self.store.save_target(target_data())

    def test_keyless_config_and_backend_switch(self):
        for provider in ("google", "baidu"):
            self.store.save_provider(provider, dict(enabled=True))
            config = next(p for p in self.store.providers(secrets=True) if p["id"] == provider)
            self.assertFalse(config["needs_key"])
            self.assertEqual(config["key"], "")
            with self.assertRaises(ValueError):
                self.store.save_provider(provider, dict(enabled=True, search_backend="serpapi"))
        with self.assertRaises(ValueError):
            self.store.save_provider("shodan", dict(search_backend="direct_html"))

    def test_existing_database_migration_retains_paid_config(self):
        self.store.save_provider("google", dict(key="fixture-key", enabled=True, search_backend="serpapi"))
        with self.store.db() as db:
            db.execute("ALTER TABLE providers DROP COLUMN search_backend")
        upgraded = Store(self.temp.name)
        configs = {p["id"]: p for p in upgraded.providers(secrets=True)}
        self.assertEqual(configs["google"]["search_backend"], "serpapi")
        self.assertEqual(configs["google"]["key"], "fixture-key")
        self.assertTrue(configs["google"]["enabled"])
        self.assertEqual(configs["baidu"]["search_backend"], "direct_html")
        self.assertEqual(len(upgraded.rules()), len(self.store.rules()))

    def test_collection_pagination_storage_no_key_or_result_fetch(self):
        for provider, html in [("google", GOOGLE), ("baidu", BAIDU)]:
            transport = FixtureTransport([html, "<p>Your search did not match any documents.</p>"])
            collector = Collectors(self.store, threading.Event(), transport)
            rule = dict(provider=provider, kind="brand", query="Acme", id=None)
            with patch.object(collector.stop, "wait", return_value=False) as wait:
                items, message = exhaust(collector.collect(rule, self.target, dict(pages=2, key="must-not-send", search_backend="direct_html")))
            self.assertIn("HTML", message)
            self.assertTrue(wait.called)
            for item in items:
                self.store.upsert_finding(self.target["id"], "real", provider, rule, item)
                self.assertEqual(item["evidence"]["collection_method"], "direct_html")
            self.assertEqual(len(transport.calls), 2)
            for index, (args, kwargs) in enumerate(transport.calls):
                self.assertEqual(urlsplit(args[1]).hostname, "www.google.com" if provider == "google" else "www.baidu.com")
                self.assertNotIn("must-not-send", args[1])
                params = parse_qs(urlsplit(args[1]).query)
                self.assertEqual(params["q" if provider == "google" else "wd"], ["Acme"])
                self.assertEqual(params["start" if provider == "google" else "pn"], [str(index * 10)])
                self.assertEqual(kwargs["response_format"], "html")

    def test_engine_stops_provider_after_challenge(self):
        self.store.save_provider("google", dict(enabled=True))
        transport = FixtureTransport(['<title>CAPTCHA</title>'])
        def factory(store, stop):
            collector = Collectors(store, stop, transport)
            collector.use_browser = False
            return collector
        engine = Engine(self.store, factory)
        run_id = engine.start("real")
        engine.worker.join(10)
        self.assertFalse(engine.worker.is_alive())
        with self.store.db() as db:
            steps = [dict(r) for r in db.execute("SELECT * FROM run_steps WHERE run_id=?", (run_id,))]
        self.assertEqual(steps[0]["status"], "blocked")
        self.assertTrue(all(s["status"] == "skipped" for s in steps[1:]))
        self.assertEqual(len(transport.calls), 1)

    def test_google_javascript_fallback_and_challenge(self):
        initial = '<meta content="0;url=/httpservice/retry/enablejs">'
        rule = dict(provider="google", kind="brand", query="Acme")
        for rendered, expected in [(GOOGLE, None), ('<title>CAPTCHA</title>', "blocked")]:
            transport = FixtureTransport([initial])
            collector = Collectors(self.store, threading.Event(), transport)
            with patch("app.collectors.render_search", return_value=rendered) as render, patch.object(collector.stop, "wait", return_value=False):
                if expected:
                    with self.assertRaises(CollectionError) as error:
                        exhaust(collector.collect(rule, self.target, dict(pages=1)))
                    self.assertEqual(error.exception.code, expected)
                else:
                    self.assertEqual(len(exhaust(collector.collect(rule, self.target, dict(pages=1)))[0]), 1)
                render.assert_called_once()

    def test_opaque_links_remain_low_confidence(self):
        from app.domain import web_finding
        item = dict(url="https://www.google.com/goto?url=opaque", title="Acme advisory",
                    description="https://www.cisa.gov · Acme advisory", display_url="https://www.cisa.gov › alerts")
        finding = web_finding(item, dict(kind="advisory"), self.target)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["confidence"], "low")
        self.assertTrue(finding["evidence"]["redirect_unresolved"])

    def test_transport_html_decode_and_request_budget(self):
        self.store.save_provider("baidu", dict(enabled=True, daily_limit=1))
        transport = Transport(self.store, threading.Event())
        class Response:
            headers = Message()
            headers["Content-Type"] = "text/html; charset=gb18030"
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit): return "中文摘要".encode("gb18030")
        with patch.object(transport.opener, "open", return_value=Response()):
            self.assertEqual(transport.fetch("baidu", "https://www.baidu.com/s?wd=test", response_format="html"), "中文摘要")
            with self.assertRaises(CollectionError) as error:
                transport.fetch("baidu", "https://www.baidu.com/s?wd=test", response_format="html")
            self.assertEqual(error.exception.code, "quota")


if __name__ == "__main__":
    unittest.main()
