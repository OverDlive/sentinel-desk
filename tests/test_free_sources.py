"""Offline collection, quota, migration and evidence checks for free sources."""
import ipaddress
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from urllib.error import HTTPError
from urllib.parse import parse_qs, unquote, urlsplit
from unittest.mock import patch

from app.collectors import CollectionError, Collectors
from app.domain import web_finding
from app.engine import Engine
from app.store import Store
from app.vault import unseal
from test_monitor import FixtureTransport, exhaust, target_data


class Response:
    headers = Message()

    def __init__(self, data):
        self.data = data

    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, limit): return json.dumps(self.data).encode()


def host_response(ip):
    return dict(result=dict(resource=dict(ip=ip, services=[dict(port=443, protocol="HTTP",
        transport_protocol="tcp", scan_time="2026-10-01T12:00:00Z", vulns=["CVE-2024-3400"])])))


class FreeSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.target = self.store.save_target(target_data(cidrs=["192.0.2.0/30"]))
        self.rule = next(r for r in self.store.rules() if r["provider"] == "censys")
        self.config = dict(key="fixture-pat", censys_mode="lookup", lookup_limit=2, organization_id="do-not-send", pages=3)

    def collector(self, handler=None):
        collector = Collectors(self.store, threading.Event())
        calls = []
        def respond(request, **kwargs):
            calls.append(request)
            ip = unquote(urlsplit(request.full_url).path.rsplit("/", 1)[1])
            return Response(handler(ip) if handler else host_response(ip))
        mock = patch.object(collector.transport.opener, "open", side_effect=respond)
        mock.start()
        self.addCleanup(mock.stop)
        return collector, calls

    def test_keyless_defaults_and_required_pat(self):
        for provider in ("zoneh", "xssed"):
            self.store.save_provider(provider, dict(enabled=True))
            config = next(p for p in self.store.providers(secrets=True) if p["id"] == provider)
            self.assertFalse(config["needs_key"])
            self.assertTrue(config["browser_session"])
            self.assertEqual(config["key"], "")
            with self.assertRaises(ValueError):
                self.store.save_provider(provider, dict(enabled=True, search_backend="serpapi"))
        censys = next(p for p in self.store.providers() if p["id"] == "censys")
        self.assertEqual(censys["censys_mode"], "lookup")
        with self.assertRaises(ValueError):
            self.store.save_provider("censys", dict(enabled=True))

    def test_legacy_migration_keeps_paid_keys_and_preferences(self):
        self.store.save_provider("zoneh", dict(key="fixture-serp", enabled=True, search_backend="serpapi"))
        self.store.save_provider("censys", dict(key="fixture-pat", enabled=True, organization_id="saved-org"))
        self.store.toggle_rule(self.rule["id"], False)
        with self.store.db() as db:
            settings = self.store.settings()
            settings.pop("free_sources_version")
            db.execute("UPDATE settings SET value=?", (json.dumps(settings),))
            db.execute("UPDATE providers SET search_backend='serpapi' WHERE id='xssed'")
            db.execute("ALTER TABLE providers DROP COLUMN censys_mode")
        upgraded = Store(self.temp.name)
        configs = {p["id"]: p for p in upgraded.providers(secrets=True)}
        self.assertEqual(configs["zoneh"]["key"], "fixture-serp")
        self.assertEqual(configs["zoneh"]["search_backend"], "serpapi")
        self.assertTrue(configs["zoneh"]["enabled"])
        self.assertEqual(configs["xssed"]["search_backend"], "direct_html")
        self.assertFalse(configs["xssed"]["enabled"])
        self.assertEqual(configs["censys"]["censys_mode"], "search")
        self.assertEqual(configs["censys"]["organization_id"], "saved-org")
        self.assertFalse(next(r for r in upgraded.rules() if r["id"] == self.rule["id"])["enabled"])
        upgraded.save_provider("zoneh", dict(enabled=True, search_backend="direct_html"))
        with upgraded.db() as db:
            zoneh_secret = db.execute("SELECT secret FROM providers WHERE id='zoneh'").fetchone()[0]
        with patch("app.store.unseal", wraps=unseal) as decrypt:
            self.assertEqual(next(p for p in upgraded.providers(secrets=True) if p["id"] == "zoneh")["key"], "")
            self.assertNotIn(zoneh_secret, [call.args[0] for call in decrypt.call_args_list])

    def test_archive_html_filters_source_and_stores_provider(self):
        for provider, host in (("zoneh", "zone-h.org"), ("xssed", "xssed.com")):
            html = '<div id="search">' + ''.join(
                f'<div class="g"><a href="https://{source}/mirror/1"><h3>Acme report</h3></a><div class="VwiC3b">example.com</div></div>'
                for source in ("www." + host, host + ".evil.example", "unrelated.example")) + '</div>'
            transport = FixtureTransport([html])
            collector = Collectors(self.store, threading.Event(), transport)
            rule = next(r for r in self.store.rules() if r["provider"] == provider)
            findings, _ = exhaust(collector.collect(rule, self.target, dict(search_backend="direct_html", pages=1, key="never-send")))
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual(finding["evidence"]["search_engine"], "google")
            self.assertEqual(finding["evidence"]["collection_method"], "direct_html")
            self.assertIn("과거 신고", finding["evidence"]["classification"])
            self.store.upsert_finding(self.target["id"], "real", provider, rule, finding)
            self.assertEqual(self.store.findings("real", dict(provider=provider))["total"], 1)
            args, kwargs = transport.calls[0]
            self.assertEqual(args[0], provider)
            self.assertEqual(urlsplit(args[1]).hostname, "www.google.com")
            self.assertEqual(parse_qs(urlsplit(args[1]).query)["q"], [rule["query"]])
            self.assertNotIn("never-send", args[1] + json.dumps(kwargs))

    def test_unresolved_archive_redirect_requires_matching_display_host(self):
        rule = dict(provider="zoneh", kind="archive")
        item = dict(url="https://www.google.com/goto?url=opaque", title="Acme", description="example.com")
        self.assertIsNone(web_finding(item, rule, self.target))
        good = web_finding(dict(item, display_url="https://www.zone-h.org › mirror"), rule, self.target)
        self.assertEqual(good["confidence"], "low")
        self.assertTrue(good["evidence"]["redirect_unresolved"])
        self.assertIsNone(web_finding(dict(item, display_url="https://zone-h.org.evil.example/"), rule, self.target))

    def test_google_and_archives_share_browser_but_count_separately(self):
        collector = Collectors(self.store, threading.Event(), FixtureTransport([]))
        items = [dict(url="https://www.zone-h.org/mirror/1", title="Acme", description="example.com"),
                 dict(url="https://www.xssed.com/mirror/2", title="Acme", description="example.com")]
        with patch("app.collectors.SearchSession") as session, patch.object(collector.stop, "wait", return_value=False):
            session.return_value.results.return_value = (items, False)
            session.return_value.captcha_attempts = []
            for provider in ("google", "zoneh", "xssed"):
                rule = next(r for r in self.store.rules() if r["provider"] == provider)
                exhaust(collector.collect(rule, self.target, dict(search_backend="direct_html", browser_session=True, pages=1)))
            self.assertEqual(session.call_count, 1)
            self.assertEqual(session.call_args.args[1], "google")
            self.assertEqual(session.return_value.results.call_count, 3)
            configs = {p["id"]: p for p in self.store.providers()}
            self.assertEqual([configs[p]["used_today"] for p in ("google", "zoneh", "xssed")], [1, 1, 1])
            collector.close()
            session.return_value.close.assert_called_once()

    def test_shared_google_challenge_skips_both_archive_providers(self):
        for provider in ("zoneh", "xssed"):
            self.store.save_provider(provider, dict(enabled=True))
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
            steps = list(db.execute("SELECT * FROM run_steps WHERE run_id=? ORDER BY id", (run_id,)))
        self.assertEqual(steps[0]["status"], "blocked")
        self.assertTrue(all(s["status"] == "skipped" for s in steps[1:]))
        self.assertEqual(len(transport.calls), 1)

    def test_censys_rotates_persistently_and_reuses_cache(self):
        collector, calls = self.collector()
        first, note = exhaust(collector.collect(self.rule, self.target, self.config))
        self.assertIn("상한", note)
        self.assertEqual([f["evidence"]["ip"] for f in first], ["192.0.2.0", "192.0.2.1"])
        self.assertEqual(first[0]["observed_at"], "2026-10-01T12:00:00Z")
        self.assertEqual(first[0]["cves"], ["CVE-2024-3400"])
        self.store = Store(self.temp.name)
        second_collector, second_calls = self.collector()
        second, _ = exhaust(second_collector.collect(self.rule, self.target, self.config))
        self.assertEqual([f["evidence"]["ip"] for f in second], ["192.0.2.2", "192.0.2.3"])
        third, _ = exhaust(second_collector.collect(self.rule, self.target, self.config))
        self.assertTrue(all(f["evidence"]["cache_hit"] for f in third))
        self.assertEqual(len(calls) + len(second_calls), 4)
        for request in calls + second_calls:
            self.assertNotIn("organization_id", request.full_url)
            self.assertEqual(request.get_header("Authorization"), "Bearer fixture-pat")
            self.assertEqual(request.get_header("Accept"), "application/vnd.censys.api.v3.host.v1+json")
        self.assertNotIn("fixture-pat", json.dumps(first))

    def test_censys_monthly_budget_is_atomic_and_preserves_resume_position(self):
        self.store.save_provider("censys", dict(monthly_limit=2))
        collector, calls = self.collector()
        iterator = collector.collect(self.rule, self.target, dict(self.config, lookup_limit=4))
        self.assertEqual(next(iterator)["evidence"]["ip"], "192.0.2.0")
        self.assertEqual(next(iterator)["evidence"]["ip"], "192.0.2.1")
        with self.assertRaises(CollectionError) as error:
            next(iterator)
        self.assertEqual(error.exception.code, "quota")
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.store.censys_cursor(self.target["id"], "192.0.2.0/30"), 2)
        with ThreadPoolExecutor(max_workers=6) as pool:
            self.assertEqual(sum(pool.map(lambda _: self.store.claim_request("censys", operation="lookup"), range(12))), 0)
        self.assertTrue(self.store.claim_request("censys"))  # Paid search has a separate budget.
        with self.store.db() as db:
            db.execute("UPDATE requests SET created_at='2000-01-01T00:00:00+00:00'")
        self.assertTrue(self.store.claim_request("censys", operation="lookup"))

    def test_censys_404_is_cached_and_not_reported_as_a_vulnerability(self):
        def missing(ip):
            raise HTTPError("https://api.platform.censys.io/", 404, "not found", {}, None)
        collector, calls = self.collector(missing)
        config = dict(self.config, lookup_limit=4)
        findings, note = exhaust(collector.collect(self.rule, self.target, config))
        self.assertEqual(findings, [])
        self.assertIn("미관측(404) 4개", note)
        self.assertNotIn("상한", note)
        exhaust(collector.collect(self.rule, self.target, config))
        self.assertEqual(len(calls), 4)

    def test_censys_errors_do_not_advance_or_retry_chargeable_requests(self):
        for status, code in ((401, "auth"), (403, "auth"), (402, "quota"), (429, "rate_limited"), (500, "error")):
            def fail(ip):
                raise HTTPError("https://api.platform.censys.io/?fixture-pat", status, "fixture-pat", {}, None)
            collector, calls = self.collector(fail)
            with self.assertRaises(CollectionError) as error:
                exhaust(collector.collect(self.rule, self.target, self.config))
            self.assertEqual(error.exception.code, code)
            self.assertNotIn("fixture-pat", str(error.exception))
            self.assertEqual(len(calls), 1)
            self.assertEqual(self.store.censys_cursor(self.target["id"], "192.0.2.0/30"), 0)
        for data in (None, {}, dict(result=dict(resource=dict(ip="198.51.100.1", services=[])))):
            collector, _ = self.collector(lambda ip: data)
            with self.assertRaises(CollectionError) as error:
                exhaust(collector.collect(self.rule, self.target, self.config))
            self.assertEqual(error.exception.code, "schema")
        collector, calls = self.collector()
        collector.stop.set()
        with self.assertRaises(CollectionError) as error:
            exhaust(collector.collect(self.rule, self.target, self.config))
        self.assertEqual(error.exception.code, "cancelled")
        self.assertEqual(calls, [])

    def test_censys_cache_expires_and_is_separate_for_each_pat(self):
        collector, calls = self.collector()
        config = dict(self.config, lookup_limit=4)
        exhaust(collector.collect(self.rule, self.target, config))
        exhaust(collector.collect(self.rule, self.target, dict(config, key="another-pat")))
        self.assertEqual(len(calls), 8)
        with self.store.db() as db:
            db.execute("UPDATE censys_host_cache SET fetched_at='2000-01-01T00:00:00+00:00'")
        findings, _ = exhaust(collector.collect(self.rule, self.target, config))
        self.assertEqual(len(calls), 12)
        self.assertTrue(all(not f["evidence"]["cache_hit"] for f in findings))

    def test_censys_large_ipv6_scope_is_bounded_and_cannot_escape_target(self):
        target = self.store.save_target(target_data(cidrs=["2001:db8::/32"]))
        rule = next(r for r in self.store.rules() if r["target_id"] == target["id"] and r["provider"] == "censys")
        self.store.censys_cursor(target["id"], "2001:db8::/32", 2 ** 80)
        collector, calls = self.collector()
        findings, _ = exhaust(collector.collect(rule, target, self.config))
        expected = str(ipaddress.ip_network("2001:db8::/32")[2 ** 80])
        self.assertEqual(findings[0]["evidence"]["ip"], expected)
        self.assertEqual(len(calls), 2)
        with self.assertRaises(CollectionError):
            exhaust(collector.collect(dict(rule, query='host.ip: "8.8.8.8/32"'), target, self.config))
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
