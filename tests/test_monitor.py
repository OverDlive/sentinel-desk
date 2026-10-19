import csv
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch
from urllib.error import HTTPError

from app.collectors import CollectionError, Collectors, Transport, SameHostRedirect, service_finding
from app.domain import canonical_url, compile_rules, host_matches, validate_target, web_finding
from app.engine import Engine
from app.reporting import export_csv, safe_cell
from app.store import Store
from app.vault import seal, unseal


def target_data(**changes):
    return {**dict(name="Test Org", domains=["example.com"], keywords=["Acme"], cidrs=["192.0.2.0/24"],
                products=[], cves=["CVE-2024-3400"], owner="SOC", enabled=True), **changes}


class FixtureTransport:
    def __init__(self, responses):
        self.responses, self.calls = iter(responses), []

    def fetch(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        value = next(self.responses)
        if isinstance(value, Exception):
            raise value
        return value


def exhaust(iterator):
    results = []
    while True:
        try:
            results.append(next(iterator))
        except StopIteration as end:
            return results, end.value


class DomainTests(unittest.TestCase):
    def test_complete_image_rule_coverage(self):
        target = validate_target(target_data(name="중부발전", domains=["komipo.co.kr"],
            keywords=["komipo", "중부발전"], cidrs=["219.252.41.0/25", "124.136.8.0/25"]))
        rules = compile_rules(target)
        queries = {(r['provider'], r['query']) for r in rules}
        for scope in ('komipo.co.kr', 'komipo'):
            for ext in 'conf cnf reg inf rdp cfg txt ora ini bak xls xlsx ppt pptx doc docx hwp pdf'.split():
                self.assertIn(('google', f'site:{scope} filetype:{ext}'), queries)
        for ext in 'xls xlsx ppt pptx doc docx hwp pdf'.split():
            self.assertIn(('google', f'intitle:"중부발전" filetype:{ext}'), queries)
        for term in ('komipo', '중부발전'):
            self.assertIn(('google', f'site:pastebin.com "{term}"'), queries)
            self.assertIn(('zoneh', f'site:zone-h.org "{term}"'), queries)
            self.assertIn(('xssed', f'site:xssed.com "{term}"'), queries)
        self.assertIn(('baidu', '"@komipo.co.kr"'), queries)
        self.assertIn(('baidu', '"중부발전" "@komipo.co.kr"'), queries)
        for cidr in target['cidrs']:
            self.assertIn(('shodan', f'net:{cidr}'), queries)
            self.assertIn(('censys', f'host.ip: "{cidr}"'), queries)
        for path in ('alerts', 'analysis-reports'):
            self.assertIn(('google', f'site:us-cert.cisa.gov/ncas/{path} "komipo"'), queries)
            self.assertIn(('google', f'site:cisa.gov/news-events/{path} "komipo"'), queries)
        self.assertIn(('google', 'site:cisa.gov/news-events/cybersecurity-advisories "komipo"'), queries)
        self.assertTrue(any(r['provider'] == 'phishtank' for r in rules))
        self.assertEqual(len(rules), len({(r['provider'], r['kind'], r['query']) for r in rules}))

    def test_advisory_relevance_and_paste_source_boundary(self):
        target = validate_target(target_data(products=['Example Product']))
        rule = dict(kind='advisory')
        item = dict(url='https://www.cisa.gov/news-events/alerts/test',
                    title='Example Product CVE-2024-9999', description='Security update')
        finding = web_finding(item, rule, target)
        self.assertEqual(finding['cves'], ['CVE-2024-9999'])
        self.assertEqual(finding['severity'], 'info')
        self.assertIsNone(web_finding(dict(item, url='https://cisa.gov.evil.example/a'), rule, target))
        self.assertIsNone(web_finding(dict(item, title='Unrelated product'), rule, target))
        self.assertIsNone(web_finding(dict(url='https://pastebin.com.evil.example/', title='Acme'), dict(kind='paste'), target))
        self.assertIsNotNone(web_finding(dict(url='https://pastebin.com/a', title='Email @example.com'), dict(kind='paste'), target))

    def test_target_validation_and_cidr_normalization(self):
        data = target_data()
        data["domains"] = "EXAMPLE.COM, example.com"
        data["cidrs"] = "192.0.2.9/24"
        t = validate_target(data)
        self.assertEqual(t["domains"], ["example.com"])
        self.assertEqual(t["cidrs"], ["192.0.2.0/24"])

    def test_invalid_targets(self):
        for field, bad in [("domains", ["https://example.com"]), ("domains", ['example.com site:other.com']),
                           ("cidrs", ["999.1.1.1"]), ("cves", ["CVE-fake"]), ("keywords", [2])]:
            data = target_data()
            data[field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                validate_target(data)

    def test_rule_mapping_and_cenql(self):
        rules = compile_rules(validate_target(target_data()))
        self.assertIn('host.ip: "192.0.2.0/24"', [r["query"] for r in rules])
        self.assertIn("site:example.com filetype:bak", [r["query"] for r in rules])
        self.assertTrue(all(r["source_row"] for r in rules))

    def test_domain_boundary_prevents_false_attribution(self):
        self.assertTrue(host_matches("portal.example.com", ["example.com"]))
        self.assertFalse(host_matches("example.com.attacker.net", ["example.com"]))
        finding = web_finding(dict(url="https://example.com.attacker.net/a", title="Unrelated", description=""),
                              dict(kind="config"), validate_target(target_data()))
        self.assertIsNone(finding)

    def test_url_dedup_preserves_query(self):
        self.assertEqual(canonical_url("https://EXAMPLE.com:443/A?a=1#x"), "https://example.com/A?a=1")
        self.assertNotEqual(canonical_url("https://example.com/A?a=1"), canonical_url("https://example.com/A?a=2"))
        for value in ["javascript:alert(1)", "file:///etc/passwd", "https://user:pass@example.com"]:
            with self.assertRaises(ValueError):
                canonical_url(value)


class StoreFixture(unittest.TestCase):
    def setUp(self):
        base = Path("test-artifacts")
        base.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.store = Store(self.temp.name)
        self.target = self.store.save_target(target_data())
        self.rule = dict(query="net:192.0.2.0/24", kind="service")
        self.finding = service_finding("192.0.2.10", dict(port=443, product="nginx", vulns=["CVE-2021-23017"]), "shodan", "2026-10-16")

    def tearDown(self):
        self.temp.cleanup()


class StoreTests(StoreFixture):
    def test_keys_are_encrypted_and_never_returned(self):
        secret = "test-key-private-value"
        self.store.save_provider("brave", dict(key=secret, enabled=True))
        self.assertTrue(next(p for p in self.store.providers() if p["id"] == "brave")["has_key"])
        self.assertNotIn(secret, json.dumps(self.store.providers()))
        with self.store.db() as db:
            stored = db.execute("SELECT secret FROM providers WHERE id='brave'").fetchone()[0]
        self.assertNotIn(secret, stored)
        self.assertEqual(unseal(stored), secret)
        self.store.save_provider("brave", dict(key="", enabled=True))
        self.assertEqual(next(p for p in self.store.providers(secrets=True) if p["id"] == "brave")["key"], secret)
        self.store.save_provider("brave", dict(clear_key=True, enabled=False))
        self.assertFalse(next(p for p in self.store.providers() if p["id"] == "brave")["has_key"])

    def test_provider_key_requirement(self):
        for provider in ("brave", "shodan", "censys", "phishtank", "google", "baidu", "zoneh", "xssed"):
            with self.assertRaises(ValueError):
                self.store.save_provider(provider, dict(enabled=True, search_backend="serpapi"))
        self.store.save_provider("cisa", dict(enabled=True))

    def test_search_rule_upgrade_preserves_preferences_and_history(self):
        self.store.upsert_finding(self.target["id"], "real", "shodan", self.rule, self.finding)
        with self.store.db() as db:
            settings = self.store.settings()
            settings.pop("search_rules_version")
            db.execute("UPDATE settings SET value=?", (json.dumps(settings),))
            db.execute("UPDATE rules SET enabled=0,last_run='2026-10-01' WHERE provider='brave'")
            db.execute("DELETE FROM rules WHERE provider IN ('google','baidu','zoneh','xssed')")
            db.execute("""INSERT INTO rules(target_id,provider,kind,query,label,source_row,enabled)
                          VALUES (?,'zoneh','manual','Test Org','old','Zone-H',0)""", (self.target["id"],))
        upgraded = Store(self.temp.name)
        rules = upgraded.rules()
        self.assertTrue(all(not r["enabled"] for r in rules if r["provider"] == 'brave'))
        self.assertTrue(all(r["last_run"] == '2026-10-01' for r in rules if r["provider"] == 'brave' and r['kind'] != 'advisory'))
        self.assertTrue(all(not r["enabled"] for r in rules if r["provider"] == 'zoneh'))
        self.assertEqual({r['provider'] for r in rules}, {'brave','google','baidu','zoneh','xssed','shodan','censys','phishtank','cisa'})
        self.assertFalse(any(r['kind'] == 'manual' for r in rules))
        self.assertEqual(upgraded.findings('real')['total'], 1)
        self.assertFalse(any(p['enabled'] for p in upgraded.providers()))
        self.assertEqual(len(Store(self.temp.name).rules()), len(rules))

    def test_version_two_adds_missing_rules_without_reenabling_old_rules(self):
        old_rules = self.store.rules()
        keep = next(r for r in old_rules if r['provider'] == 'google' and r['kind'] == 'config')
        with self.store.db() as db:
            settings = self.store.settings()
            settings['search_rules_version'] = 1
            db.execute('UPDATE settings SET value=?', (json.dumps(settings),))
            db.execute("DELETE FROM rules WHERE kind='advisory' AND provider IN ('brave','google')")
            db.execute("DELETE FROM rules WHERE provider='baidu' AND source_row LIKE '%이메일%'")
            db.execute("UPDATE rules SET enabled=0,last_run='2026-10-01' WHERE id=?", (keep['id'],))
        upgraded = Store(self.temp.name)
        preserved = next(r for r in upgraded.rules() if r['id'] == keep['id'])
        self.assertEqual((preserved['enabled'], preserved['last_run']), (0, '2026-10-01'))
        self.assertEqual(len(upgraded.rules()), len(compile_rules(self.target)))
        self.assertEqual(upgraded.settings()['search_rules_version'], 2)
        self.assertEqual(len(Store(self.temp.name).rules()), len(upgraded.rules()))

    def test_dpapi_roundtrip(self):
        self.assertEqual(unseal(seal("비밀 API key")), "비밀 API key")

    def test_dedup_and_status_preserved(self):
        self.assertEqual(self.store.upsert_finding(self.target["id"], "real", "shodan", self.rule, self.finding), (1, 0))
        item = self.store.findings("real")["items"][0]
        self.store.update_finding(item["id"], "resolved", "SOC", "검토 완료")
        self.assertEqual(self.store.upsert_finding(self.target["id"], "real", "shodan", self.rule, self.finding), (0, 0))
        changed = dict(self.finding, evidence=dict(self.finding["evidence"], version="new"))
        self.assertEqual(self.store.upsert_finding(self.target["id"], "real", "shodan", self.rule, changed), (0, 1))
        result = self.store.detail(item["id"])
        self.assertEqual(result["status"], "resolved")
        self.assertEqual(len(result["sightings"]), 2)
        self.assertEqual(result["change_count"], 1)
        self.assertTrue(any("검토 저장" in e["message"] for e in result["events"]))

    def test_multi_source_and_mode_separation(self):
        for provider in ("shodan", "censys"):
            self.store.upsert_finding(self.target["id"], "real", provider, self.rule, self.finding)
        self.store.upsert_finding(self.target["id"], "demo", "shodan", self.rule, self.finding)
        self.assertEqual(self.store.findings("real")["total"], 1)
        self.assertEqual(self.store.findings("demo")["total"], 1)
        self.assertEqual(set(self.store.findings("real")["items"][0]["sources"]), {"censys", "shodan"})

    def test_budget_atomic_under_concurrent_access(self):
        self.store.save_provider("cisa", dict(daily_limit=3, enabled=True))
        results = []
        threads = [threading.Thread(target=lambda: results.append(self.store.claim_request("cisa"))) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(results), 3)

    def test_target_update_preserves_rule_preferences(self):
        rule = self.store.rules()[0]
        self.store.toggle_rule(rule["id"], False)
        self.store.save_target(target_data(), self.target["id"])
        rule = next(r for r in self.store.rules() if r["query"] == rule["query"] and r["provider"] == rule["provider"])
        self.assertEqual(rule["enabled"], 0)

    def test_delete_cascades_results_and_evidence(self):
        self.store.upsert_finding(self.target["id"], "real", "shodan", self.rule, self.finding)
        self.store.delete_target(self.target["id"])
        self.assertEqual(self.store.findings("real")["total"], 0)
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM sightings").fetchone()[0], 0)

    def test_csv_filtered_and_formula_protected(self):
        finding = dict(self.finding, title="=HYPERLINK(1)")
        self.store.upsert_finding(self.target["id"], "real", "shodan", self.rule, finding)
        path = Path(self.temp.name) / "report.csv"
        self.assertEqual(export_csv(self.store, path, "real", {"severity": "high"}), 1)
        content = path.read_text(encoding="utf-8-sig")
        rows = list(csv.reader(io.StringIO(content)))
        self.assertTrue(rows[1][3].startswith("'="))
        self.assertEqual(export_csv(self.store, path, "real", {"severity": "info"}), 0)
        self.assertEqual(safe_cell("  @SUM(1)"), "'  @SUM(1)")


class CollectorTests(StoreFixture):
    # Inherit setup only; independent collector cases reuse a real SQLite store.
    def collector(self, responses):
        transport = FixtureTransport(responses)
        return Collectors(self.store, threading.Event(), transport), transport

    def config(self, pages=1):
        return dict(key="fixture-secret", pages=pages, organization_id="", search_backend="serpapi")

    def test_serpapi_engine_pagination_and_credential_destination(self):
        for provider in ('google', 'baidu'):
            with self.subTest(provider=provider):
                collector, transport = self.collector([
                    dict(search_metadata=dict(status='Success'), organic_results=[
                        dict(link='https://example.com/a.bak', title='Backup', snippet='file')],
                        serpapi_pagination=dict(next='https://evil.example/?api_key=do-not-follow')),
                    dict(search_metadata=dict(status='Success'), organic_results=[])])
                rule = dict(provider=provider, query='site:example.com filetype:bak', kind='config')
                items, _ = exhaust(collector.collect(rule, self.target, self.config(2)))
                self.assertEqual(len(items), 1)
                self.assertEqual(items[0]['severity'], 'high')
                self.assertEqual(items[0]['evidence']['search_engine'], provider)
                self.assertNotIn('fixture-secret', json.dumps(items))
                for index, (args, _) in enumerate(transport.calls):
                    parsed = urlsplit(args[1])
                    self.assertEqual(parsed.netloc, 'serpapi.com')
                    params = parse_qs(parsed.query)
                    self.assertEqual(params['engine'], [provider])
                    self.assertEqual(params['api_key'], ['fixture-secret'])
                    self.assertEqual(params['pn' if provider == 'baidu' else 'start'], [str(index * 10)])

    def test_serpapi_archive_restricts_host_and_matches_domain_in_snippet(self):
        for provider, host in [('zoneh', 'zone-h.org'), ('xssed', 'xssed.com')]:
            collector, _ = self.collector([dict(search_metadata=dict(status='Success'), organic_results=[
                dict(link=f'https://www.{host}/mirror/1', title='Report', snippet='portal.example.com'),
                dict(link=f'https://{host}.evil.example/mirror/2', title='Acme', snippet='example.com'),
                dict(link=f'https://{host}/mirror/3', title='Other org', snippet='unrelated.org')])])
            rule = next(r for r in compile_rules(self.target) if r['provider'] == provider)
            items, _ = exhaust(collector.collect(rule, self.target, self.config()))
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]['kind'], 'archive')
            self.assertEqual(items[0]['severity'], 'info')
            self.assertIn('현재', items[0]['reason'])

    def test_serpapi_zero_error_schema_and_page_limit(self):
        rule = dict(provider='google', query='Acme', kind='brand')
        for response in [dict(search_metadata=dict(status='Success'), organic_results=[]),
                         dict(search_metadata=dict(status='Success'), error="Google hasn't returned any results for this query.")]:
            collector, _ = self.collector([response])
            self.assertEqual(exhaust(collector.collect(rule, self.target, self.config()))[0], [])
        for response in [{}, dict(search_metadata=dict(status='Success')),
                         dict(search_metadata=dict(status='Success'), organic_results={}),
                         dict(search_metadata=dict(status='Success'), organic_results=[None]),
                         dict(search_metadata=dict(status='Error'), error='fixture-secret'),
                         dict(search_metadata=dict(status='Processing'))]:
            collector, _ = self.collector([response])
            with self.assertRaises(CollectionError) as caught:
                exhaust(collector.collect(rule, self.target, self.config()))
            self.assertNotIn('fixture-secret', str(caught.exception))
        collector, _ = self.collector([dict(search_metadata=dict(status='Success'), organic_results=[
            dict(link='https://example.com/', title='Acme')], serpapi_pagination=dict(next='next'))])
        self.assertIn('상한', exhaust(collector.collect(rule, self.target, self.config()))[1])

    def test_brave_scoping_and_pagination(self):
        collector, transport = self.collector([
            dict(query=dict(more_results_available=True), web=dict(results=[dict(url="https://example.com/a.bak", title="Settings", description="") ])),
            dict(query=dict(more_results_available=False), web=dict(results=[dict(url="https://unrelated.net/", title="no", description="") ])),
        ])
        items, message = exhaust(collector.collect(dict(provider="brave", query="site:example.com filetype:bak", kind="config"), self.target, self.config(2)))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["severity"], "high")
        self.assertIn("offset=1", transport.calls[1][0][1])

    def test_brave_valid_zero_vs_invalid_response(self):
        collector, _ = self.collector([dict(query=dict(more_results_available=False))])
        items, _ = exhaust(collector.collect(dict(provider="brave", query="q", kind="brand"), self.target, self.config()))
        self.assertEqual(items, [])
        collector, _ = self.collector([dict(error="invalid")])
        with self.assertRaises(CollectionError):
            exhaust(collector.collect(dict(provider="brave", query="q", kind="brand"), self.target, self.config()))

    def test_shodan_scopes_ip_and_reports_cve(self):
        collector, _ = self.collector([dict(total=2, matches=[dict(ip_str="192.0.2.5", port=443, product="nginx", vulns={"CVE-2021-23017": {}}),
                                                            dict(ip_str="198.51.100.1", port=22)])])
        items, _ = exhaust(collector.collect(dict(provider="shodan", query="net:192.0.2.0/24"), self.target, self.config()))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["cves"], ["CVE-2021-23017"])

    def test_censys_v3_schema_and_pagination(self):
        collector, transport = self.collector([
            dict(result=dict(hits=[dict(host_v1=dict(resource=dict(ip="192.0.2.8", services=[dict(port=443, protocol="HTTP")])))], next_page_token="next-token")),
            dict(result=dict(hits=[], next_page_token=""))])
        items, _ = exhaust(collector.collect(dict(provider="censys", query='host.ip: "192.0.2.0/24"'), self.target, self.config(2)))
        self.assertEqual(len(items), 1)
        self.assertEqual(transport.calls[1][1]["body"]["page_token"], "next-token")

    def test_phishing_only_verified_online_and_related(self):
        collector, _ = self.collector([[dict(url="https://acme.example.net/login", verified="yes", online="yes", phish_id=1),
                                       dict(url="https://acme.example.net/offline", verified="yes", online="no"),
                                       dict(url="https://unrelated.example.net/", verified="yes", online="yes")]])
        items, _ = exhaust(collector.collect(dict(provider="phishtank", query="match"), self.target, self.config()))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["kind"], "phishing")

    def test_phishing_name_only_target_matches_http_and_https(self):
        target = validate_target(target_data(name='UniqueOrg', domains=[], keywords=[]))
        collector, _ = self.collector([[dict(url=f'{scheme}://uniqueorg.example/login', verified='yes', online='yes')
                                       for scheme in ('http', 'https')]])
        rule = next(r for r in compile_rules(target) if r['provider'] == 'phishtank')
        self.assertEqual(len(exhaust(collector.collect(rule, target, self.config()))[0]), 2)

    def test_cisa_matches_registered_and_observed_cves(self):
        self.store.upsert_finding(self.target["id"], "real", "shodan", self.rule, self.finding)
        collector, _ = self.collector([dict(catalogVersion="test", vulnerabilities=[dict(cveID="CVE-2024-3400", vulnerabilityName="registered"),
            dict(cveID="CVE-2021-23017", vulnerabilityName="observed"), dict(cveID="CVE-2024-99999", vulnerabilityName="unrelated")])])
        items, _ = exhaust(collector.collect(dict(provider="cisa", query="KEV"), self.target, self.config()))
        self.assertEqual({x["asset"] for x in items}, {"CVE-2024-3400", "CVE-2021-23017"})

    def test_feed_cache_reused_across_collectors(self):
        collector, transport = self.collector([dict(vulnerabilities=[])])
        collector.feed("cisa", self.config())
        second, empty_transport = self.collector([])
        self.assertEqual(second.feed("cisa", self.config()), dict(vulnerabilities=[]))
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(len(empty_transport.calls), 0)

    def test_error_redacts_credentials_and_blocks_429(self):
        self.store.save_provider("shodan", dict(key="fake", enabled=True))
        transport = Transport(self.store, threading.Event())
        class Opener:
            def open(self, *args, **kwargs):
                raise HTTPError("https://provider/?key=super-secret", 429, "secret in body", {}, None)
        transport.opener = Opener()
        with self.assertRaises(CollectionError) as caught:
            transport.fetch("shodan", "https://api.shodan.io/test?key=super-secret")
        self.assertEqual(caught.exception.code, "rate_limited")
        self.assertNotIn("super-secret", str(caught.exception))

    def test_cross_host_redirect_rejected(self):
        from urllib.request import Request
        redirect = SameHostRedirect()
        with self.assertRaises(CollectionError):
            redirect.redirect_request(Request("https://api.shodan.io/x?key=secret"), None, 302, "", {}, "https://evil.example/x")


class EngineTests(StoreFixture):
    def test_scheduler_runs_when_due_and_respects_saved_interval(self):
        self.store.save_provider("cisa", dict(enabled=True))
        self.store.save_settings(dict(schedule_enabled=True, interval_minutes=15))
        class ZeroCollector:
            def __init__(self, *args): pass
            def collect(self, *args):
                yield from []
        engine = Engine(self.store, ZeroCollector)
        with patch.object(engine.shutdown, "wait", side_effect=[False, True]):
            engine._schedule_loop()
        engine.worker.join(timeout=5)
        runs = self.store.overview("real")["runs"]
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["trigger"], "schedule")
        self.assertTrue(self.store.settings()["last_scheduled_at"])
        # A newly started engine must respect the last persisted schedule timestamp.
        restarted = Engine(self.store, ZeroCollector)
        with patch.object(restarted.shutdown, "wait", side_effect=[False, True]):
            restarted._schedule_loop()
        self.assertEqual(len(self.store.overview("real")["runs"]), 1)

    def test_scheduler_disabled_performs_no_collection(self):
        engine = Engine(self.store)
        with patch.object(engine.shutdown, "wait", side_effect=[False, True]), patch.object(engine, "start") as start:
            engine._schedule_loop()
        start.assert_not_called()

    def test_single_process_per_data_directory(self):
        from main import InstanceLock
        lock = InstanceLock(Path(self.temp.name))
        try:
            with self.assertRaises(RuntimeError):
                InstanceLock(Path(self.temp.name))
        finally:
            lock.close()
        # The lock must be released cleanly when a process closes its handle.
        second = InstanceLock(Path(self.temp.name))
        second.close()

    def test_demo_never_calls_network(self):
        engine = Engine(self.store)
        engine.seed_demo()
        with patch("app.collectors.Transport.fetch", side_effect=AssertionError("network")):
            engine.start("demo")
            engine.worker.join(timeout=5)
        run = self.store.overview("demo")["runs"][0]
        self.assertEqual(run["status"], "success")
        self.assertGreaterEqual(self.store.findings("demo")["total"], 8)

    def test_real_zero_result_is_success(self):
        self.store.save_provider("cisa", dict(enabled=True))
        class ZeroCollector:
            def __init__(self, *args): pass
            def collect(self, *args):
                yield from []
                return "0건 검색 완료"
        engine = Engine(self.store, ZeroCollector)
        engine.start("real")
        engine.worker.join(timeout=5)
        run = self.store.overview("real")["runs"][0]
        self.assertEqual(run["status"], "success")
        self.assertEqual(run["result_count"], 0)

    def test_real_partial_retains_first_page(self):
        self.store.save_provider("cisa", dict(enabled=True))
        finding = self.finding
        class PartialCollector:
            def __init__(self, *args): pass
            def collect(self, *args):
                yield finding
                raise CollectionError("호출 제한", "rate_limited")
        engine = Engine(self.store, PartialCollector)
        engine.start("real")
        engine.worker.join(timeout=5)
        self.assertEqual(self.store.findings("real")["total"], 1)
        step = self.store.overview("real")["steps"][0]
        self.assertEqual(step["status"], "partial")
        self.assertEqual(self.store.overview("real")["runs"][0]["status"], "partial")

    def test_guard_and_lock(self):
        engine = Engine(self.store)
        with self.assertRaises(ValueError):
            engine.start("real")
        self.assertFalse(engine.lock.locked())
        engine.lock.acquire()
        with self.assertRaises(ValueError):
            engine.start("demo")
        engine.lock.release()

    def test_fair_rotation_with_one_rule_budget(self):
        self.store.save_provider("brave", dict(enabled=True, key="fixture-key"))
        self.store.save_provider("cisa", dict(enabled=True))
        self.store.save_settings(dict(max_queries_per_run=1))
        class ZeroCollector:
            def __init__(self, *args): pass
            def collect(self, *args):
                yield from []
        engine = Engine(self.store, ZeroCollector)
        for _ in range(2):
            engine.start("real")
            engine.worker.join(timeout=5)
        with self.store.db() as db:
            ids = [r[0] for r in db.execute("SELECT rule_id FROM run_steps")]
        self.assertEqual(len(set(ids)), 2)


if __name__ == "__main__":
    unittest.main()
