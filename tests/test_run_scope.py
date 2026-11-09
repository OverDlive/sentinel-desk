import csv
import json
from pathlib import Path
import tempfile
import unittest

from app.collectors import service_finding
from app.engine import Engine
from app.reporting import export_csv
from app.store import Store
from test_monitor import target_data


class RunScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.target = self.store.save_target(target_data())
        self.rule = dict(query='net:192.0.2.0/24')

    def run_record(self, mode='real', start='2026-01-01', end='2026-01-02', index='exact'):
        with self.store.db() as db:
            return db.execute("INSERT INTO runs(mode,status,trigger,started_at,finished_at,result_index) VALUES (?,'success','manual',?,?,?)", (mode, start, end, index)).lastrowid

    def test_run_membership_snapshot_filters_and_csv(self):
        first, second, empty = (self.run_record() for _ in range(3))
        low = service_finding('192.0.2.10', dict(port=443, product='old'), 'shodan')
        self.store.upsert_finding(self.target['id'], 'real', 'shodan', self.rule, low, run_id=first)
        high = service_finding('192.0.2.10', dict(port=443, product='new', vulns=['CVE-2020-11023']), 'shodan')
        self.store.upsert_finding(self.target['id'], 'real', 'shodan', self.rule, high, run_id=second)
        page = self.store.findings('real', dict(run_id=first, severity='low', provider='shodan'))
        self.assertEqual(page['total'], 1)
        self.assertEqual(page['items'][0]['title'], low['title'])
        self.assertEqual(page['items'][0]['run_label'], '이번 신규')
        self.assertEqual(self.store.findings('real', dict(run_id=first, severity='high'))['total'], 0)
        self.assertEqual(self.store.findings('real', dict(run_id=second))['items'][0]['run_label'], '내용 변경')
        self.assertEqual(self.store.findings('real', dict(run_id=empty))['total'], 0)
        self.assertEqual(self.store.findings('demo', dict(run_id=first))['total'], 0)
        self.assertEqual(self.store.findings('real', dict(run_id=-1))['total'], 0)
        self.assertEqual(self.store.run_summary('real', second)['indexed_changed'], 1)
        finding_id = page['items'][0]['id']
        self.store.update_finding(finding_id, 'reviewing', 'SOC', 'current review')
        detail = self.store.detail(finding_id, run_id=first)
        self.assertEqual((detail['title'], detail['status'], detail['owner']), (low['title'], 'reviewing', 'SOC'))
        self.assertEqual(detail['run_evidence']['cves'], [])
        path = Path(self.temp.name) / 'run.csv'
        self.assertEqual(export_csv(self.store, path, 'real', dict(run_id=first)), 1)
        with path.open(encoding='utf-8-sig', newline='') as stream:
            rows = list(csv.reader(stream))
        self.assertEqual(rows[0][1:3], ['실행 번호', '해당 실행에서'])
        self.assertEqual(rows[1][1:3], [str(first), '이번 신규'])

    def test_repeated_multisource_result_is_one_member(self):
        run_id = self.run_record()
        finding = service_finding('192.0.2.10', dict(port=443), 'shodan')
        for source in ('shodan', 'censys', 'shodan'):
            self.store.upsert_finding(self.target['id'], 'real', source, self.rule, finding, run_id=run_id)
        summary = self.store.run_summary('real', run_id)
        self.assertEqual((summary['unique_count'], summary['indexed_new']), (1, 1))
        self.assertEqual(self.store.findings('real', dict(run_id=run_id, provider='censys'))['total'], 1)
        following = self.run_record()
        self.store.upsert_finding(self.target['id'], 'real', 'shodan', self.rule, finding, run_id=following)
        self.assertEqual(self.store.findings('real', dict(run_id=following))['items'][0]['run_label'], '기존 재수집')

    def test_legacy_reconstruction_does_not_fill_unproven_intermediate_runs(self):
        first = self.run_record(start='2026-01-01', end='2026-01-02', index='legacy')
        middle = self.run_record(start='2026-02-01', end='2026-02-02', index='legacy')
        last = self.run_record(start='2026-03-01', end='2026-03-02', index='legacy')
        finding = service_finding('192.0.2.10', dict(port=443), 'shodan')
        self.store.upsert_finding(self.target['id'], 'real', 'shodan', self.rule, finding)
        with self.store.db() as db:
            db.execute("UPDATE findings SET first_seen='2026-01-01T01:00:00'")
            db.execute("UPDATE sightings SET first_seen='2026-01-01T01:00:00',last_seen='2026-03-01T01:00:00'")
            settings = json.loads(db.execute('SELECT value FROM settings').fetchone()[0])
            settings.pop('run_index_version')
            db.execute('UPDATE settings SET value=?', (json.dumps(settings),))
        upgraded = Store(self.temp.name)
        self.assertEqual(upgraded.findings('real', dict(run_id=first, provider='shodan'))['total'], 1)
        self.assertEqual(upgraded.findings('real', dict(run_id=middle))['total'], 0)
        self.assertEqual(upgraded.findings('real', dict(run_id=last))['total'], 1)
        self.assertEqual(upgraded.run_summary('real', middle)['result_index'], 'legacy')

    def test_engine_records_demo_run_members(self):
        engine = Engine(self.store)
        engine.seed_demo()
        run_id = engine.start('demo')
        engine.worker.join(10)
        self.assertFalse(engine.worker.is_alive())
        self.assertEqual(self.store.findings('demo', dict(run_id=run_id))['total'], 10)
        self.assertEqual(self.store.run_summary('demo', run_id)['result_index'], 'exact')
        engine.close()

    def test_one_provider_cannot_hide_another_providers_risk_in_same_run(self):
        run_id = self.run_record()
        high = service_finding('192.0.2.10', dict(port=443, vulns=['CVE-2020-11023']), 'shodan')
        low = service_finding('192.0.2.10', dict(port=443), 'censys')
        self.store.upsert_finding(self.target['id'], 'real', 'shodan', self.rule, high, run_id=run_id)
        self.store.upsert_finding(self.target['id'], 'real', 'censys', self.rule, low, run_id=run_id)
        row = self.store.findings('real', dict(run_id=run_id))['items'][0]
        self.assertEqual((row['severity'], row['confidence'], row['cves']), ('high', 'medium', ['CVE-2020-11023']))
        self.assertEqual(row['sources'], ['censys', 'shodan'])
