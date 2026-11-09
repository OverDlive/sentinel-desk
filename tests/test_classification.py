import json
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.collectors import service_finding
from app.domain import web_finding
from app.store import Store
from test_monitor import target_data


class ClassificationTests(unittest.TestCase):
    def test_opaque_link_rotation_keeps_one_candidate_and_all_source_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            target = store.save_target(target_data())
            rule = dict(provider='baidu', kind='brand', query='Acme')
            findings = [web_finding(dict(url='https://www.baidu.com/link?url=' + token,
                        title='Acme news', description='Acme article on news.example.org'), rule, target) for token in ('one', 'two')]
            self.assertEqual(store.upsert_finding(target['id'], 'real', 'baidu', rule, findings[0]), (1, 0))
            self.assertEqual(store.upsert_finding(target['id'], 'real', 'baidu', rule, findings[1]), (0, 0))
            with store.db() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM findings').fetchone()[0], 1)
                self.assertEqual(db.execute('SELECT count(*) FROM sightings').fetchone()[0], 2)
                self.assertEqual(db.execute('SELECT url FROM findings').fetchone()[0], findings[1]['url'])

    def test_legacy_duplicates_merge_preserving_review_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            target = store.save_target(target_data())
            rule = dict(provider='baidu', kind='brand', query='Acme')
            for token in ('one', 'two'):
                finding = web_finding(dict(url='https://www.baidu.com/link?url=' + token,
                    title='Acme news', description='Acme article'), rule, target)
                finding['identity'] = 'url:' + finding['url']
                store.upsert_finding(target['id'], 'real', 'baidu', rule, finding)
            with store.db() as db:
                db.execute("INSERT INTO runs(mode,status,trigger,started_at,finished_at,new_count,result_count) VALUES('real','success','manual','2000','2999',2,2)")
                db.execute("UPDATE findings SET status='reviewing',owner='SOC',note='keep' WHERE id=(SELECT max(id) FROM findings)")
                settings = json.loads(db.execute('SELECT value FROM settings').fetchone()[0])
                settings.pop('search_identity_version')
                db.execute('UPDATE settings SET value=?', (json.dumps(settings),))
            result = store.repair_search_identities()
            self.assertEqual(result['merged'], 1)
            self.assertTrue(Path(result['backup']).exists())
            with store.db() as db:
                self.assertEqual(db.execute('SELECT status,owner,note FROM findings').fetchone()[:], ('reviewing', 'SOC', 'keep'))
                self.assertEqual(db.execute('SELECT count(*) FROM sightings').fetchone()[0], 2)
                self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0], 2)
                self.assertEqual(db.execute('SELECT count(*) FROM merged_findings').fetchone()[0], 1)
                self.assertEqual(db.execute('SELECT new_count FROM runs').fetchone()[0], 1)
                self.assertEqual(db.execute('SELECT original_new_count,corrected_new_count FROM run_count_corrections').fetchone()[:], (2, 1))
                self.assertFalse(db.execute('PRAGMA foreign_key_check').fetchall())
            self.assertEqual(store.repair_search_identities()['merged'], 0)

    def test_duplicate_repair_does_not_merge_conflicting_reviews(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            target = store.save_target(target_data())
            rule = dict(provider='baidu', kind='brand', query='Acme')
            for token in ('one', 'two'):
                finding = web_finding(dict(url='https://www.baidu.com/link?url=' + token,
                    title='Acme news', description='Acme article'), rule, target)
                finding['identity'] = 'url:' + finding['url']
                store.upsert_finding(target['id'], 'real', 'baidu', rule, finding)
            with store.db() as db:
                db.execute("UPDATE findings SET status='reviewing' WHERE id=(SELECT min(id) FROM findings)")
                db.execute("UPDATE findings SET status='confirmed' WHERE id=(SELECT max(id) FROM findings)")
                settings = json.loads(db.execute('SELECT value FROM settings').fetchone()[0])
                settings.pop('search_identity_version')
                db.execute('UPDATE settings SET value=?', (json.dumps(settings),))
            result = store.repair_search_identities()
            self.assertEqual((result['merged'], result['conflicts']), (0, 1))
            with store.db() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM findings').fetchone()[0], 2)

    def test_document_requires_resolved_document_url(self):
        target = target_data()
        for url, expected in [
            ('https://example.com/report.PDF?id=2', 'document'),
            ('https://example.com/report%2Epdf', 'document'),
            ('https://www.youtube.com/watch?v=1', 'brand'),
            ('https://example.com/board', 'brand'),
            ('https://example.com/report.pdf.html', 'brand'),
            ('https://example.com/board?search=report.pdf', 'brand'),
            ('https://www.google.com/goto?url=opaque', 'brand'),
        ]:
            with self.subTest(url=url):
                finding = web_finding(dict(url=url, title='Acme', description='',
                                           display_url='https://example.com/report.pdf'),
                                      dict(kind='document', provider='google'), target)
                self.assertEqual(finding['kind'], expected)

    def test_update_and_existing_data_repair_preserve_history(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            target = store.save_target(target_data())
            rule = dict(query='net:192.0.2.0/24')
            service = service_finding('192.0.2.10', dict(port=443), 'shodan')
            store.upsert_finding(target['id'], 'real', 'shodan', rule, service)
            service = service_finding('192.0.2.10', dict(port=443, vulns=['CVE-2020-11023']), 'shodan')
            store.upsert_finding(target['id'], 'real', 'shodan', rule, service)
            with store.db() as db:
                self.assertEqual(db.execute('SELECT confidence FROM findings').fetchone()[0], 'medium')
            item = dict(url='https://www.youtube.com/watch?v=1', title='Acme', description='Acme video')
            doc = web_finding(item, dict(kind='document', provider='google'), target)
            store.upsert_finding(target['id'], 'real', 'google', dict(query='Acme filetype:hwp'), doc)
            with store.db() as db:
                db.execute("UPDATE findings SET confidence='high' WHERE kind='service'")
                db.execute("UPDATE findings SET kind='document' WHERE kind='brand'")
                db.execute("UPDATE findings SET status='reviewing',owner='SOC',note='keep me'")
                settings = json.loads(db.execute('SELECT value FROM settings').fetchone()[0])
                settings.pop('classification_version')
                db.execute('UPDATE settings SET value=?', (json.dumps(settings),))
                before = [dict(r) for r in db.execute('SELECT * FROM findings ORDER BY id')]
                sightings = [tuple(r) for r in db.execute('SELECT * FROM sightings ORDER BY id')]
                events = [tuple(r) for r in db.execute('SELECT * FROM events ORDER BY id')]
            result = store.repair_classifications()
            self.assertEqual(result['updated'], 2)
            self.assertTrue(Path(result['backup']).is_file())
            with closing(sqlite3.connect(result['backup'])) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM findings WHERE kind='document'").fetchone()[0], 1)
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            with store.db() as db:
                after = [dict(r) for r in db.execute('SELECT * FROM findings ORDER BY id')]
                self.assertEqual([r['kind'] for r in after], ['service', 'brand'])
                self.assertEqual(after[0]['confidence'], 'medium')
                for old, new in zip(before, after):
                    for key in old.keys() - {'kind', 'confidence', 'reason'}:
                        self.assertEqual(old[key], new[key], key)
                self.assertEqual(sightings, [tuple(r) for r in db.execute('SELECT * FROM sightings ORDER BY id')])
                self.assertEqual(events, [tuple(r) for r in db.execute('SELECT * FROM events ORDER BY id')])
            self.assertEqual(store.repair_classifications()['updated'], 0)
            # A later observation can correct category/confidence/reason again.
            with store.db() as db:
                db.execute("UPDATE findings SET kind='document',confidence='high',reason='old reason' WHERE identity=?", (doc['identity'],))
            doc['reason'] = 'fresh evidence'
            store.upsert_finding(target['id'], 'real', 'google', dict(query='Acme filetype:hwp'), doc)
            with store.db() as db:
                self.assertEqual(db.execute("SELECT kind,confidence,reason FROM findings WHERE identity=?", (doc['identity'],)).fetchone()[:], ('brand', 'low', 'fresh evidence'))


if __name__ == '__main__':
    unittest.main()
