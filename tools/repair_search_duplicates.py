"""Back up and merge repeated opaque-link search evidence in an existing DB."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.store import Store


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    store = Store.__new__(Store)
    store.directory = args.directory.resolve()
    store.path = store.directory / 'sentinel.sqlite3'
    if not store.path.is_file():
        raise FileNotFoundError(store.path)
    with store.db() as db:
        if db.execute("SELECT count(*) FROM runs WHERE status='running'").fetchone()[0]:
            raise RuntimeError('수집 완료 후 다시 실행하세요.')
    result = store.repair_search_identities()
    with store.db() as db:
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert not db.execute('PRAGMA foreign_key_check').fetchall()
        if result['backup']:
            with closing(sqlite3.connect(Path(result['backup']).as_uri() + '?mode=ro', uri=True)) as old:
                old.row_factory = sqlite3.Row
                for table in ('targets', 'providers', 'rules', 'run_steps', 'requests'):
                    assert [tuple(r) for r in old.execute('SELECT * FROM ' + table + ' ORDER BY rowid')] == [tuple(r) for r in db.execute('SELECT * FROM ' + table + ' ORDER BY rowid')], table
                assert old.execute('SELECT count(*) FROM events').fetchone()[0] == db.execute('SELECT count(*) FROM events').fetchone()[0]
                assert old.execute('SELECT sum(count) FROM sightings').fetchone()[0] == db.execute('SELECT sum(count) FROM sightings').fetchone()[0]
                for row in old.execute('SELECT * FROM findings'):
                    current = db.execute('SELECT * FROM findings WHERE id=?', (row['id'],)).fetchone()
                    if current:
                        for key in ('status', 'owner', 'note'):
                            assert row[key] == current[key], (row['id'], key)
                    else:
                        archived = db.execute('SELECT original FROM merged_findings WHERE duplicate_id=?', (row['id'],)).fetchone()
                        assert json.loads(archived[0]) == dict(row)
        result['latest_run'] = dict(db.execute("SELECT id,new_count,result_count,status FROM runs WHERE mode='real' ORDER BY id DESC LIMIT 1").fetchone())
    print(json.dumps(dict(**result, integrity='ok', review_and_evidence_preserved=True), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
