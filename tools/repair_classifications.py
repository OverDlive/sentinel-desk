"""Apply the classification migration without starting the app or a collection."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.store import Store


def snapshot(store):
    with store.db() as db:
        if db.execute("SELECT count(*) FROM runs WHERE status='running'").fetchone()[0]:
            raise RuntimeError('수집이 실행 중입니다. 완료 후 다시 실행하세요.')
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise RuntimeError('데이터베이스 무결성 검사 실패')
        findings = [dict(row) for row in db.execute('SELECT * FROM findings ORDER BY id')]
        protected = {}
        for table in ('targets', 'providers', 'rules', 'runs', 'run_steps', 'requests', 'sightings', 'events'):
            protected[table] = [tuple(row) for row in db.execute('SELECT * FROM ' + table + ' ORDER BY rowid')]
        return findings, protected


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
    before, protected = snapshot(store)
    result = store.repair_classifications()
    after, current = snapshot(store)
    assert protected == current, '수집/검토 이력 변경 감지'
    assert len(before) == len(after)
    changes = []
    for old, new in zip(before, after):
        for key in old.keys() - {'kind', 'confidence', 'reason'}:
            assert old[key] == new[key], (old['id'], key)
        delta = {key: [old[key], new[key]] for key in ('kind', 'confidence', 'reason') if old[key] != new[key]}
        if delta:
            changes.append(dict(id=old['id'], fields=delta))
    if result['backup']:
        with closing(sqlite3.connect(Path(result['backup']).as_uri() + '?mode=ro', uri=True)) as db:
            assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    print(json.dumps(dict(**result, preserved_history=True, findings=len(after), changes=changes), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
