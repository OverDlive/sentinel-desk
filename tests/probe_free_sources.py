"""Explicit live probe: two Google archive-index queries for example.com only."""
import json
from pathlib import Path
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.engine import Engine
from app.store import Store


def main():
    folder = Path(__file__).resolve().parents[1] / "test-artifacts/free-sources-live"
    store = Store(folder / "data")
    target = store.save_target(dict(name="IANA example domain", domains=["example.com"],
        keywords=[], cidrs=[], products=[], cves=[], enabled=True))
    for rule in store.rules():
        store.toggle_rule(rule["id"], rule["target_id"] == target["id"] and
                          rule["provider"] in ("zoneh", "xssed") and rule["query"].endswith('"example.com"'))
    for provider in ("zoneh", "xssed"):
        store.save_provider(provider, dict(enabled=True, search_backend="direct_html", pages=1, daily_limit=20))
    engine = Engine(store)
    timer = threading.Timer(120, engine.cancel.set)
    timer.daemon = True
    try:
        run_id = engine.start("real", trigger="schedule")
        timer.start()
        engine.worker.join(155)
    finally:
        timer.cancel()
        engine.close()
    with store.db() as db:
        run = dict(db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone())
        steps = [dict(r) for r in db.execute("SELECT provider,query,status,result_count,message FROM run_steps WHERE run_id=? ORDER BY id", (run_id,))]
    report = dict(run=run, steps=steps, target="example.com", target_page_visits=0,
                  note="Censys actual account API calls are not included; offline fixtures verify lookup, caching and limits.")
    (folder / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=True, indent=2))
    # A one-page probe may correctly report partial coverage; that is not a transport failure.
    return 0 if len(steps) == 2 and all(s["status"] in ("success", "partial") for s in steps) else 1


if __name__ == "__main__":
    sys.exit(main())
