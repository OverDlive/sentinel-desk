"""Explicit, small live probe: one public example query per engine, no target visits."""
import json
from pathlib import Path
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.collectors import Transport, CollectionError
from app.search_html import parse_search_html, SearchPageError
from app.store import Store
from app.search_browser import render_search, RenderError


def main():
    folder = Path(__file__).resolve().parents[1] / "test-artifacts/html-probe"
    folder.mkdir(parents=True, exist_ok=True)
    store = Store(folder / "data")
    transport = Transport(store, threading.Event())
    report = {}
    if "--render-google-only" in sys.argv:
        report_path = folder / "report.json"
        report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
        try:
            html = render_search("https://www.google.com/search?q=IANA+example+domain&hl=ko&gl=kr&start=0", threading.Event())
            (folder / "google-rendered.html").write_text(html, encoding="utf-8")
            items, more = parse_search_html(html, "google")
            report["google"] = dict(status="success", rendering="Edge", result_count=len(items), more=more, items=items[:2])
        except (SearchPageError, RenderError) as exc:
            report["google"] = dict(status=getattr(exc, "code", "error"), message=str(exc), rendering="Edge")
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=True, indent=2))
        return
    for engine, url in [
        ("google", "https://www.google.com/search?q=IANA+example+domain&hl=ko&gl=kr&start=0"),
        ("baidu", "https://www.baidu.com/s?wd=IANA+example+domain&pn=0&rn=10"),
    ]:
        try:
            html = transport.fetch(engine, url, headers={"Accept": "text/html", "Accept-Language": "ko,en;q=0.8,zh;q=0.7"}, response_format="html")
            (folder / (engine + ".html")).write_text(html, encoding="utf-8")
            items, more = parse_search_html(html, engine)
            report[engine] = dict(status="success", result_count=len(items), more=more, items=items[:2])
        except (CollectionError, SearchPageError) as exc:
            report[engine] = dict(status=exc.code, message=str(exc))
    (folder / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
