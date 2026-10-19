"""Explicit browser integration probe; not run during unit tests."""
import json
from pathlib import Path
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.search_browser import SearchSession, RenderError


def main():
    folder = Path("test-artifacts/browser-session-probe")
    folder.mkdir(parents=True, exist_ok=True)
    report = {}
    session = SearchSession(folder, "google", threading.Event())
    try:
        session.start()
        response = session.client.call("Runtime.evaluate", dict(expression="'a'.repeat(1024*1024)", returnByValue=True), session=session.session)
        assert len(response["result"]["value"]) == 1024 * 1024
        report["devtools"] = dict(status="success", response_bytes=1024 * 1024)
    finally:
        session.close()
    if "--local-only" not in sys.argv:
        for engine, url in [
            ("google", "https://www.google.com/search?q=IANA+example+domain&hl=ko&gl=kr&start=0"),
            ("baidu", "https://www.baidu.com/s?wd=IANA+example+domain&pn=0&rn=10")]:
            session = SearchSession(folder, engine, threading.Event(), interactive="--interactive" in sys.argv)
            try:
                items, more = session.results(url, auth_timeout=10)
                report[engine] = dict(status="success", parsed_results=len(items), more=more)
            except RenderError as exc:
                report[engine] = dict(status=exc.code, message=str(exc))
            finally:
                session.close()
    (folder / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
