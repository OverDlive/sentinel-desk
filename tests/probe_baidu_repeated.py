"""A few real searches in one app-owned Baidu browser session."""
import argparse
import base64
import json
import os
from pathlib import Path
import sys
import threading
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.search_browser import SearchSession, RenderError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--packaged", action="store_true")
    options = parser.parse_args()
    if options.packaged:
        os.environ["SENTINEL_CAPTCHA_RUNTIME"] = str(Path("dist/captcha-runtime").resolve())
    folder = options.output
    folder.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()
    session = SearchSession(folder / "data", "baidu", stop, interactive=False,
        progress=lambda value: print(json.dumps({"progress": value}), flush=True))
    rows = []
    try:
        for number, query in enumerate(("IANA example domain", "site:iana.org example", '"IANA" "example"')):
            capture = folder / str(number + 1)
            capture.mkdir(parents=True, exist_ok=True)
            session.captcha_artifacts = capture
            row = dict(query=query)
            try:
                items, more = session.results("https://www.baidu.com/s?" + urlencode(dict(wd=query, pn=0, rn=10)), auth_timeout=0)
                row.update(status="search_results_received", count=len(items), first_titles=[item["title"] for item in items[:2]])
            except RenderError as exc:
                row.update(status=exc.code, reason=str(exc), count=0)
            row["captcha_attempts"] = session.captcha_attempts
            row["captcha_pass_and_search"] = row["status"] == "search_results_received" and any(
                attempt.get("status") == "navigation_resumed" and any(event.get("submitted") for event in attempt.get("events", []))
                for attempt in session.captcha_attempts)
            if session.client:
                state = session.snapshot()
                (capture / "final.html").write_text(state.get("html", ""), encoding="utf-8")
                picture = session.client.call("Page.captureScreenshot", dict(format="png"), session=session.session)
                (capture / "final.png").write_bytes(base64.b64decode(picture["data"]))
            rows.append(row)
            (folder / "report.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps({key:value for key,value in row.items() if key != "captcha_attempts"}), flush=True)
            if number < 2:
                stop.wait(10)
    finally:
        session.close()


if __name__ == "__main__":
    main()
