"""Explicit live model integration test: one harmless query per selected engine."""
import json
import os
from pathlib import Path
import sys
import threading
import base64
import argparse
from urllib.parse import urlsplit, urlencode, parse_qs
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.search_browser import SearchSession, RenderError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("engines", nargs="*", choices=("google", "baidu"))
    parser.add_argument("--packaged", action="store_true")
    parser.add_argument("--fresh-profile", action="store_true")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--unattended", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--profile-root", type=Path)
    parser.add_argument("--query", default="IANA example domain")
    parser.add_argument("--page", type=int, choices=(0, 1, 2), default=0)
    parser.add_argument("--retry-search-after-widget", action="store_true")
    options = parser.parse_args()
    if "--packaged" in sys.argv:
        os.environ["SENTINEL_CAPTCHA_RUNTIME"] = str(Path(__file__).resolve().parents[1] / "dist/captcha-runtime")
    folder = options.output or Path("test-artifacts/captcha-models/live-fresh" if options.fresh_profile else "test-artifacts/captcha-models/live")
    folder.mkdir(parents=True, exist_ok=True)
    report = json.loads((folder / "report.json").read_text(encoding="utf-8")) if (folder / "report.json").exists() else {}
    engines = options.engines or ["google", "baidu"]
    for engine in engines:
        url = ("https://www.google.com/search?" + urlencode(dict(q=options.query, hl="ko", gl="kr", start=options.page*10))
               if engine == "google" else "https://www.baidu.com/s?" + urlencode(dict(wd=options.query, pn=options.page*10, rn=10)))
        session = SearchSession(options.profile_root or folder / "data", engine, threading.Event(), interactive=not (options.headless or options.unattended),
            progress=lambda message: print(json.dumps(dict(progress=message), ensure_ascii=True), flush=True), headless=options.headless)
        session.captcha_artifacts = folder / engine
        network = []
        def record_network(event):
            if event.get("method") == "Network.responseReceived":
                response = event.get("params", {}).get("response", {})
                parts = urlsplit(response.get("url", ""))
                if response.get("status", 0) >= 400 or (engine == "baidu" and parts.hostname == "passport.baidu.com"):
                    network.append(dict(host=parts.hostname, path=parts.path, status=response.get("status")))
            elif event.get("method") == "Network.loadingFailed":
                network.append(dict(error=event.get("params", {}).get("errorText")))
        try:
            session.start()
            session.client.event_handler = record_network
            session.client.call("Network.enable", session=session.session)
            items, more = session.results(url, options.page*10, auth_timeout=3)
            report[engine] = dict(status="search_results_received", count=len(items), more=more,
                                  captcha_attempts=session.captcha_attempts, first_titles=[i["title"] for i in items[:3]])
        except RenderError as exc:
            report[engine] = dict(status=exc.code, reason=str(exc), captcha_attempts=session.captcha_attempts)
            first_attempts = list(session.captcha_attempts)
            if options.retry_search_after_widget and any(event.get("widget_success_observed")
                    for job in first_attempts for event in job.get("events", [])):
                session.auto_captcha = False
                session.stop.wait(10)
                try:
                    items, more = session.results(url, options.page*10, auth_timeout=0)
                    report[engine].update(status="search_results_received", count=len(items), more=more,
                        recovered_after_verified_widget=True, first_titles=[item["title"] for item in items[:3]])
                except RenderError as retry_error:
                    report[engine]["retry_status"] = retry_error.code
                session.captcha_attempts = first_attempts + session.captcha_attempts
        finally:
            if session.client:
                try:
                    state = session.snapshot()
                    epoch = parse_qs(urlsplit(state.get("url", "")).query).get("timestamp", [""])[0]
                    if epoch.isdigit():
                        stamp = int(epoch) / (1000 if len(epoch) > 10 else 1)
                        report[engine]["challenge_age_seconds"] = time.time()-stamp
                    (folder / (engine + "-final.html")).write_text(state.get("html", ""), encoding="utf-8")
                    screenshot = session.client.call("Page.captureScreenshot", dict(format="png"), session=session.session)
                    (folder / (engine + "-final.png")).write_bytes(base64.b64decode(screenshot["data"]))
                except Exception:
                    pass
            session.close()
        report[engine]["network_diagnostics"] = network[-30:]
        report[engine]["runtime"] = "standalone" if "--packaged" in sys.argv else "venv"
        report[engine]["headless"] = session.headless
        report[engine]["interactive"] = session.interactive
        report[engine]["automatic_captcha_pass_and_search"] = (report[engine]["status"] == "search_results_received" and
            any(a.get("status") in ("widget_verified", "navigation_resumed") for a in session.captcha_attempts))
        (folder / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({engine: report[engine]}, ensure_ascii=True, indent=2), flush=True)


if __name__ == "__main__":
    main()
