"""Bounded live search-only recovery probe; never visits result destinations."""
import json
from pathlib import Path
import sys
import threading
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.search_browser import SearchSession, RenderError


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    folder = Path('test-artifacts/search-recovery-live')
    folder.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()
    timer = threading.Timer(170, stop.set)
    timer.daemon = True
    session = SearchSession(folder, 'google', stop, headless=True)
    session.auto_captcha = False
    report = []
    timer.start()
    try:
        for query in ['site:us-cert.cisa.gov/ncas/analysis-reports "중부발전"', 'intitle:"중부발전" filetype:hwp']:
            url = 'https://www.google.com/search?' + urlencode(dict(q=query, hl='ko', gl='kr', start=0))
            try:
                items, more = session.results(url, auth_timeout=0)
                result = dict(query=query, status='success', count=len(items), more=more)
            except RenderError as exc:
                result = dict(query=query, status=exc.code, message=str(exc))
            report.append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
            if stop.is_set():
                break
    finally:
        timer.cancel()
        session.close()
    (folder / 'report.json').write_text(json.dumps(dict(results=report, target_page_visits=0), ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
