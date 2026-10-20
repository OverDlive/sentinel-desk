"""Optional JS rendering with installed Edge and an isolated temporary profile."""
import os
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlsplit
from urllib.request import build_opener, ProxyHandler

from .devtools import DevTools, DevToolsError
from .search_html import parse_search_html, SearchPageError
from .captcha_runtime import attempt_captcha


class RenderError(ValueError):
    def __init__(self, message, code="blocked"):
        super().__init__(message)
        self.code = code


def edge_path():
    for variable in ("PROGRAMFILES(X86)", "PROGRAMFILES", "LOCALAPPDATA"):
        root = os.environ.get(variable)
        if root:
            candidate = Path(root) / "Microsoft/Edge/Application/msedge.exe"
            if candidate.is_file():
                return str(candidate)
    raise RenderError("Google 검색에 JavaScript 렌더링이 필요합니다. Microsoft Edge를 설치하거나 SerpApi를 선택하세요.")


def local_debugger_endpoint(port):
    """Discover only the explicitly allocated loopback browser endpoint."""
    opener = build_opener(ProxyHandler({}))
    with opener.open(f"http://127.0.0.1:{port}/json/version", timeout=0.5) as response:
        payload = response.read(65537)
    if len(payload) > 65536:
        raise ValueError("브라우저 연결 메타데이터 크기 초과")
    metadata = json.loads(payload)
    if not isinstance(metadata, dict):
        raise ValueError("브라우저 연결 메타데이터 형식 오류")
    endpoint = metadata.get("webSocketDebuggerUrl", "")
    parts = urlsplit(endpoint)
    if (parts.scheme != "ws" or parts.hostname != "127.0.0.1" or parts.port != port or
            parts.username or parts.password or parts.query or parts.fragment or
            not parts.path.startswith("/devtools/browser/")):
        raise ValueError("앱 전용 로컬 브라우저 연결 정보가 아닙니다.")
    return endpoint


def render_search(url, stop):
    executable = edge_path()
    # Never share cookies, extensions or history with the user's browser.
    with tempfile.TemporaryDirectory(prefix="sentinel-search-", ignore_cleanup_errors=True) as folder:
        output = Path(folder) / "page.html"
        with output.open("wb") as stream:
            process = subprocess.Popen([
                executable, "--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                "--disable-extensions", "--disable-background-networking", "--disable-component-update",
                "--user-data-dir=" + str(Path(folder) / "profile"),
                "--virtual-time-budget=8000", "--dump-dom", url,
            ], stdout=stream, stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            deadline = time.monotonic() + 40
            failure = None
            while process.poll() is None:
                if stop.wait(0.1):
                    failure = "사용자가 검색 렌더링을 중지했습니다."
                    break
                if time.monotonic() >= deadline:
                    failure = "검색 페이지 렌더링 시간이 초과되었습니다."
                    break
                if output.stat().st_size > 8 * 1024 * 1024:
                    failure = "렌더링된 검색 HTML 크기 제한을 초과했습니다."
                    break
            if failure:
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=10)
                process.wait(timeout=10)
                raise RenderError(failure)
            if process.returncode:
                raise RenderError("Microsoft Edge 검색 렌더링에 실패했습니다.")
        if not output.exists() or not 0 < output.stat().st_size <= 8 * 1024 * 1024:
            raise RenderError("렌더링된 검색 HTML이 없거나 크기 제한을 초과했습니다.")
        return output.read_text(encoding="utf-8", errors="replace")


class SearchSession:
    """Reuse an app-owned profile; let a human complete challenges in manual runs."""
    def __init__(self, directory, engine, stop, interactive=False, progress=None, headless=False):
        self.directory = Path(directory) / "browser-profiles" / engine
        self.engine, self.stop = engine, stop
        self.interactive, self.progress = interactive, progress or (lambda _message: None)
        # Authentication waiting and browser rendering are independent. Baidu
        # rejected headless sessions even when the same profile worked headed.
        self.headless = headless
        self.process = self.client = self.session = None
        self.endpoint = self.target_id = None
        self.captcha_attempts = []
        self.auto_captcha = True
        self.captcha_artifacts = None

    def start(self):
        if self.client:
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        portfile = self.directory / "DevToolsActivePort"
        portfile.unlink(missing_ok=True)
        # Chromium's port=0 mode sets navigator.webdriver even in a normal window.
        # Use a normal explicit loopback debugging port; don't override page APIs.
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        arguments = [edge_path(), "--no-first-run", "--no-default-browser-check", "--disable-extensions",
                     "--window-size=1280,900",
                     "--remote-debugging-address=127.0.0.1", f"--remote-debugging-port={port}",
                     "--user-data-dir=" + str(self.directory.resolve()), "--new-window", "about:blank"]
        if self.headless:
            arguments.insert(1, "--headless")
        self.process = subprocess.Popen(arguments, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=0 if self.interactive else getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if self.stop.is_set():
                    raise RenderError("사용자가 수집을 중지했습니다.", "cancelled")
                if self.process.poll() is not None:
                    raise RenderError("검색 브라우저를 시작하지 못했습니다. 앱 전용 Edge 창을 닫고 다시 실행하세요.")
                try:
                    self.endpoint = local_debugger_endpoint(port)
                except (OSError, ValueError):
                    self.stop.wait(0.1)
                    continue
                self.client = DevTools(self.endpoint)
                target = self.client.call("Target.createTarget", dict(url="about:blank"))
                self.target_id = target["targetId"]
                self.session = self.client.call("Target.attachToTarget", dict(targetId=target["targetId"], flatten=True))["sessionId"]
                return
            raise RenderError("브라우저 연결 시간이 초과되었습니다. Edge 원격 디버깅 허용 정책을 확인하세요.")
        except Exception:
            self.close()
            raise

    def snapshot(self):
        # Read only the dedicated search tab; never inspect the user's personal browser.
        expression = '''(() => {
          const host = location.hostname;
          if (!(host === 'google.com' || host.endsWith('.google.com') ||
                host === 'baidu.com' || host.endsWith('.baidu.com'))) return {url: location.href, outside: true};
          const html = document.documentElement ? document.documentElement.outerHTML : '';
          return {url: location.href, ready: document.readyState,
                  html: html.length <= 8*1024*1024 ? html : '', oversized: html.length > 8*1024*1024};
        })()'''
        result = self.client.call("Runtime.evaluate", dict(expression=expression, returnByValue=True), session=self.session)
        value = result.get("result", {}).get("value")
        if not isinstance(value, dict):
            raise RenderError("검색 브라우저의 페이지 내용을 읽지 못했습니다.")
        return value

    def results(self, url, offset=0, auth_timeout=300):
        if self.stop.is_set():
            raise RenderError("사용자가 수집을 중지했습니다.", "cancelled")
        self.captcha_attempts = []
        expected = urlsplit(url)
        expected_host = "www.google.com" if self.engine == "google" else "www.baidu.com"
        if expected.scheme != "https" or expected.hostname != expected_host or expected.path != ("/search" if self.engine == "google" else "/s"):
            raise RenderError("허용되지 않은 검색 주소입니다.")
        self.start()
        try:
            navigation = self.client.call("Page.navigate", dict(url=url), session=self.session)
            if navigation.get("errorText"):
                raise RenderError("검색 페이지에 연결하지 못했습니다. 네트워크·브라우저 프록시를 확인하세요.", "error")
            load_deadline = time.monotonic() + 40
            auth_deadline = None
            last_error = None
            stable = None
            attempted = False
            approval_deadline = None
            while not self.stop.is_set():
                snapshot = self.snapshot()
                if snapshot.get("oversized"):
                    raise RenderError("검색 HTML 크기 제한을 초과했습니다.", "schema")
                current = urlsplit(snapshot.get("url", ""))
                if snapshot.get("outside"):
                    if current.scheme == "about":
                        if time.monotonic() >= load_deadline:
                            raise RenderError("검색 페이지 로딩 시간이 초과되었습니다.", "schema")
                        self.stop.wait(0.25)
                        continue
                    raise RenderError("검색 탭이 다른 사이트로 이동했습니다. 해당 엔진의 수집을 중단합니다.")
                html = snapshot.get("html", "")
                try:
                    result = parse_search_html(html, self.engine, offset)
                    parameter = "q" if self.engine == "google" else "wd"
                    query_matches = parse_qs(current.query).get(parameter) == parse_qs(expected.query).get(parameter)
                    if current.hostname != expected_host or current.path != expected.path or not query_matches:
                        raise RenderError("검색 탭의 검색어가 변경되었습니다. 수집을 다시 실행하세요.", "schema")
                    # Wait for two stable snapshots so the first result doesn't truncate a loading page.
                    signature = tuple((item["url"], item["title"]) for item in result[0])
                    if stable == signature and snapshot.get("ready") == "complete":
                        self.progress(f"{self.engine}: 검색 결과 수집 중")
                        return result
                    stable = signature
                except SearchPageError as exc:
                    stable, last_error = None, exc
                    challenge = exc.code == "blocked" or current.path.startswith("/sorry") or current.hostname in ("wappass.baidu.com", "passport.baidu.com", "consent.google.com")
                    if challenge:
                        if not attempted and self.auto_captcha and self.endpoint and self.target_id:
                            attempted = True
                            self.progress(f"{self.engine}: 로컬 CAPTCHA 모델 처리 중")
                            outcome = attempt_captcha(self.engine, self.endpoint, self.target_id, self.stop, self.captcha_artifacts)
                            self.captcha_attempts.append(outcome)
                            if outcome["status"] == "cancelled":
                                raise RenderError("사용자가 수집을 중지했습니다.", "cancelled")
                            # Only parsing the original query's search results confirms completion.
                            if outcome["status"] in ("widget_verified", "navigation_resumed"):
                                load_deadline = time.monotonic() + 20
                                approval_deadline = load_deadline
                                continue
                            self.progress(f"{self.engine}: 자동 인증 {outcome['status']} · " + str(outcome.get("reason", "직접 인증 필요")))
                        if approval_deadline is not None and time.monotonic() < approval_deadline:
                            self.stop.wait(0.25)
                            continue
                        if not self.interactive:
                            detail = self.captcha_attempts[-1].get("reason", self.captcha_attempts[-1]["status"]) if attempted and self.captcha_attempts else "자동 처리 불가"
                            raise RenderError("브라우저 인증이 필요합니다. " + str(detail) + " · 수집 실행을 직접 눌러 Edge에서 인증하세요.", "auth_required")
                        if auth_deadline is None:
                            auth_deadline = time.monotonic() + auth_timeout
                            self.progress(f"{self.engine}: 인증 대기 · 열린 앱 전용 Edge에서 CAPTCHA/동의를 완료하세요 (최대 {auth_timeout // 60}분)")
                deadline = auth_deadline if auth_deadline is not None else load_deadline
                if time.monotonic() >= deadline:
                    if auth_deadline:
                        raise RenderError("브라우저 인증 대기 시간이 끝났습니다. 인증 후 수집을 다시 실행하세요.", "auth_required")
                    raise RenderError(str(last_error) if last_error else "검색 결과 로딩 시간이 초과되었습니다.", "schema")
                self.stop.wait(0.5)
            raise RenderError("사용자가 수집을 중지했습니다.", "cancelled")
        except (DevToolsError, OSError, TimeoutError):
            raise RenderError("검색 브라우저가 닫혔거나 연결이 끊겼습니다. 다시 수집을 실행하세요.") from None

    def close(self):
        if self.client:
            try:
                self.client.call("Browser.close", timeout=2)
            except (DevToolsError, OSError, TimeoutError, ValueError):
                pass
            self.client.close()
            self.client = None
        if self.process and self.process.poll() is None:
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                subprocess.run(["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=10)
        self.process = None
