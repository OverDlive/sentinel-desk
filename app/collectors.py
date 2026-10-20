"""Passive collection from provider APIs and search HTML, never target pages."""
import gzip
import io
import json
import re
import socket
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .domain import host_matches, ip_matches, now, web_finding
from .search_html import SearchPageError, parse_search_html
from .search_browser import RenderError, render_search, SearchSession
from .devtools import DevToolsError


class CollectionError(Exception):
    def __init__(self, message, code="error"):
        super().__init__(message)
        self.code = code


class SameHostRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        old, new = urlsplit(request.full_url), urlsplit(newurl)
        if new.scheme != "https" or new.netloc != old.netloc:
            raise CollectionError("제공자가 다른 호스트로 리디렉션했습니다. 자격 증명 보호를 위해 중단했습니다.")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


class Transport:
    def __init__(self, store, stop):
        self.store, self.stop = store, stop
        self.opener = build_opener(SameHostRedirect())

    def fetch(self, provider, url, headers=None, body=None, compressed=False, limit=8 * 1024 * 1024, response_format="json"):
        headers = dict(headers or {})
        headers.setdefault("User-Agent", "SentinelDesk/1.0 (passive exposure monitoring)")
        headers.setdefault("Accept", "application/json")
        if provider == "phishtank":
            headers["User-Agent"] = "phishtank/SentinelDesk-1.0"
        payload = json.dumps(body).encode() if body is not None else None
        if payload is not None:
            headers["Content-Type"] = "application/json"
        attempts = 1 if response_format == "html" else 2
        for attempt in range(attempts):
            if self.stop.is_set():
                raise CollectionError("사용자가 수집을 중지했습니다.", "cancelled")
            if not self.store.claim_request(provider):
                raise CollectionError("애플리케이션 일일 호출 한도에 도달했습니다. 한도는 UTC 00:00에 초기화됩니다.", "quota")
            try:
                request = Request(url, headers=headers, data=payload)
                with self.opener.open(request, timeout=20) as response:
                    raw = response.read(limit + 1)
                    if len(raw) > limit:
                        raise CollectionError("응답 크기 제한을 초과했습니다.", "schema")
                    if compressed or response.headers.get("Content-Encoding") == "gzip":
                        expanded_limit = limit if response_format == "html" else 100 * 1024 * 1024
                        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                            raw = stream.read(expanded_limit + 1)
                        if len(raw) > expanded_limit:
                            raise CollectionError("압축 해제 크기 제한을 초과했습니다.", "schema")
                    if response_format == "html":
                        charset = response.headers.get_content_charset() or "utf-8"
                        try:
                            return raw.decode(charset, errors="replace")
                        except LookupError:
                            raise CollectionError("검색 HTML 문자 인코딩을 인식하지 못했습니다.", "schema") from None
                    return json.loads(raw)
            except HTTPError as exc:
                # Never persist response bodies or request URLs: these can contain API keys.
                if exc.code in (401, 403):
                    if response_format == "html":
                        raise CollectionError(f"HTTP {exc.code}: 검색엔진이 직접 수집 접근을 거부했습니다.", "blocked") from None
                    raise CollectionError(f"HTTP {exc.code}: 키·검색 권한·서비스 접근 정책을 확인하세요.", "auth") from None
                if exc.code == 429:
                    raise CollectionError("HTTP 429: 제공자 호출 제한. 이번 실행의 해당 제공자를 중단합니다.", "rate_limited") from None
                if exc.code >= 500 and attempt + 1 < attempts:
                    self.stop.wait(1)
                    continue
                raise CollectionError(f"제공자 HTTP {exc.code} 오류. 요청 형식과 서비스 상태를 확인하세요.") from None
            except (URLError, TimeoutError, socket.timeout, ConnectionError):
                if attempt + 1 < attempts:
                    self.stop.wait(1)
                    continue
                raise CollectionError("네트워크 연결 또는 응답 시간 초과. 네트워크·프록시를 확인하세요.") from None
            except CollectionError as exc:
                if response_format == "html" and "리디렉션" in str(exc):
                    raise CollectionError("검색엔진이 다른 호스트의 확인 화면으로 이동을 요청했습니다. 직접 수집을 중단합니다.", "blocked") from None
                raise
            except (ValueError, OSError):
                raise CollectionError("JSON 또는 압축 응답 형식이 올바르지 않습니다.", "schema") from None


def require_list(value, field):
    if not isinstance(value, list):
        raise CollectionError(f"응답 형식 변경: {field} 목록이 없습니다.", "schema")
    return value


def service_finding(ip, service, provider, observed=None):
    port = service.get("port", 0)
    protocol = str(service.get("transport_protocol") or service.get("transport") or "tcp").lower()
    product = str(service.get("product") or service.get("protocol") or service.get("service_name") or "서비스")
    version = str(service.get("version") or "")
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", json.dumps(service.get("vulns") or service.get("vulnerabilities") or []))))
    info = {"ip": ip, "port": port, "transport": protocol, "product": product, "version": version,
            "cves": cves, "software": service.get("software", []),
            "http_title": (service.get("http") or {}).get("title")}
    url = f"https://www.shodan.io/host/{quote(ip)}" if provider == "shodan" else f"https://platform.censys.io/hosts/{quote(ip)}"
    return dict(identity=f"service:{ip}:{port}:{protocol}", url=url, asset=f"{ip}:{port}/{protocol}",
                title=f"{product} {version} · {ip}:{port}".strip(),
                summary="제공자에서 보고한 CVE: " + ", ".join(cves) if cves else "외부 서비스 관측 정보. 포트 공개 자체로 취약점을 확정하지 않습니다.",
                kind="service", severity="high" if cves else "low", confidence="medium" if cves else "high",
                reason="등록 CIDR 일치 · 제품/버전과 실제 영향 조건 검토 필요", observed_at=observed,
                cves=cves, evidence=info)


class Collectors:
    def __init__(self, store, stop, transport=None):
        self.store, self.stop = store, stop
        self.transport = transport or Transport(store, stop)
        self.memory = {}
        self.html_last_request = None
        self.browser_sessions = {}
        self.interactive = False
        self.progress = lambda _message: None
        self.use_browser = True

    def close(self):
        for session in self.browser_sessions.values():
            try:
                session.close()
            except Exception:
                pass
        self.browser_sessions.clear()

    def html_items(self, provider, url, page, config):
        if config.get("browser_session") and self.use_browser:
            if not self.store.claim_request(provider):
                raise CollectionError("애플리케이션 일일 호출 한도에 도달했습니다.", "quota")
            if provider not in self.browser_sessions:
                self.browser_sessions[provider] = SearchSession(self.store.directory, provider, self.stop,
                    interactive=self.interactive, progress=self.progress)
            try:
                return self.browser_sessions[provider].results(url, page * 10)
            except (RenderError, DevToolsError, OSError, TimeoutError) as exc:
                raise CollectionError(str(exc) if isinstance(exc, RenderError) else "검색 브라우저 연결에 실패했습니다.",
                                      getattr(exc, "code", "blocked")) from None
        html = self.transport.fetch(provider, url, headers={"Accept": "text/html", "Accept-Language": "ko,en;q=0.8,zh;q=0.7"}, response_format="html")
        try:
            return parse_search_html(html, provider, page * 10)
        except SearchPageError as exc:
            if exc.code != "render_required":
                raise CollectionError(str(exc), exc.code) from None
            if self.stop.wait(5):
                raise CollectionError("사용자가 수집을 중지했습니다.", "cancelled")
            if not self.store.claim_request(provider):
                raise CollectionError("애플리케이션 일일 호출 한도에 도달했습니다.", "quota")
            try:
                return parse_search_html(render_search(url, self.stop), provider, page * 10)
            except SearchPageError as rendered:
                raise CollectionError(str(rendered), "blocked" if rendered.code in ("blocked", "render_required") else rendered.code) from None
            except (RenderError, OSError, TimeoutError) as rendered:
                raise CollectionError(str(rendered) if isinstance(rendered, RenderError) else "검색 브라우저 실행에 실패했습니다.", "cancelled" if self.stop.is_set() else "blocked") from None

    def collect_html(self, rule, target, config):
        provider = rule["provider"]
        seen = set()
        for page in range(config["pages"]):
            # Shared spacing also covers consecutive rules and the two engines.
            if self.html_last_request is not None:
                delay = max(0, 10 - (time.monotonic() - self.html_last_request))
                if self.stop.wait(delay):
                    raise CollectionError("사용자가 수집을 중지했습니다.", "cancelled")
            if self.stop.is_set():
                raise CollectionError("사용자가 수집을 중지했습니다.", "cancelled")
            if provider == "google":
                url = "https://www.google.com/search?" + urlencode(dict(q=rule["query"], hl="ko", gl="kr", start=page * 10))
            else:
                url = "https://www.baidu.com/s?" + urlencode(dict(wd=rule["query"], pn=page * 10, rn=10))
            try:
                items, more = self.html_items(provider, url, page, config)
            finally:
                self.html_last_request = time.monotonic()
            for item in items:
                try:
                    finding = web_finding(item, rule, target)
                except ValueError:
                    continue
                if finding and finding["identity"] not in seen:
                    seen.add(finding["identity"])
                    finding["evidence"].update(search_engine=provider, collection_method="direct_html",
                        browser_session=bool(config.get("browser_session") and self.use_browser),
                        search_url=url, display_url=item.get("display_url", ""),
                        redirect_unresolved=urlsplit(item["url"]).hostname in ("www.baidu.com", "baidu.com", "www.google.com", "google.com"))
                    if provider in self.browser_sessions:
                        finding["evidence"]["captcha_attempts"] = self.browser_sessions[provider].captcha_attempts
                    yield finding
            if not more:
                return "검색 완료 · HTML 직접 수집 · 검색 색인 후보"
        return "페이지 상한 도달 · 추가 검색 결과가 남아 있을 수 있습니다."

    def feed(self, provider, config):
        if provider in self.memory:
            return self.memory[provider]
        path = self.store.directory / (provider + "-feed.json")
        if path.exists() and time.time() - path.stat().st_mtime < 3600:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                self.validate_feed(provider, data)
                self.memory[provider] = data
                return data
            except (ValueError, OSError, CollectionError):
                pass
        if provider == "cisa":
            data = self.transport.fetch("cisa", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        else:
            url = "https://data.phishtank.com/data/" + quote(config["key"], safe="") + "/online-valid.json.gz"
            data = self.transport.fetch("phishtank", url, compressed=True, limit=40 * 1024 * 1024)
        self.validate_feed(provider, data)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)
        self.memory[provider] = data
        return data

    @staticmethod
    def validate_feed(provider, data):
        if provider == "cisa":
            if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                raise CollectionError("CISA 피드 형식이 올바르지 않습니다.", "schema")
        elif not isinstance(data, list):
            raise CollectionError("PhishTank 피드 형식이 올바르지 않습니다.", "schema")

    def collect(self, rule, target, config):
        provider = rule["provider"]
        if provider in ("google", "baidu") and config.get("search_backend", "direct_html") == "direct_html":
            return (yield from self.collect_html(rule, target, config))
        if provider in ("google", "baidu", "zoneh", "xssed"):
            engine = "baidu" if provider == "baidu" else "google"
            archive_host = {"zoneh": "zone-h.org", "xssed": "xssed.com"}.get(provider)
            for page in range(config["pages"]):
                params = dict(engine=engine, q=rule["query"], api_key=config["key"])
                params["pn" if engine == "baidu" else "start"] = page * 10
                if engine == "google":
                    params.update(hl="ko", gl="kr")
                # Construct every request locally; never follow provider-supplied links with credentials.
                data = self.transport.fetch(provider, "https://serpapi.com/search.json?" + urlencode(params))
                if not isinstance(data, dict) or not isinstance(data.get("search_metadata"), dict):
                    raise CollectionError("SerpApi 응답 형식이 올바르지 않습니다.", "schema")
                status = data["search_metadata"].get("status")
                error = data.get("error")
                empty = error in ("Google hasn't returned any results for this query.",
                                  "Baidu hasn't returned any results for this query.")
                if status != "Success" or (error and not empty):
                    # Provider messages may contain echoed keys/URLs. Never expose them.
                    raise CollectionError("SerpApi 검색 실패. 키·계정 크레딧·검색 상태를 확인하세요.", "error")
                items = require_list(data.get("organic_results", [] if empty else None), "organic_results")
                for item in items:
                    if not isinstance(item, dict):
                        raise CollectionError("SerpApi 검색 항목 형식이 올바르지 않습니다.", "schema")
                    try:
                        url = str(item.get("link", ""))
                        if archive_host and not host_matches(urlsplit(url).hostname or "", [archive_host]):
                            continue
                        finding = web_finding(dict(url=url, title=item.get("title", ""),
                                                   description=item.get("snippet", "")), rule, target)
                    except ValueError:
                        continue
                    if finding:
                        finding["evidence"].update(search_engine=engine, intermediary="SerpApi")
                        if archive_host:
                            finding["reason"] = "신고 이력 검색 색인에서 대상 문자열 일치 · 현재 영향 확인 필요"
                            finding["evidence"]["classification"] = "과거 신고의 검색 색인 후보. 원본 신고·현재 취약점은 확인하지 않았습니다."
                        yield finding
                pagination = data.get("serpapi_pagination", {})
                if not isinstance(pagination, dict):
                    raise CollectionError("SerpApi 페이지 정보 형식이 올바르지 않습니다.", "schema")
                if not items or not pagination.get("next"):
                    return "검색 완료 · SerpApi 검색 색인 기준 · 원본 전체 조회 아님"
            return "페이지 상한 도달 · 추가 검색 결과가 남아 있을 수 있습니다."
        if provider == "brave":
            for page in range(config["pages"]):
                params = urlencode(dict(q=rule["query"], count=20, offset=page, country="KR", search_lang="ko", text_decorations="false"))
                data = self.transport.fetch(provider, "https://api.search.brave.com/res/v1/web/search?" + params,
                                             {"X-Subscription-Token": config["key"]})
                if not isinstance(data, dict) or "query" not in data:
                    raise CollectionError("Brave 응답 형식이 올바르지 않습니다.", "schema")
                items = require_list((data.get("web") or {}).get("results", []), "web.results")
                for item in items:
                    try:
                        finding = web_finding(item, rule, target)
                    except ValueError:
                        continue
                    if finding:
                        yield finding
                more = bool((data.get("query") or {}).get("more_results_available", len(items) == 20))
                if not more:
                    return "검색 완료 · 제공자가 반환한 색인 결과 기준"
            return "페이지 상한 도달 · 추가 검색 결과가 남아 있을 수 있습니다."
        if provider == "shodan":
            for page in range(1, config["pages"] + 1):
                params = urlencode(dict(key=config["key"], query=rule["query"], page=page))
                data = self.transport.fetch(provider, "https://api.shodan.io/shodan/host/search?" + params)
                if not isinstance(data, dict) or "total" not in data:
                    raise CollectionError("Shodan 응답 형식이 올바르지 않습니다.", "schema")
                items = require_list(data.get("matches"), "matches")
                for item in items:
                    if ip_matches(str(item.get("ip_str", "")), target["cidrs"]):
                        yield service_finding(item["ip_str"], item, provider, item.get("timestamp"))
                if page * 100 >= int(data["total"]) or not items:
                    return "검색 완료 · Shodan 관측 시각을 확인하세요."
            return "페이지 상한 도달 · 일부 결과만 수집했습니다."
        if provider == "censys":
            token = ""
            for page in range(config["pages"]):
                body = dict(query=rule["query"], page_size=100)
                if token:
                    body["page_token"] = token
                url = "https://api.platform.censys.io/v3/global/search/query"
                if config.get("organization_id"):
                    url += "?" + urlencode(dict(organization_id=config["organization_id"]))
                data = self.transport.fetch(provider, url, {"Authorization": "Bearer " + config["key"]}, body=body)
                result = data.get("result", {}) if isinstance(data, dict) else {}
                hits = require_list(result.get("hits"), "result.hits")
                for hit in hits:
                    host = (hit.get("host_v1") or {}).get("resource") or hit.get("resource") or hit
                    ip = str(host.get("ip", ""))
                    if not ip:
                        raise CollectionError("Censys 호스트 응답에 IP가 없습니다. 응답 스키마를 확인하세요.", "schema")
                    if not ip_matches(ip, target["cidrs"]):
                        continue
                    services = host.get("services") or hit.get("matched_services") or []
                    if not services:
                        services = [{"port": 0, "protocol": "호스트 (서비스 상세 없음)"}]
                    for service in services:
                        yield service_finding(ip, service, provider, host.get("last_updated_at") or host.get("last_updated"))
                token = result.get("next_page_token", "")
                if not token:
                    return "검색 완료 · Censys 관측 데이터 기준"
            return "페이지 상한 도달 · 추가 페이지 토큰이 남아 있습니다."
        if provider == "phishtank":
            entries = self.feed(provider, config)
            terms = list(dict.fromkeys(target["keywords"] + target["domains"] + [target["name"]]))
            for row in entries:
                if self.stop.is_set():
                    raise CollectionError("사용자가 수집을 중지했습니다.", "cancelled")
                if not row.get("verified") in ("yes", True) or row.get("online") not in ("yes", True):
                    continue
                url = str(row.get("url", ""))
                matched = [term for term in terms if term.casefold() in url.casefold()]
                if matched:
                    try:
                        from .domain import canonical_url
                        url = canonical_url(url)
                    except ValueError:
                        continue
                    yield dict(identity="url:" + url, url=url, asset=urlsplit(url).hostname,
                        title="브랜드 관련 피싱 후보 · " + urlsplit(url).hostname,
                        summary="PhishTank 검증 피싱 URL에서 문자열 일치: " + ", ".join(matched),
                        kind="phishing", severity="high", confidence="medium",
                        reason="피싱으로 검증된 URL. 기관 사칭 여부는 별도 검토 필요",
                        observed_at=row.get("verification_time"), cves=[], evidence={
                            "url": url, "phish_id": row.get("phish_id"), "verified": row.get("verified"),
                            "online": row.get("online"), "matched_terms": matched, "phish_detail_url": row.get("phish_detail_url")})
            return "검증된 활성 피싱 DB 대조 완료 · 피드 최대 1시간 캐시"
        if provider == "cisa":
            feed = self.feed(provider, config)
            with self.store.db() as db:
                rows = db.execute("SELECT cves FROM findings WHERE mode='real' AND target_id=?", (target["id"],)).fetchall()
            tracked = set(target["cves"])
            for row in rows:
                tracked.update(json.loads(row[0]))
            for row in feed["vulnerabilities"]:
                cve = row.get("cveID", "")
                text = (str(row.get("vendorProject", "")) + " " + str(row.get("product", ""))).casefold()
                products = [p for p in target["products"] if all(w in text for w in p.casefold().split())]
                exact = cve in tracked
                if not exact and not products:
                    continue
                yield dict(identity="cve:" + cve, url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    asset=cve, title=cve + " · " + str(row.get("vulnerabilityName", "")),
                    summary=str(row.get("shortDescription", "")), kind="advisory", severity="high" if exact else "medium",
                    confidence="medium" if exact else "low", reason="추적/관측 CVE가 KEV에 등재됨 · 실제 영향 확인 필요" if exact else
                    "등록 제품명 문자열 일치 · 버전 영향 미확인", observed_at=row.get("dateAdded"), cves=[cve],
                    evidence={"cveID": cve, "vendorProject": row.get("vendorProject"), "product": row.get("product"),
                              "requiredAction": row.get("requiredAction"), "dateAdded": row.get("dateAdded"),
                              "dueDate": row.get("dueDate"), "notes": row.get("notes"), "matched_products": products,
                              "catalog_version": feed.get("catalogVersion"),
                              "notice": "CISA 기한은 기관 자체 조치 기한으로 자동 적용하지 않습니다."})
            return "KEV 대조 완료 · 추적 CVE/제품 또는 선행 서비스 수집 결과 기준"
        raise CollectionError("자동 수집 미지원 제공자입니다.", "unsupported")
