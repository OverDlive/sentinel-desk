import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

CONFIG_EXTS = "conf cnf reg inf rdp cfg txt ora ini bak".split()
DOC_EXTS = "xls xlsx ppt pptx doc docx hwp pdf".split()
CISA_SEARCH_SCOPES = (
    ("site:cisa.gov/news-events/alerts", "US-CERT / CISA 경보"),
    ("site:cisa.gov/news-events/analysis-reports", "US-CERT / CISA 분석 보고서"),
    ("site:cisa.gov/news-events/cybersecurity-advisories", "US-CERT / CISA 통합 권고"),
    ("site:us-cert.cisa.gov/ncas/alerts", "US-CERT 과거 경보"),
    ("site:us-cert.cisa.gov/ncas/analysis-reports", "US-CERT 과거 분석 보고서"),
)
SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
STATUSES = {"new", "reviewing", "confirmed", "in_progress", "resolved", "false_positive", "accepted"}
PROVIDERS = [
    dict(id="brave", name="Brave Search", category="웹 검색", needs_key=True, supported=True,
         description="설정·문서·브랜드·Pastebin·CISA 권고/분석 보고서 색인 검색. Google과 다른 독립 검색 색인입니다.",
         docs="https://api-dashboard.search.brave.com/documentation/services/web-search"),
    dict(id="shodan", name="Shodan", category="외부 서비스", needs_key=True, supported=True,
         description="등록 CIDR의 기존 관측 데이터 및 CVE 후보. 능동 스캔을 요청하지 않습니다.",
         docs="https://developer.shodan.io/api"),
    dict(id="censys", name="Censys", category="외부 서비스", needs_key=True, supported=True,
         description="Platform v3 / CenQL. 검색 권한이 포함된 PAT가 필요합니다.",
         docs="https://docs.censys.com/reference/get-started"),
    dict(id="phishtank", name="PhishTank", category="피싱 피드", needs_key=True, supported=True,
         description="검증된 활성 피싱 DB에서 브랜드 문자열 대조. 전체 DB는 1시간 캐시합니다.",
         docs="https://phishtank.org/developer_info.php"),
    dict(id="cisa", name="CISA KEV", category="취약점 권고", needs_key=False, supported=True,
         description="키 없이 사용. 추적 CVE·관측 CVE·등록 제품명과 KEV를 대조합니다.",
         docs="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    dict(id="google", name="Google", category="웹 검색", needs_key=True, supported=True,
         description="설정·문서·Pastebin·CISA 권고/분석 보고서 검색. HTML 직접 수집은 API 키 없이 Google에 검색어를 전송합니다. SerpApi 수집도 선택할 수 있습니다.",
         docs="https://www.google.com/search/howsearchworks/"),
    dict(id="baidu", name="Baidu", category="웹 검색", needs_key=True, supported=True,
         description="기관·브랜드·이메일 도메인 검색. HTML 직접 수집은 API 키 없이 Baidu에 검색어를 전송합니다. SerpApi 수집도 선택할 수 있습니다.",
         docs="https://www.baidu.com/"),
    dict(id="zoneh", name="Zone-H (색인)", category="신고 이력 색인", needs_key=True, supported=True,
         description="SerpApi / Google의 zone-h.org 색인에서 신고 이력 후보를 수집합니다. SerpApi 키 필요. 원본 DB 전체 조회가 아니며 과거 신고는 현재 침해의 증거가 아닙니다.",
         docs="https://serpapi.com/search-api"),
    dict(id="xssed", name="XSSed (색인)", category="신고 이력 색인", needs_key=True, supported=True,
         description="SerpApi / Google의 xssed.com 색인에서 XSS 신고 이력 후보를 수집합니다. SerpApi 키 필요. 색인 누락·오래된 신고가 있을 수 있으며 현재 취약점을 확정하지 않습니다.",
         docs="https://serpapi.com/search-api"),
]
PROVIDER_MAP = {x["id"]: x for x in PROVIDERS}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def lines(value, name, maximum=30):
    if isinstance(value, str):
        value = re.split(r"[\n,]", value)
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise ValueError(f"{name}: 문자열 목록을 입력하세요.")
    result = list(dict.fromkeys(x.strip() for x in value if x.strip()))
    if len(result) > maximum or any(len(x) > 150 for x in result):
        raise ValueError(f"{name}: 최대 {maximum}개, 항목당 150자까지 가능합니다.")
    return result


def validate_target(data):
    name = str(data.get("name", "")).strip()
    if not 1 <= len(name) <= 100:
        raise ValueError("기관명은 1~100자로 입력하세요.")
    result = {"name": name, "owner": str(data.get("owner", ""))[:100],
              "enabled": bool(data.get("enabled", True))}
    for field in ("domains", "keywords", "cidrs", "products", "cves"):
        result[field] = lines(data.get(field, []), field)
    domains = []
    for domain in result["domains"]:
        try:
            domain = domain.lower().rstrip(".").encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError("올바른 도메인을 입력하세요.")
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
            raise ValueError("도메인은 URL·경로 없이 입력하세요. 예: example.com")
        domains.append(domain)
    result["domains"] = list(dict.fromkeys(domains))
    try:
        result["cidrs"] = list(dict.fromkeys(str(ipaddress.ip_network(x, strict=False)) for x in result["cidrs"]))
    except ValueError:
        raise ValueError("올바른 IP 또는 CIDR을 입력하세요. 예: 192.0.2.0/24")
    result["cves"] = [x.upper() for x in result["cves"]]
    if any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", x) for x in result["cves"]):
        raise ValueError("CVE는 CVE-2024-12345 형식으로 입력하세요.")
    if not any(result[f] for f in ("domains", "keywords", "cidrs", "products", "cves")):
        raise ValueError("도메인·키워드·CIDR·제품·CVE 중 하나 이상 등록하세요.")
    return result


def canonical_url(url):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise ValueError("유효한 http(s) URL이 아닙니다.")
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    if port and not (parts.scheme == "https" and port == 443 or parts.scheme == "http" and port == 80):
        host += f":{port}"
    # Preserve path case and query order/values: they may identify different documents.
    return urlunsplit((parts.scheme.lower(), host, parts.path or "/", parts.query, ""))


def host_matches(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)


def ip_matches(ip, cidrs):
    try:
        address = ipaddress.ip_address(ip)
        return any(address in ipaddress.ip_network(net) for net in cidrs)
    except ValueError:
        return False


def quote(value):
    return '"' + value.replace('"', ' ').replace('\\', ' ').strip() + '"'


def compile_rules(target):
    rules = []
    seen = set()
    def add(provider, kind, query, label, row):
        key = (provider, kind, query)
        if key in seen:
            return
        seen.add(key)
        rules.append(dict(provider=provider, kind=kind, query=query, label=label, source_row=row))
    # The source table also uses a short brand in site: (e.g. site:komipo).
    # Only single ASCII hostname tokens are valid site operands.
    scopes = list(dict.fromkeys(target["domains"] + [
        term for term in target["keywords"] if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", term)]))
    for domain in scopes:
        for ext in CONFIG_EXTS:
            add("brave", "config", f"site:{domain} filetype:{ext}", f"설정·백업 파일 · {ext}", "Google 설정 파일")
        for ext in DOC_EXTS:
            add("brave", "document", f"site:{domain} filetype:{ext}", f"공개 문서 · {ext}", "Google 문서 파일")
    terms = list(dict.fromkeys(target["keywords"] + [target["name"]]))
    for term in terms:
        add("brave", "brand", quote(term), "외부 기관 언급", "Baidu / 기관 키워드")
        add("brave", "paste", f"site:pastebin.com {quote(term)}", "Pastebin 색인 검색", "Pastebin")
    # One title rule per document type; engines may interpret intitle differently.
    for ext in DOC_EXTS:
        add("brave", "document", f"intitle:{quote(target['name'])} filetype:{ext}", f"기관명 제목 문서 · {ext}", "Google 기관명 제목")
    for cidr in target["cidrs"]:
        add("shodan", "service", f"net:{cidr}", "CIDR 서비스 조회", "Shodan / Censys")
        add("censys", "service", f'host.ip: "{cidr}"', "CIDR 호스트 조회", "Shodan / Censys")
    add("phishtank", "phishing", "브랜드·도메인 문자열 대조", "HTTP/HTTPS 피싱 URL · 기관명·브랜드·도메인 대조", "PhishTank")
    add("cisa", "advisory", "등록/관측 CVE 및 제품명 ↔ KEV", "실제 악용 취약점 대조", "US-CERT / CISA")
    for term in dict.fromkeys(terms + target["domains"] + target["products"] + target["cves"]):
        for scope, row in CISA_SEARCH_SCOPES:
            add("brave", "advisory", f"{scope} {quote(term)}", "권고·분석 보고서 색인 검색", row)
    # Preserve Brave rules while adding genuine Google/Baidu searches.
    for rule in list(rules):
        if rule["provider"] == "brave":
            add("google", rule["kind"], rule["query"], rule["label"], rule["source_row"])
            if rule["kind"] == "brand":
                add("baidu", rule["kind"], rule["query"], rule["label"], rule["source_row"])
    for domain in target["domains"]:
        add("baidu", "brand", quote("@" + domain), "이메일 도메인 언급", "Baidu / 이메일 도메인")
        for term in terms:
            add("baidu", "brand", f"{quote(term)} {quote('@' + domain)}", "기관·이메일 도메인 교차 검색", "Baidu / 기관·이메일")
    for term in dict.fromkeys(target["domains"] + terms):
        add("zoneh", "archive", f"site:zone-h.org {quote(term)}", "변조 신고 이력 색인 검색", "Zone-H")
        add("xssed", "archive", f"site:xssed.com {quote(term)}", "XSS 신고 이력 색인 검색", "XSSed")
    return rules


def web_finding(item, rule, target):
    url = canonical_url(str(item.get("url", "")))
    title = str(item.get("title", ""))[:500] or url
    description = re.sub(r"<[^>]*>", "", str(item.get("description", "")))[:3000]
    host = urlsplit(url).hostname
    redirect = host in ("www.google.com", "google.com", "www.baidu.com", "baidu.com") and urlsplit(url).path in ("/goto", "/link")
    displayed = re.match(r"https?://[^\s›>]+", str(item.get("display_url", ""))) if redirect else None
    display_host = urlsplit(displayed.group()).hostname if displayed else None
    source_host = display_host or host
    related = not redirect and host_matches(host, target["domains"])
    terms = target["keywords"] + [target["name"]]
    kind = rule["kind"]
    if kind in ("brand", "paste", "archive", "advisory"):
        terms += target["domains"]
    if kind == "paste" and not host_matches(source_host, ["pastebin.com"]):
        return None
    if kind == "advisory":
        if not host_matches(source_host, ["cisa.gov"]):
            return None
        terms += target["products"] + target["cves"]
    keyword_match = any(t.casefold() in (url + " " + title + " " + description).casefold() for t in terms)
    if not related and not keyword_match:
        return None
    severity = "high" if kind == "config" and related else "medium" if kind == "paste" else "info"
    finding = dict(identity="url:" + url, url=url, asset=host, title=title, summary=description,
                kind=kind, severity=severity, confidence="high" if related else "low",
                reason="등록 도메인 일치" if related else "기관 키워드 일치 — 관련성 검토 필요",
                observed_at=None, cves=[], evidence={"title": title, "description": description,
                "url": url, "classification": "검색 색인 후보. 파일 내용과 현재 접근 가능 여부는 확인하지 않았습니다."})
    if kind == "advisory":
        finding["cves"] = sorted(set(c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,}", title + " " + description, re.I)))
        finding["reason"] = "CISA 권고 색인에서 등록 키워드·제품·CVE 일치 · 실제 영향 확인 필요"
        finding["evidence"]["classification"] = "권고·분석 보고서의 검색 색인 후보. KEV 등재 또는 취약 버전 보유를 뜻하지 않습니다."
    if redirect:
        finding["confidence"] = "low"
        finding["reason"] += " · 검색엔진 중계 링크: 최종 목적지 미확인"
        finding["evidence"].update(display_url=item.get("display_url", ""), redirect_unresolved=True)
    return finding
