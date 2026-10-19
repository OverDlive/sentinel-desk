from .collectors import service_finding
from .domain import web_finding


def demo_findings(target):
    examples = [
        ("brave", "config", "https://portal.example.com/archive/settings.bak", "설정 백업 파일 검색 노출 의심", "검색 색인에 설정 백업 파일 경로가 포함되었습니다. 내용은 확인하지 않았습니다."),
        ("brave", "config", "https://portal.example.com/help/remote.rdp", "원격 접속 설정 파일 검색 결과", "등록 도메인의 RDP 파일 후보. 공개 목적과 내용 검토가 필요합니다."),
        ("brave", "document", "https://www.example.com/reports/annual-report.pdf", "2026 연간 사업보고서", "정상 공개 자료 여부를 담당 부서에서 확인하세요."),
        ("brave", "document", "https://www.example.com/library/guide.xlsx", "업무 안내 문서", "외부 검색 가능한 문서입니다. 확장자만으로 유출로 판단하지 않습니다."),
        ("brave", "paste", "https://pastebin.com/demo-placeholder", "예시 기관 관련 Pastebin 검색 결과", "예시 기관 키워드가 포함된 게시물 후보. 원문 수집은 하지 않았습니다."),
        ("brave", "brand", "https://news.example.net/article/100", "예시 기관 사업 관련 공개 기사", "예시 기관에 대한 일반 공개 언급입니다."),
    ]
    for provider, kind, url, title, description in examples:
        rule = dict(query=f"데모 · {kind} · {target['name']}", kind=kind)
        finding = web_finding(dict(url=url, title=title, description=description), rule, target)
        if finding:
            yield provider, rule, finding
    for ip, port, product, vulns in [("192.0.2.10", 443, "nginx", ["CVE-2021-23017"]),
                                      ("192.0.2.20", 22, "OpenSSH", [])]:
        rule = dict(query="net:192.0.2.0/24", kind="service")
        finding = service_finding(ip, dict(port=port, product=product, version="데모", vulns=vulns), "shodan", "2026-10-16T03:00:00Z")
        yield "shodan", rule, finding
    yield "censys", dict(query='host.ip: "192.0.2.0/24"', kind="service"), service_finding(
        "192.0.2.10", dict(port=443, product="nginx", version="데모", transport_protocol="tcp"), "censys", "2026-10-16T04:00:00Z")
    yield "phishtank", dict(query="example 브랜드 문자열 대조", kind="phishing"), dict(
        identity="url:https://login-example.example.net/verify", url="https://login-example.example.net/verify",
        asset="login-example.example.net", title="예시 기관을 사칭하는 피싱 후보", summary="합성 데모 데이터입니다. 실제 피싱 URL이 아닙니다.",
        kind="phishing", severity="high", confidence="medium", reason="브랜드 문자열 일치 · 기관 사칭 여부 검토 필요",
        observed_at="2026-10-16T01:00:00Z", cves=[], evidence=dict(verified="yes", online="yes", matched_terms=["example"], demo=True))
    yield "cisa", dict(query="CVE-2024-3400 ↔ KEV (데모)", kind="advisory"), dict(
        identity="cve:CVE-2024-3400", url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        asset="CVE-2024-3400", title="CVE-2024-3400 · KEV 대조 예시", summary="합성 데모 결과. 실제 조직의 제품 보유·영향을 의미하지 않습니다.",
        kind="advisory", severity="high", confidence="medium", reason="추적 CVE 일치 · 취약 버전 여부 확인 필요",
        observed_at="2024-04-12", cves=["CVE-2024-3400"], evidence=dict(cveID="CVE-2024-3400", demo=True,
        requiredAction="제조사 권고 및 해당 자산의 버전을 검토하세요."))
