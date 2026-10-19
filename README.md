# Sentinel Desk 1.0 — Windows 데스크톱 프로그램

공개 검색 결과 HTML·위협정보 API를 이용해 등록한 조직의 외부 노출과 취약점 **후보**를 수집하는 네이티브 Windows 프로그램입니다. 웹 서버, Python 별도 설치 없이 `SentinelDesk.exe`를 실행합니다. Windows 10/11 x64용이며 설치·관리자 권한은 필요하지 않습니다. Google/Baidu 직접 수집에는 설치된 Microsoft Edge를 사용합니다.

## 시작하기

1. 배포 ZIP을 풀고 `SentinelDesk.exe`를 실행합니다.
2. 첫 화면은 **데모 보기**입니다. 합성 예시이며 실제 기관의 결과가 아닙니다.
3. **점검 대상 → 점검 대상 등록**에서 기관명, 도메인, 키워드, IP/CIDR 등을 등록합니다. 도메인은 `https://` 없이 입력합니다.
4. **API 연동 → Google 또는 Baidu → HTML 직접 수집 (키 불필요)**을 선택하고 **실제 수집에 사용**을 켠 뒤 저장합니다. 다른 API 수집은 해당 키가 필요합니다. CISA KEV도 키 없이 사용할 수 있습니다.
5. 상단 **실제 수집 → 수집 실행**을 누릅니다. 수집 이력에서 규칙별 성공·0건·오류를 확인합니다.
6. **검색 결과·후보**에서 결과를 두 번 클릭합니다. 출처와 증거를 확인하고 **검토·조치** 탭에서 담당자, 상태, 메모를 저장합니다.
7. 자동 반복이 필요하면 **자동 수집 설정**에서 주기를 설정합니다. **프로그램이 실행 중일 때만** 동작하며 Windows 작업 스케줄러·자동 시작 등록은 수행하지 않습니다.

## UI / UX 개선

밝은 워크스페이스, 부드러운 보라색 강조, 둥근 요약 카드와 위험도별 색상으로 화면을 재구성했습니다. 개요에서는 검토 시작 → 핵심 수치 → 우선 검토 목록 → 발견 유형 분포·설정 안내 순서로 확인합니다. 빈 화면에도 다음 행동을 안내합니다.

- 검색 화면에서 제목·자산·CVE를 검색하고 위험도·상태·출처·대상으로 필터링합니다. 드롭다운 변경은 즉시 적용되며 **필터 초기화**로 검색 조건을 모두 지울 수 있습니다.
- **Ctrl+F** 검색 화면 및 검색창으로 이동 / **Enter** 검색창에서 검색, 결과 목록에서 선택 결과 열기 / **F5** 새로고침 / **Esc** 상세·대상 등록 창 닫기.
- 개요·설정·등록 화면은 마우스 휠로 스크롤합니다. 수집 중에만 중지 버튼을 표시하고, 선택한 결과가 있을 때 검토 버튼을 활성화합니다.
- 최소 창 크기는 1100×740입니다. 긴 결과 목록과 표는 세로·가로 스크롤을 지원합니다.

컴포넌트 스타일은 `app/ui.py`에서 공통 관리합니다. 기본·주요·삭제·탐색 버튼은 같은 모서리·간격·포커스 규격을 사용합니다. 표 외곽은 연속된 둥근 테두리로 처리하고 머리글 배경·글자 대비, 하단선과 열 구분선을 강화했습니다. 열 제목과 데이터의 정렬을 맞추고 제목 길이와 글꼴 배율에 따라 최소 열 너비를 확보합니다. 버튼은 실제 부모 배경색으로 모서리를 칠해 상태 전환 시 직각 잔상이 남지 않도록 했습니다. 표·폼·텍스트 편집기는 화살표와 가운데 그립 선이 없는 긴 막대형 스크롤바를 사용하며, 내용이 넘칠 때만 표시합니다. 드롭다운과 팝업 목록의 배경·선택 색상도 통일했습니다. 상단 바는 내용에 따라 높이가 결정되고 필터 행은 공간이 부족하면 줄바꿈합니다.

버튼 잘림 회귀 검증: `python tests/check_ui_layout.py`. 100·125·150·200% Tk 글꼴 배율과 1100×740·1380×900 창 크기에서 전체 화면의 버튼 할당 크기, 버튼 상태별 모서리 픽셀, 스크롤바 표시·숨김과 실제 손잡이 드래그를 검사합니다. 보고서는 `test-artifacts/geometry-audit.json`에 저장합니다. 실제 Windows 디스플레이 배율은 변경하지 않습니다.

창 크기 변경 성능: 버튼 배경의 작은 이미지 조각을 넓은 영역에 반복해 그리던 비용을 줄이고, 같은 너비의 줄바꿈과 같은 그리드 배치를 재적용하지 않도록 했습니다. 카드·차트 도형은 새로 만들지 않고 좌표를 갱신하며, 폼의 라벨 목록은 내용 변경 시에만 다시 찾습니다. 스크롤 영역의 높이 변경은 스크롤 범위만 갱신합니다. 대기 중인 레이아웃 작업은 화면을 닫을 때 취소합니다.

재현용 성능 검사: `python tests/check_resize_performance.py --frames 40`. 4개 화면에서 창 크기를 줄였다 늘리며 시간과 Tk 호출 프로파일을 기록합니다. 각 측정에는 이벤트 처리 대기 20ms와 프로파일링 비용이 포함됩니다. 이 개발 환경의 개요 화면 중앙값은 수정 전 약 376ms에서 약 135ms로 감소했습니다. 측정값은 PC와 다른 실행 중인 작업에 따라 달라집니다.

디자인 참고: [Linear의 2026 UI 개편](https://linear.app/now/behind-the-latest-design-refresh), [Pinterest 보안 대시보드 레퍼런스](https://www.pinterest.com/pin/security-dashboard-design--451556300148062261/). 정보의 위계와 부드러운 시각 구분을 이 앱의 검토 흐름에 맞게 적용했습니다.

## 구현 범위

| 서비스 | 상태 / 기능 |
| --- | --- |
| Brave Search | 공식 API. 등록 도메인·영문 브랜드의 설정·백업/문서, 기관명 제목 문서, 브랜드, Pastebin, CISA 권고·분석 보고서 색인 검색 |
| Shodan | 공식 API. 등록 CIDR의 관측 서비스·보고된 CVE 수집. 능동 스캔 요청 없음 |
| Censys | Platform v3 검색 API/PAT. CIDR 호스트·서비스 조회. 검색 권한을 제공하는 요금제 필요 |
| PhishTank | 앱 키를 사용한 검증된 활성 피싱 JSON 피드. HTTP/HTTPS URL 내 기관명·브랜드·도메인 문자열 대조 |
| CISA | KEV JSON. 등록 추적 CVE, 이미 관측된 CVE, 제품명 문자열과 대조. 일반 권고·분석 보고서는 Google/Brave 색인으로 별도 검색 |
| Google | 키 없는 Edge 세션 HTML 수집 / SerpApi 선택. 수동 실행 중 CAPTCHA 직접 인증 후 자동 재개. 설정·문서·기관명·브랜드·Pastebin·CISA 권고·분석 보고서 색인 검색 |
| Baidu | 키 없는 Edge 세션 HTML 수집 / SerpApi 선택. 확인 페이지 직접 인증 후 재개. 기관명·브랜드, 이메일 도메인, 기관명과 이메일 도메인 교차 검색 |
| Zone-H / XSSed | SerpApi Google 검색의 해당 사이트 색인에서 신고 이력 후보 자동 수집. 원본 DB 전체 조회·현재 취약점 확인 아님 |
| Pastebin | Google/Brave에 색인된 공개 검색 결과만 수집. 별도 Scraping API·원문 수집 미포함 |

검색 규칙은 점검 대상 저장 시 자동 생성합니다. 원본 표 항목, 검색식, 최근 실행, 개별 활성 상태를 확인할 수 있습니다. 규칙 수가 실행당 한도를 넘으면 오래 실행하지 않은 규칙부터 다음 실행에 순환 처리합니다. KEV 대조는 일부 슬롯을 예약해 서비스 조회 이후 실행합니다.

### 첨부 표 규칙 반영

표의 `|`로 연결된 확장자는 검색 누락을 줄이도록 확장자별 독립 규칙으로 생성합니다. `file type` 오기는 `filetype:`으로 정규화하고 Censys의 과거 검색 문법은 현재 프로그램의 CenQL 문법으로 변환합니다. 설정·백업 10종(`conf cnf reg inf rdp cfg txt ora ini bak`)과 문서 8종(`xls xlsx ppt pptx doc docx hwp pdf`)을 검색합니다. 문서 검색이 표 첫 번째 파일 행의 `xls xlsx ppt hwp`도 포함합니다. `site:komipo` 형태는 영문 단일 키워드에도 생성하며, 정식 등록 도메인 일치와 동일하게 취급하지 않습니다.

표와 같은 대상으로 사용하려면 기관명 `중부발전`, 도메인 `komipo.co.kr`, 키워드 `komipo`, `중부발전`, CIDR `219.252.41.0/25`, `124.136.8.0/25`를 점검 대상으로 등록합니다. 실제 대상은 자동 등록하거나 수집하지 않습니다. PhishTank의 `*komipo*`는 와일드카드를 문자 그대로 비교하지 않고 HTTP/HTTPS URL의 대소문자 무관 부분 문자열로 대조합니다.

US-CERT의 과거 경보·분석 보고서 경로와 [CISA 통합 권고](https://www.cisa.gov/news-events/cybersecurity-advisories), 현재 경보·분석 보고서 경로를 Google/Brave에서 등록 기관명·도메인·키워드·제품·CVE별로 검색합니다. CISA 도메인 결과만 수집하고, 키워드나 제품만 일치한 보고서를 실제 취약점 또는 KEV 등재로 표시하지 않습니다. Zone-H·XSSed는 검색 색인 방식이며 원본 DB 전체를 조회하지 않습니다.

규칙 버전 2는 기존 데이터 폴더를 열 때 누락 규칙을 추가합니다. 기존 규칙의 ID·최근 실행·켜기/끄기, 수집 결과와 검토 이력을 유지합니다. 해당 제공자의 규칙이 모두 꺼져 있었다면 추가 규칙도 꺼진 상태로 넣습니다. API 제공자는 자동 활성화하지 않습니다.

### Google·Baidu·Zone-H·XSSed 사용

**Google / Baidu 직접 수집:** API 연동에서 엔진을 선택하고 **HTML 직접 수집 (키 불필요) → 실제 수집에 사용 → 연동 설정 저장**을 누릅니다. 상단에서 **실제 수집 → 수집 실행**을 누르면 기존 검색 규칙을 실행하고, 제목·링크·요약을 검색 결과·후보 화면에 표시합니다. 신규·기존 키 미등록 설정의 기본 방식입니다. 기존 SerpApi 키가 있는 설정은 방식·키·활성 상태를 보존하므로 직접 수집으로 바꾸려면 수집 방식을 선택해 저장하세요.

구현 순서는 고정된 엔진 검색 URL 생성 → 앱 전용 Edge 세션에서 검색 → 인증 필요 시 직접 인증 대기 → 두 번 연속 안정된 HTML 확인 → 엔진별 결과 파싱 → 광고·중복 제외 → 기존 대상 관련성 분류 → SQLite 저장·화면 표시입니다. Python 표준 라이브러리와 Edge DevTools Protocol을 사용합니다. 검색 결과의 원문 사이트는 자동 방문하지 않습니다.

- 직접 수집 검색 사이에는 최소 10초 간격을 둡니다. 규칙당 1~3페이지, 기존 일일 한도·실행당 규칙 수 제한을 적용합니다. 하루 한 번 실행하더라도 규칙 수×페이지 수만큼 요청할 수 있습니다. 기본 실행당 40규칙 한도로 모든 규칙을 하루에 처리하지 못하면 다음 실행에 순환합니다.
- **수집 실행**을 직접 누르면 앱 전용 Edge 창이 열립니다. CAPTCHA·동의·Baidu 확인 화면이 나오면 그 창에서 직접 완료하세요. 프로그램 하단에 **인증 대기**가 표시되며 최대 5분 기다린 뒤 같은 검색의 수집을 자동 재개합니다. 인증이 필요 없으면 그대로 수집합니다. 검색어를 직접 바꾸거나 창을 닫으면 해당 엔진 수집이 중단됩니다.
- **예약 실행**은 창 없는 Edge로 실행합니다. 인증이 필요하면 **브라우저 인증 필요**를 기록하고 해당 엔진의 남은 규칙을 건너뜁니다. 이후 수집 실행을 직접 눌러 인증하세요. 인증 상태 재사용은 검색엔진 정책에 따라 만료되거나 무효화될 수 있습니다. CAPTCHA의 완전 자동 해제는 제공하지 않습니다. 무인 수집이 필요하면 기존 SerpApi 방식을 선택할 수 있습니다(별도 키 필요).
- 엔진별 전용 프로필은 데이터 폴더의 `browser-profiles/google`, `browser-profiles/baidu`에 저장합니다. 개인 Edge 프로필은 사용하지 않습니다. 같은 실행 내에서는 브라우저와 탭을 재사용하고 실행 종료 시 닫습니다. 프로필의 쿠키·사이트 저장소는 다음 실행에서도 유지합니다. 일반 로딩은 최대 40초, HTML은 최대 8MiB입니다. 앱은 `127.0.0.1`의 임시 디버깅 포트로 자신이 실행한 브라우저만 제어합니다. 브라우저의 하위 리소스·리디렉션 요청은 앱의 검색 탐색 카운터에 포함하지 않습니다.
- 접근 거부는 **접근 차단**, 모르는 HTML 구조는 **응답 오류**로 기록합니다. 정상적인 검색 0건과 구분하며 유료 API로 자동 전환하지 않습니다.
- 최종 URL이 HTML에 있으면 사용하고, 불투명한 Google `/goto`·Baidu `/link`는 그대로 저장합니다. 화면에 표시된 출처 주소를 증거에 남기며 최종 목적지 미확인·낮은 신뢰도로 분류합니다. 중계 URL이 바뀌면 별도 후보로 기록될 수 있습니다.
- 하루 한 번 자동 실행하려면 **자동 수집 설정**에서 주기를 **1440분**으로 저장합니다. 앱이 실행 중일 때만 동작합니다. 직접 수집 활성화와 자동 실행은 사용자 설정으로 켜야 합니다.

**SerpApi 선택 / Zone-H·XSSed:** API 연동에서 Google/Baidu는 **SerpApi (API 키 필요)**를 선택하고, 원하는 항목의 **SerpApi API 키**를 입력한 뒤 **실제 수집에 사용 → 연동 설정 저장**을 누릅니다. Google/Baidu 자체 API 키가 아닌 [SerpApi](https://serpapi.com/) 계정의 키입니다. 동일한 키를 네 항목에 각각 등록할 수 있습니다. 이 방식에서는 키·검색어가 중계 서비스 SerpApi로 전송됩니다. 직접 수집은 저장된 SerpApi 키를 복호화하거나 전송하지 않습니다. 계정 크레딧은 공유되며 앱의 일일 호출 상한은 항목별로 적용됩니다.

기존 데이터 폴더도 첫 실행 시 새 규칙을 자동 추가합니다. 기존 결과·검토 이력·다른 규칙의 활성 상태를 보존하며 제공자를 자동으로 켜지 않습니다. Zone-H·XSSed는 화면에 **(색인)**으로 표시됩니다. 검색에 색인되지 않은 신고는 수집할 수 없고 0건이 안전함을 뜻하지 않습니다. 신고 URL을 자동 방문하거나 CAPTCHA를 우회하지 않습니다.

검색 페이지 수에는 상한(규칙당 1~3)이 있습니다. 전수 검색을 보장하지 않습니다. 제공자 제한, 애플리케이션 자체 한도, 페이지 제한은 수집 이력에서 구분합니다. 피드는 최대 1시간 캐시하며 실패 시 오래된 피드로 조용히 대체하지 않습니다. 일일 요청 상한은 **UTC 00:00** 기준이며 제공자의 요금·크레딧과 다릅니다. 재시도도 요청 횟수에 포함됩니다. HTTP 타임아웃은 20초이며 API 방식의 연결 오류·서버 오류는 최대 한 번 재시도합니다. 429·권한·한도 오류는 해당 실행의 제공자를 중단합니다.

## 결과 해석

- 파일 확장자·검색 색인 일치만으로 내용 유출을 확정하지 않습니다. 파일·페이지를 자동 방문하거나 다운로드하지 않습니다.
- 포트 공개 자체는 취약점이 아닙니다. 제품/버전 기반 CVE는 실제 영향 조건을 별도로 확인해야 합니다.
- KEV 대조는 우선 검토 대상입니다. 제품명 문자열 일치는 취약 버전 보유를 뜻하지 않습니다. CISA 기한은 자체 조치 기한으로 자동 적용하지 않습니다.
- 피싱 DB의 URL에서 조직 키워드가 일치해도 해당 기관 사칭인지는 담당자가 검토해야 합니다. 악성 의심 URL은 자동으로 열지 않습니다.
- 여러 출처에서 관측한 동일 URL 또는 IP·포트·전송 프로토콜 결과는 합칩니다. URL의 쿼리는 보존합니다. 원본 출처별 증거, 첫/최근 수집, 관측 시각, 변경 이력은 남깁니다.
- 검색에서 사라졌다고 조치 완료 처리하지 않습니다. 위험도와 담당자 검증 상태는 별개입니다. CSV 내보내기는 현재 필터의 전체 결과이며 UTF-8 BOM과 수식 삽입 방지를 적용합니다.

## 저장소·보안·운영

- 기본 데이터 경로: `%LOCALAPPDATA%\SentinelDesk`.
- SQLite 파일, CISA/PhishTank 캐시, 프로세스 잠금 파일을 저장합니다. 같은 데이터 폴더는 한 인스턴스만 사용합니다.
- API 키는 **Windows DPAPI / 현재 사용자**로 암호화합니다. 데이터베이스에 평문 키를 저장하지 않고 UI·로그·CSV에도 내보내지 않습니다. 같은 Windows 계정에서 복호화할 수 있습니다. 키가 들어간 DB를 다른 계정으로 이동하면 기존 키를 지우고 다시 등록해야 합니다.
- 수집 결과와 피드 캐시는 평문입니다. 파일 접근 권한과 디스크 암호화는 조직의 Windows 정책을 따릅니다.
- API 키를 네트워크로 보내는 대상은 해당 API 서비스입니다. SerpApi 방식의 Google·Baidu·Zone-H·XSSed 연동은 SerpApi에 키를 보냅니다. 직접 수집은 해당 엔진에 검색어를 전송합니다. Edge는 자체 네트워크 설정으로 페이지 스크립트·하위 리소스·확인 화면 리디렉션을 처리하며 API 키와 개인 브라우저 프로필을 사용하지 않습니다. 앱은 Google/Baidu 도메인의 검색 탭만 읽고 결과의 검색어가 요청한 검색어와 일치하는지 확인합니다.
- 원격 공동 사용자 로그인, 이메일/메신저 알림, PDF 보고서, 능동 취약점 검증, 자동 업데이트, 자동 시작은 이번 버전 미포함입니다.
- 배포 EXE는 코드 서명되지 않았습니다.

프로그램을 종료한 뒤 데이터 폴더를 백업하세요. 데이터 삭제가 필요하면 앱을 종료하고 해당 폴더를 삭제합니다. 대상 삭제는 해당 대상의 규칙·결과·검토 이력도 삭제하므로 화면에서 확인을 거칩니다.

사용자 지정 저장 경로:

```powershell
.\SentinelDesk.exe --data-dir 'D:\SecurityData\SentinelDesk'
```

## 소스 실행·테스트·빌드

Windows Python 3.11 이상에서 앱 실행에 외부 패키지는 필요하지 않습니다. 빌드할 때만 PyInstaller 6.22.3을 사용하며 `.build-tools`에 설치합니다.

```powershell
python main.py
python -m unittest discover -s tests -v
powershell -ExecutionPolicy Bypass -File build.ps1 -Python python
```

배포 결과는 `dist/SentinelDesk.exe`와 `dist/SentinelDesk-v1.0.0-Windows-x64.zip`입니다.

네트워크 없이 실제 네이티브 화면을 검증하려면:

```powershell
python main.py --data-dir .\test-artifacts\ui-data --smoke-ui .\test-artifacts\ui-report.json
.\dist\SentinelDesk.exe --data-dir .\test-artifacts\exe-data --smoke-ui .\test-artifacts\exe-report.json
```

구조: `app/domain.py` 검증·규칙 / `store.py` 저장·이력 / `collectors.py` API·HTML 수집 / `search_html.py` HTML 파서 / `search_browser.py` Edge 세션·인증 대기 / `devtools.py` 로컬 브라우저 제어 / `engine.py` 작업·예약 / `desktop.py` 네이티브 UI / `vault.py` 키 암호화 / `reporting.py` CSV.

## 공식 문서

- [Brave Search API](https://api-dashboard.search.brave.com/documentation/services/web-search)
- [Shodan API](https://developer.shodan.io/api)
- [Censys Platform API](https://docs.censys.com/reference/get-started)
- [Censys CenQL](https://docs.censys.com/docs/censys-query-language)
- [PhishTank 데이터 피드](https://phishtank.org/developer_info.php)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Google Custom Search API 안내](https://developers.google.com/custom-search/v1/overview)
- [SerpApi Google 검색 API](https://serpapi.com/search-api)
- [SerpApi Baidu 검색 API](https://serpapi.com/baidu-search-api)

문서 확인 기준: 2026-10-19. 자동 테스트 61개로 파싱·페이지 처리·인증 대기 후 재개·예약 수집의 인증 필요 처리·키 없는 설정·기존 DB 전환·세션 재사용을 검증했습니다. 실제 Edge의 로컬 DevTools 연결과 1MiB 응답 수신도 확인했습니다. 새 세션 수집의 현재 네트워크 실측은 Google/Baidu 모두 인증 필요 상태였으며, 사람의 CAPTCHA 인증 완료 후 실제 검색 성공은 아직 검증하지 못했습니다. 보고서는 `test-artifacts/browser-session-probe/report.json`입니다. 이전 테스트에서 HTML 파싱은 Google 9건·Baidu 8건을 확인했지만 현재 차단 해제 성공을 의미하지 않습니다. API 수집은 유료 키 없이 fixture로 검증했습니다.

참고: [Google 비정상 트래픽·직접 CAPTCHA 인증 안내](https://support.google.com/websearch/answer/86640?hl=ko), [Microsoft Edge DevTools Protocol](https://learn.microsoft.com/en-us/microsoft-edge/devtools/protocol/).

