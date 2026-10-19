"""Parse search pages without executing scripts or visiting result links."""
import json
import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlsplit


class SearchPageError(ValueError):
    def __init__(self, message, code="schema"):
        super().__init__(message)
        self.code = code


class Node:
    def __init__(self, tag="", attrs=(), parent=None):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.children = []

    def walk(self):
        pending = [self]
        while pending:
            node = pending.pop()
            yield node
            pending.extend(reversed([c for c in node.children if isinstance(c, Node)]))

    def text(self):
        parts, pending = [], [self]
        while pending:
            node = pending.pop()
            if isinstance(node, str):
                parts.append(node)
            elif node.tag not in ("script", "style", "noscript", "svg"):
                pending.extend(reversed(node.children))
        return re.sub(r"\s+", " ", " ".join(parts)).strip()

    def classes(self):
        return set((self.attrs.get("class") or "").split())


class Tree(HTMLParser):
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.root = self.current = Node()
        self.count = 0
        self.feed(html)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.count += 1
        if self.count > 100000:
            raise SearchPageError("검색 HTML 요소 수 제한을 초과했습니다.")
        node = Node(tag, attrs, self.current)
        self.current.children.append(node)
        if tag not in self.VOID:
            self.current = node

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        node = self.current
        while node.parent:
            if node.tag == tag:
                self.current = node.parent
                return
            node = node.parent

    def handle_data(self, data):
        self.current.children.append(data)


def result_url(href, engine):
    try:
        return _result_url(href, engine)
    except (ValueError, TypeError):
        return None


def _result_url(href, engine):
    base = "https://www.google.com" if engine == "google" else "https://www.baidu.com"
    url = urljoin(base, href or "")
    parts = urlsplit(url)
    if engine == "google" and parts.hostname in ("www.google.com", "google.com") and parts.path == "/url":
        values = parse_qs(parts.query)
        url = (values.get("q") or values.get("url") or [""])[0]
        parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return None
    if parts.hostname in ("www.google.com", "google.com", "www.baidu.com", "baidu.com"):
        # Baidu's opaque result redirects are retained; never resolve them over the network.
        if not ((engine == "baidu" and parts.path == "/link") or (engine == "google" and parts.path == "/goto")):
            return None
    return url


def parse_search_html(html, engine, offset=0):
    tree = Tree(html)
    nodes = list(tree.root.walk())
    title = " ".join(n.text() for n in nodes if n.tag == "title").casefold()
    visible = tree.root.text()
    lower = visible.casefold()
    challenge = any(n.attrs.get("id") in ("captcha", "recaptcha", "g-recaptcha", "verify") or
                    "g-recaptcha" in n.classes() or
                    (n.tag == "form" and "/sorry/" in (n.attrs.get("action") or "")) for n in nodes)
    blocked = challenge or any(x in title for x in ("百度安全验证", "安全验证", "captcha", "unusual traffic", "before you continue")) or any(
            x in lower for x in ("our systems have detected unusual traffic", "请输入验证码", "请完成安全验证"))
    items, seen = [], set()
    for heading in nodes:
        if heading.tag not in ("h3", "h2"):
            continue
        container, ancestor, advert = None, heading, False
        while ancestor.parent:
            classes = ancestor.classes()
            if ancestor.attrs.get("id") in ("tads", "bottomads") or ancestor.attrs.get("data-text-ad") is not None or classes & {"ec-tuiguang", "ec-result", "commercial-unit-desktop-top"}:
                advert = True
            if container is None and (classes & {"g", "MjjYud", "tF2Cxc", "ezO2md"} if engine == "google" else classes & {"result", "c-container", "result-op"}):
                container = ancestor
            ancestor = ancestor.parent
        if advert:
            continue
        link = next((n for n in heading.walk() if n.tag == "a"), None)
        ancestor = heading.parent
        while link is None and ancestor and ancestor.tag not in ("body", "html"):
            if ancestor.tag == "a":
                link = ancestor
                break
            ancestor = ancestor.parent
        if link is None:
            continue
        if container is None:
            # Unknown page layouts must not silently become successful zero-result runs.
            continue
        url = result_url(link.attrs.get("href"), engine)
        if engine == "baidu":
            try:
                original = json.loads(container.attrs.get("data-tools", "{}" )).get("url")
                if original:
                    url = result_url(original, engine) or url
            except (ValueError, AttributeError, TypeError):
                pass
        name = heading.text()
        if not url or not name or url in seen:
            continue
        snippets = [n.text() for n in container.walk() if n.classes() & {
            "VwiC3b", "IsZvec", "c-abstract", "c-span-last", "c-line-clamp3", "c-line-clamp4"}]
        snippet = max(snippets, key=len) if snippets else container.text().replace(name, "", 1).strip()
        display = " ".join(dict.fromkeys(n.text() for n in container.walk() if n.tag == "cite"))
        if display and display not in snippet:
            snippet = display + " · " + snippet
        seen.add(url)
        items.append(dict(url=url, title=name[:500], description=snippet[:3000], display_url=display))
    empty = any(x in lower for x in ("did not match any documents", "no results found for", "找不到和您的查询", "没有找到与", "未找到相关结果", "일치하는 검색결과가 없습니다", "검색어와 일치하는 문서가 없습니다"))
    if not items and blocked:
        raise SearchPageError("검색엔진의 CAPTCHA·접근 확인 화면입니다.", "blocked")
    if not items and engine == "google" and any(n.tag == "meta" and "/httpservice/retry/enablejs" in (n.attrs.get("content") or "") for n in nodes):
        raise SearchPageError("Google 검색에 JavaScript 렌더링이 필요합니다.", "render_required")
    if not items and not empty:
        raise SearchPageError("검색 결과 HTML을 인식하지 못했습니다. 구조 변경·동의 화면·접근 제한 여부를 확인하세요.")
    more = False
    base = "https://www.google.com" if engine == "google" else "https://www.baidu.com"
    for node in nodes:
        if node.tag != "a":
            continue
        parts = urlsplit(urljoin(base, node.attrs.get("href") or ""))
        if parts.hostname != urlsplit(base).hostname or parts.path not in ("/search", "/s"):
            continue
        try:
            next_offset = int(parse_qs(parts.query).get("start" if engine == "google" else "pn", ["0"])[0])
        except ValueError:
            continue
        more |= next_offset > offset
    return items, more
