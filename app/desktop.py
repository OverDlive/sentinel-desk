"""Native Windows UI: no HTTP server, browser, Electron, or WebView runtime."""
import json
import os
from pathlib import Path
import sys
import tkinter as tk
from datetime import datetime, timedelta, timezone
from tkinter import filedialog, messagebox, ttk, font as tkfont
import webbrowser

from .domain import PROVIDER_MAP, SEVERITIES
from .reporting import export_csv

from .ui import BG, WHITE, NAVY, TEAL, TEXT, MUTED, LINE, SOFT, GREEN, AMBER, install_theme, AutoScrollbar, ResultList, Button, TableFrame, bind_resize, bind_wrap, CanvasLayout

class RoundedPanel(tk.Frame):
    """Resizable native card; its inner frame remains keyboard accessible."""
    def __init__(self, parent, color=WHITE, padding=18, **kwargs):
        super().__init__(parent, bg=BG, **kwargs)
        self.canvas = tk.Canvas(self, bg=BG, highlightthickness=0, bd=0)
        self.canvas.place(relwidth=1, relheight=1)
        self.body = tk.Frame(self, bg=color)
        self.body.pack(fill="both", expand=True, padx=padding, pady=padding)
        shape = self.canvas.create_polygon(0,0,0,0, smooth=True, splinesteps=24, fill=color, outline="")
        def draw(w, h):
            r = min(18, w/2, h/2)
            self.canvas.coords(shape,
                r, 0, w-r, 0, w, 0, w, r, w, h-r, w, h,
                w-r, h, r, h, 0, h, 0, h-r, 0, r, 0, 0)
        bind_resize(self, draw, size=True)

SEV_LABEL = dict(critical="긴급", high="높음", medium="중간", low="낮음", info="정보")
STATUS_LABEL = dict(new="신규", reviewing="검토 중", confirmed="영향 확인", in_progress="조치 중",
                    resolved="조치 완료", false_positive="오탐 / 정상 공개", accepted="위험 수용")
KIND_LABEL = dict(config="설정·백업", document="공개 문서", paste="유출 의심", brand="기관 언급",
                  service="외부 서비스", phishing="피싱 후보", advisory="취약점 권고", archive="신고 이력 후보")
RUN_LABEL = dict(running="수집 중", success="완료", partial="부분 성공", failed="실패", skipped="건너뜀",
                 cancelled="중지됨", interrupted="중단됨", error="오류", auth="권한 오류", quota="일일 한도",
                 rate_limited="호출 제한", schema="응답 오류", blocked="접근 차단", auth_required="브라우저 인증 필요")


def local_time(value):
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone().strftime("%m.%d %H:%M:%S")
    except ValueError:
        return value


class Desktop:
    def __init__(self, root, store, engine):
        self.root, self.store, self.engine = root, store, engine
        self.mode = tk.StringVar(value="demo")
        self.view = "overview"
        self.offset = 0
        self.filters = {}
        self.last_signature = None
        self.nav_buttons = {}
        self.root.title("Sentinel Desk | 외부 노출·취약점 후보 모니터링")
        self.root.geometry("1380x900")
        self.root.minsize(1100, 740)
        self.root.configure(bg=BG)
        assets = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent)) / "assets"
        self.root.iconbitmap(default=str(assets / "sentinel.ico"))
        self.brand_icon = tk.PhotoImage(master=self.root, file=str(assets / "sentinel-48.png"))
        tkfont.nametofont("TkDefaultFont").configure(family="맑은 고딕", size=10)
        self.root.report_callback_exception = self.callback_error
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.configure_style()
        self.build_shell()
        self.root.bind("<MouseWheel>", self.scroll_wheel, add="+")
        self.root.bind("<Control-f>", self.focus_search)
        self.root.bind("<F5>", lambda e: self.refresh())
        self.navigate("overview")
        self.poll()

    def configure_style(self):
        self.style_images = install_theme(self.root)

    def build_shell(self):
        self.sidebar = tk.Frame(self.root, bg=NAVY, width=236)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        brand = tk.Frame(self.sidebar, bg=NAVY)
        brand.pack(fill="x", padx=20, pady=(27, 24))
        tk.Label(brand, image=self.brand_icon, bg=NAVY, bd=0).pack(side="left")
        name = tk.Frame(brand, bg=NAVY)
        name.pack(side="left", padx=10)
        tk.Label(name, text="Sentinel", fg=TEXT, bg=NAVY, font=("Segoe UI", 13, "bold")).pack(anchor="w")
        tk.Label(name, text="DESK / WINDOWS", fg=MUTED, bg=NAVY, font=("Segoe UI", 8)).pack(anchor="w")
        nav_outer = tk.Frame(self.sidebar, bg=NAVY)
        nav_outer.pack(fill="both", expand=True)
        nav_canvas = tk.Canvas(nav_outer, bg=NAVY, highlightthickness=0, bd=0)
        nav_canvas.scrollable = True
        nav_scroll = AutoScrollbar(nav_outer, orient="vertical", command=nav_canvas.yview)
        nav_canvas.configure(yscrollcommand=nav_scroll.set)
        nav_canvas.grid(row=0, column=0, sticky="nsew")
        nav_scroll.grid(row=0, column=1, sticky="ns")
        nav_outer.rowconfigure(0, weight=1)
        nav_outer.columnconfigure(0, weight=1)
        nav_inner = tk.Frame(nav_canvas, bg=NAVY)
        nav_window = nav_canvas.create_window(0, 0, window=nav_inner, anchor="nw")
        CanvasLayout(nav_canvas, nav_inner, nav_window)
        tk.Label(nav_inner, text="워크스페이스", fg=MUTED, bg=NAVY, anchor="w",
                 font=("맑은 고딕", 9)).pack(fill="x", padx=24, pady=(6, 10))
        for key, icon, label in [("overview", "◫", "모니터링 개요"), ("findings", "≡", "검색 결과·후보"),
                                 ("targets", "◎", "점검 대상"), ("providers", "◇", "API 연동"),
                                 ("rules", "▤", "검색 규칙"), ("runs", "◷", "수집 이력"), ("settings", "⚙", "자동 수집 설정")]:
            if key == "providers":
                tk.Label(nav_inner, text="관리 및 설정", fg=MUTED, bg=NAVY, anchor="w",
                         font=("맑은 고딕", 9)).pack(fill="x", padx=24, pady=(23, 9))
            button = Button(nav_inner, text=f"{icon}    {label}", style="Nav.TButton",
                                cursor="hand2", command=lambda k=key: self.navigate(k))
            button.pack(fill="x", padx=12, pady=3)
            self.nav_buttons[key] = button
        foot = tk.Frame(self.sidebar, bg=NAVY)
        foot.pack(side="bottom", before=nav_outer, fill="x", padx=22, pady=24)
        self.sidebar.configure(width=max(236, max(b.winfo_reqwidth() for b in self.nav_buttons.values()) + 24 + nav_scroll.winfo_reqwidth()))
        tk.Label(foot, text="●  공개 정보 모니터링", bg=NAVY, fg=GREEN, anchor="w", font=("맑은 고딕", 9, "bold")).pack(fill="x")
        tk.Label(foot, text="공개 검색·API 기반의 후보 수집\nSentinel Desk · v1.0.0", justify="left", bg=NAVY,
                 fg=MUTED, anchor="w", font=("맑은 고딕", 8)).pack(fill="x", pady=(9, 0))
        main = ttk.Frame(self.root)
        main.pack(side="left", fill="both", expand=True)
        top = tk.Frame(main, bg=WHITE)
        top.pack(fill="x")
        self.breadcrumb = tk.Label(top, text="워크스페이스  /  개요", bg=WHITE, fg=MUTED, font=("맑은 고딕", 9))
        self.breadcrumb.pack(side="left", fill="x", expand=True, padx=20, pady=12)
        self.mode_buttons = {}
        for mode, label in (("real", "실제 수집"), ("demo", "데모 보기")):
            button = Button(top, text=label, command=lambda m=mode: self.switch_mode(m))
            button.pack(side="right", padx=(0, 10), pady=12)
            self.mode_buttons[mode] = button
            button.configure(style="Soft.TButton" if mode == self.mode.get() else "TButton")
        self.mode_label = tk.Label(top, text="●  DEMO · 합성 예시", fg=AMBER, bg="#fff3e2", padx=10, pady=5,
                                   font=("맑은 고딕", 8, "bold"))
        self.mode_label.pack(side="right", before=self.breadcrumb, padx=12, pady=12)
        for button in self.mode_buttons.values():
            button.pack_configure(before=self.breadcrumb)
        toolbar = ttk.Frame(main)
        toolbar.pack(fill="x", padx=28, pady=(25, 22))
        toolbar.columnconfigure(0, weight=1)
        heading = ttk.Frame(toolbar)
        heading.grid(row=0, column=0, sticky="ew", padx=(0, 16))
        self.title_label = ttk.Label(heading, text="", style="Heading.TLabel", wraplength=500)
        self.title_label.pack(anchor="w", fill="x")
        self.subtitle_label = ttk.Label(heading, text="", style="Muted.TLabel", wraplength=500)
        self.subtitle_label.pack(anchor="w", fill="x", pady=(6, 0))
        self.collection_actions = ttk.Frame(toolbar)
        self.collection_actions.grid(row=0, column=1, sticky="e")
        self.run_button = Button(self.collection_actions, text="＋  수집 실행", style="Primary.TButton", command=self.run_collection)
        self.run_button.pack(side="right", padx=(8, 0))
        self.cancel_button = Button(self.collection_actions, text="수집 중지", command=self.cancel_collection)
        self.cancel_button.state(["disabled"])
        bind_wrap(heading, (self.title_label, self.subtitle_label))
        self.content = ttk.Frame(main)
        self.content.pack(fill="both", expand=True, padx=28)
        bottom = ttk.Frame(main)
        bottom.pack(side="bottom", before=self.content, fill="x", padx=28, pady=10)
        self.footer = bottom
        self.status_text = tk.StringVar(value="준비됨 · Ctrl+F 검색 / F5 새로고침")
        refresh = Button(bottom, text="↻  새로고침", command=self.refresh)
        refresh.pack(side="right", padx=(12, 0))
        status = ttk.Label(bottom, textvariable=self.status_text, style="Muted.TLabel", wraplength=500)
        status.pack(side="left", fill="x", expand=True)
        bind_wrap(status, (status,))

    def flow_row(self, frame):
        widgets = frame.winfo_children()
        for widget in widgets:
            widget.pack_forget()
        placements = {}
        widths = {widget: widget.winfo_reqwidth() + 8 for widget in widgets}
        def layout(available):
            row = column = used = 0
            for widget in widgets:
                width = widths[widget]
                if column and used + width > available:
                    row, column, used = row + 1, 0, 0
                position = row, column
                if placements.get(widget) != position:
                    widget.grid(row=row, column=column, sticky="w", padx=(0, 8), pady=(0, 6))
                    placements[widget] = position
                column, used = column + 1, used + width
        task = bind_resize(frame, layout)
        task.schedule()

    def focus_search(self, event=None):
        if self.view != "findings":
            self.navigate("findings")
        self.search_entry.focus_set()
        self.search_entry.selection_range(0, "end")
        return "break"

    def scroll_wheel(self, event):
        widget = event.widget
        while widget is not None:
            if isinstance(widget, (tk.Text, ttk.Treeview, ttk.Combobox)):
                return
            if isinstance(widget, tk.Canvas) and getattr(widget, "scrollable", False):
                if widget.bbox("all") and widget.bbox("all")[3] > widget.winfo_height():
                    widget.yview_scroll(-int(event.delta / 120) or (-1 if event.delta > 0 else 1), "units")
                return "break"
            widget = getattr(widget, "master", None)

    def switch_mode(self, mode):
        self.mode.set(mode)
        for key, button in self.mode_buttons.items():
            button.configure(style="Soft.TButton" if key == mode else "TButton")
        self.last_signature = None
        self.offset, self.filters = 0, {}
        self.mode_label.configure(text="●  DEMO · 합성 예시" if mode == "demo" else "●  LIVE · 실제 수집",
                                  fg=AMBER if mode == "demo" else GREEN, bg="#fff3e2" if mode == "demo" else "#eaf6f1")
        self.navigate(self.view)

    def navigate(self, view):
        self.view = view
        for key, button in self.nav_buttons.items():
            button.configure(style="Selected.Nav.TButton" if key == view else "Nav.TButton")
        for child in self.content.winfo_children():
            child.destroy()
        names = dict(overview=("모니터링 개요", "외부에 드러난 정보와 확인이 필요한 신호를 한곳에서 관리하세요."),
            findings=("검색 결과·취약점 후보", "검색 색인과 관측 정보입니다. 실제 취약 여부는 담당자 검증이 필요합니다."),
            targets=("점검 대상", "기관의 도메인·키워드·IP 대역·제품·추적 CVE를 등록합니다. 실제 대상은 자동으로 생성되지 않습니다."),
            providers=("API 연동", "키는 Windows DPAPI로 암호화합니다. 저장된 키는 다시 표시하지 않습니다."),
            rules=("검색 규칙", "첨부 표의 검색 목적에 맞춰 대상별 규칙을 생성합니다. 오래 실행하지 않은 규칙부터 순환 수집합니다."),
            runs=("수집 이력", "0건 검색, 부분 성공, 권한 오류, 호출 제한을 구분해 확인하세요."),
            settings=("자동 수집 설정", "프로그램 실행 중에만 실제 수집이 예약 실행됩니다. 종료하면 자동 수집도 멈춥니다."))
        self.breadcrumb.configure(text="워크스페이스  /  " + names[view][0])
        self.title_label.configure(text=names[view][0])
        self.subtitle_label.configure(text=names[view][1])
        getattr(self, "show_" + view)()

    def refresh(self):
        self.navigate(self.view)

    def notify(self, text):
        self.status_text.set(text)

    def guard_edit(self):
        if self.engine.lock.locked():
            messagebox.showinfo("수집 진행 중", "수집을 중지하거나 완료한 뒤 대상·API·규칙을 변경하세요.", parent=self.root)
            return False
        return True

    def run_collection(self):
        try:
            run_id = self.engine.start(self.mode.get())
            self.notify(f"실행 #{run_id} 시작 · {'데모: 실제 API 호출 없음' if self.mode.get() == 'demo' else '실제 API 수집 중'}")
        except ValueError as exc:
            messagebox.showinfo("수집 준비", str(exc), parent=self.root)

    def cancel_collection(self):
        self.engine.cancel.set()
        self.notify("수집 중지 요청됨 · 현재 네트워크 요청은 타임아웃까지 걸릴 수 있습니다.")

    def poll(self):
        busy = self.engine.lock.locked()
        if busy and self.engine.progress:
            self.notify(self.engine.progress)
        if busy and not self.cancel_button.winfo_manager():
            self.cancel_button.pack(side="right", padx=4)
        elif not busy:
            self.cancel_button.pack_forget()
        self.run_button.state(["disabled"] if busy else ["!disabled"])
        self.cancel_button.state(["!disabled"] if busy else ["disabled"])
        overview = self.store.overview(self.mode.get())
        signature = tuple((r["id"], r["status"]) for r in overview["runs"][:2])
        if self.last_signature is not None and signature != self.last_signature:
            if overview["runs"]:
                run = overview["runs"][0]
                self.notify(f"실행 #{run['id']} · {RUN_LABEL.get(run['status'], run['status'])} · {run['message']}")
            if self.view in ("overview", "findings", "runs"):
                self.navigate(self.view)
        self.last_signature = signature
        self.root.after(1500, self.poll)

    def table(self, parent, columns, height=12):
        frame = TableFrame(parent)
        frame.pack(fill="both", expand=True)
        tree = ResultList(frame, columns=[c[0] for c in columns], show="headings", height=height, selectmode="browse")
        heading_font = tkfont.Font(root=self.root, font=("맑은 고딕", 10, "bold"))
        heading_padding = round(14 * float(self.root.tk.call("tk", "scaling")) / (96 / 72))
        for key, label, width in columns:
            minimum = max(55, heading_font.measure(label) + heading_padding)
            alignment = "center" if key in ("enabled", "key", "usage", "status", "severity", "id", "count", "new") else "w"
            tree.heading(key, text=label, anchor=alignment)
            tree.column(key, width=max(width, minimum), minwidth=minimum, anchor=alignment, stretch=key in ("title", "query", "message", "name"))
        scroll = AutoScrollbar(frame, orient="vertical", command=tree.yview)
        hscroll = AutoScrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=scroll.set, xscrollcommand=hscroll.set)
        tree.grid(row=0, column=0, sticky="nsew", padx=(frame.edge,frame.edge), pady=(frame.edge,frame.edge))
        scroll.grid(row=0, column=1, sticky="ns", padx=(0,frame.edge), pady=(frame.edge,frame.edge))
        hscroll.grid(row=1, column=0, sticky="ew", padx=(frame.edge,frame.edge), pady=(0,frame.edge))
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree.tag_configure("high", foreground="#a95532", background="#fff8f3")
        tree.tag_configure("critical", foreground="#b54357", background="#fff2f3")
        tree.tag_configure("muted", foreground=MUTED)
        return tree

    def scroll_panel(self, parent, padding=20):
        outer = ttk.Frame(parent, style="Card.TFrame")
        canvas = tk.Canvas(outer, bg=BG, bd=0, highlightthickness=0)
        canvas.scrollable = True
        scrollbar = AutoScrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")
        canvas.grid(row=0, column=0, sticky="nsew")
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)
        inner = ttk.Frame(canvas, padding=padding, style="Card.TFrame")
        window = canvas.create_window(0, 0, window=inner, anchor="nw")
        CanvasLayout(canvas, inner, window, padding=padding, wrap=True)
        return outer, inner

    def show_overview(self):
        data = self.store.overview(self.mode.get())
        outer, body = self.scroll_panel(self.content, padding=0)
        outer.pack(fill="both", expand=True)
        body.configure(style="TFrame")
        hero = RoundedPanel(body, color=SOFT, padding=16)
        hero.pack(fill="x", pady=(0, 16))
        hero_left = tk.Frame(hero.body, bg=SOFT)
        hero_left.pack(side="left", fill="x", expand=True)
        tk.Label(hero_left, text="YOUR SECURITY, AT A GLANCE", bg=SOFT, fg=TEAL,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(hero_left, text=f"확인이 필요한 신호, {data['open']}건" if data["total"] else "첫 모니터링을 시작해 보세요",
                 bg=SOFT, fg=TEXT, font=("맑은 고딕", 15, "bold")).pack(anchor="w", pady=(5, 4))
        tk.Label(hero_left, text="합성 예시 데이터입니다. 실제 기관의 취약점을 의미하지 않습니다." if self.mode.get() == "demo"
                 else "공개 정보에서 발견한 후보의 근거를 확인하고 검토를 기록하세요.",
                 bg=SOFT, fg=MUTED, wraplength=520, justify="left", font=("맑은 고딕", 9)).pack(anchor="w")
        Button(hero.body, text="검토 시작  →" if data["total"] else "점검 대상 등록  →", style="Primary.TButton",
                   command=lambda: self.navigate("findings") if data["total"] else self.target_form()).pack(side="right", before=hero_left, padx=(12, 0))
        bind_wrap(hero_left, hero_left.winfo_children())
        strip = ttk.Frame(body)
        strip.pack(fill="x", pady=(0, 16))
        cards = [("전체 수집 결과", data["total"], "출처별 중복 통합", TEAL, WHITE),
                 ("검토·조치 필요", data["open"], "완료·오탐·수용 제외", TEXT, WHITE),
                 ("높은 위험 후보", data["high"], "검증 전 · 우선 확인", "#b95b50", "#fff0ec"),
                 ("오늘 신규 발견", data["new_today"], "UTC 일자 기준", GREEN, "#eaf6f1")]
        for index, (title, value, note, color, surface) in enumerate(cards):
            card = RoundedPanel(strip, color=surface, padding=14)
            card.grid(row=0, column=index, sticky="nsew", padx=(0, 12) if index < 3 else 0)
            strip.columnconfigure(index, weight=1, uniform="card")
            tk.Label(card.body, text=title, bg=surface, fg=MUTED, anchor="w", font=("맑은 고딕", 9)).pack(fill="x")
            tk.Label(card.body, text=f"{value:02d}", bg=surface, fg=color,
                     font=("Segoe UI", 25, "bold"), anchor="w").pack(fill="x", pady=3)
            tk.Label(card.body, text=note, bg=surface, fg=MUTED, font=("맑은 고딕", 8), anchor="w").pack(fill="x")
        middle = ttk.Frame(body)
        # Supporting charts follow the actionable review list.
        middle.columnconfigure(0, weight=3, uniform="middle")
        middle.columnconfigure(1, weight=2, uniform="middle")
        distribution = RoundedPanel(middle, padding=18)
        distribution.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        tk.Label(distribution.body, text="어떤 신호가 발견됐나요?", bg=WHITE, fg=TEXT,
                 font=("맑은 고딕", 11, "bold")).pack(anchor="w", pady=(0, 12))
        colors = [TEAL, "#8190e4", "#b4bced", "#dd9a79", "#69a995", "#cf8090", "#9b8fba"]
        chart = tk.Canvas(distribution.body, height=14, bg=WHITE, bd=0, highlightthickness=0)
        chart.pack(fill="x")
        segments = [chart.create_rectangle(0,0,0,14, fill=color, outline=WHITE, width=2) for color in colors]
        empty_bar = chart.create_rectangle(0,0,0,14, fill=BG, outline="")
        def draw(width):
            x = 0
            for (_, value), segment in zip(data["kinds"].items(), segments):
                end = x + width * value / max(1, data["total"])
                chart.coords(segment, x, 0, end, 14)
                x = end
            chart.coords(empty_bar, 0, 0, width if not data["total"] else 0, 14)
        bind_resize(chart, draw)
        legend = tk.Frame(distribution.body, bg=WHITE)
        legend.pack(fill="x", pady=(10, 0))
        for i, ((kind, value), color) in enumerate(zip(data["kinds"].items(), colors)):
            tk.Label(legend, text=f"● {KIND_LABEL[kind]}  {value}", bg=WHITE, fg=color,
                     font=("맑은 고딕", 8), anchor="w").grid(row=i//3, column=i%3, sticky="w", padx=(0, 12), pady=2)
        setup = RoundedPanel(middle, padding=18)
        setup.grid(row=0, column=1, sticky="nsew")
        tk.Label(setup.body, text="모니터링 준비", bg=WHITE, fg=TEXT,
                 font=("맑은 고딕", 11, "bold")).pack(anchor="w", pady=(0, 8))
        connected = sum(p["enabled"] for p in self.store.providers() if p["supported"])
        target_count = len(self.store.targets(demo=False))
        for title, value, dest in [("01  점검 대상", f"{target_count}개 등록", "targets"),
                                    ("02  API 연동", f"{connected}개 활성", "providers"),
                                    ("03  자동 수집", "사용 중" if self.store.settings()["schedule_enabled"] else "설정하기", "settings")]:
            button = Button(setup.body, text=f"{title}     {value}  →", style="Card.TButton",
                                cursor="hand2", command=lambda v=dest: self.navigate(v))
            button.pack(fill="x", pady=2)
        results = RoundedPanel(body, padding=18)
        results.pack(fill="both", expand=True, pady=(0, 16))
        head = tk.Frame(results.body, bg=WHITE)
        head.pack(fill="x", pady=(0, 12))
        tk.Label(head, text="우선 검토할 검색 결과", bg=WHITE, fg=TEXT,
                 font=("맑은 고딕", 12, "bold")).pack(side="left")
        Button(head, text="전체 결과 보기  →", style="Soft.TButton", command=lambda: self.navigate("findings")).pack(side="right")
        tree = self.table(results.body, [("severity", "위험도", 75), ("title", "제목 / 후보", 310),
                ("kind", "유형", 100), ("status", "검토 상태", 110), ("seen", "최근 수집", 115)], height=4)
        for row in self.store.findings(self.mode.get(), {"limit": 8})["items"]:
            tree.insert("", "end", iid=str(row["id"]), values=("● " + SEV_LABEL[row["severity"]], row["title"],
                KIND_LABEL[row["kind"]], STATUS_LABEL[row["status"]], local_time(row["last_seen"])), tags=(row["severity"],))
        tree.bind("<Double-1>", lambda e: self.open_selected(tree))
        tree.bind("<Return>", lambda e: self.open_selected(tree))
        tk.Label(results.body, text="위험도순으로 표시합니다. 행을 두 번 클릭하거나 Enter를 눌러 근거와 조치 이력을 확인하세요.",
                 bg=WHITE, fg=MUTED, font=("맑은 고딕", 8), wraplength=780).pack(anchor="w", pady=(10, 0))
        card_mode = None
        threshold = round(900 * float(self.root.tk.call('tk', 'scaling')) / (96 / 72))
        def arrange_cards(width):
            nonlocal card_mode
            # A small dead band prevents scroll-track visibility flipping the layout.
            stacked = width < threshold + (16 if card_mode else 0)
            if stacked == card_mode:
                return
            card_mode = stacked
            if stacked:
                distribution.grid_configure(row=0, column=0, columnspan=2, padx=0, pady=(0, 12))
                setup.grid_configure(row=1, column=0, columnspan=2)
            else:
                distribution.grid_configure(row=0, column=0, columnspan=1, padx=(0, 14), pady=0)
                setup.grid_configure(row=0, column=1, columnspan=1)
        bind_resize(middle, arrange_cards)
        middle.pack(fill="x", pady=(0, 16))

    def combo_filter(self, parent, name, labels, width):
        names = dict(severity="위험도", status="상태", provider="출처")
        mapping = {"전체 " + names.get(name, name): "", **labels}
        variable = tk.StringVar(value=next((label for label, value in mapping.items() if value == self.filters.get(name, "")), next(iter(mapping))))
        box = ttk.Combobox(parent, textvariable=variable, values=list(mapping), state="readonly", width=width)
        box.pack(side="left", padx=(0, 7))
        return variable, mapping

    def show_findings(self):
        row = ttk.Frame(self.content)
        row.pack(fill="x", pady=(0, 9))
        q = tk.StringVar(value=self.filters.get("q", ""))
        ttk.Label(row, text="검색어", style="Muted.TLabel").pack(side="left", padx=(0, 8))
        self.search_entry = ttk.Entry(row, textvariable=q, width=29)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        controls = []
        filter_row = ttk.Frame(self.content)
        filter_row.pack(fill="x", pady=(0, 12))
        for field, labels, width in [("severity", {v: k for k, v in SEV_LABEL.items()}, 10),
            ("status", {v: k for k, v in STATUS_LABEL.items()}, 15),
            ("provider", {p["name"]: p["id"] for p in self.store.providers() if p["supported"]}, 14)]:
            var, mapping = self.combo_filter(filter_row, field, labels, width)
            controls.append((field, var, mapping))
        def apply():
            self.filters = {"q": q.get().strip(), "target_id": self.filters.get("target_id", ""),
                            **{field: mapping[var.get()] for field, var, mapping in controls}}
            self.offset = 0
            self.navigate("findings")
        Button(row, text="검색", style="Primary.TButton", command=apply).pack(side="right", before=self.search_entry)
        self.search_entry.bind("<Return>", lambda e: apply())
        def reset():
            self.filters, self.offset = {}, 0
            self.navigate("findings")
        Button(filter_row, text="필터 초기화", command=reset).pack(side="right")
        for control in filter_row.winfo_children():
            if isinstance(control, ttk.Combobox):
                control.bind("<<ComboboxSelected>>", lambda e: apply())
        self.flow_row(filter_row)
        second = ttk.Frame(self.content)
        second.pack(fill="x", pady=(0, 12))
        targets = {"전체 점검 대상": "", **{t["name"] + f" (#{t['id']})": str(t["id"]) for t in self.store.targets(demo=self.mode.get() == "demo")}}
        target_var = tk.StringVar(value=next((k for k,v in targets.items() if v == self.filters.get("target_id", "")), "전체 점검 대상"))
        box = ttk.Combobox(second, textvariable=target_var, values=list(targets), width=28, state="readonly")
        box.pack(side="left")
        def target_changed(e):
            self.filters["target_id"] = targets[target_var.get()]
            self.offset = 0
            self.navigate("findings")
        box.bind("<<ComboboxSelected>>", target_changed)
        Button(second, text="CSV 내보내기", command=self.export_results).pack(side="right")
        detail_button = Button(second, text="선택 결과 검토  →", command=lambda: self.open_selected(tree))
        detail_button.pack(side="right", padx=8)
        detail_button.state(["disabled"])
        self.flow_row(second)
        page = self.store.findings(self.mode.get(), dict(self.filters, offset=self.offset, limit=25))
        tree = self.table(self.content, [("severity", "위험도", 75), ("title", "제목", 330), ("target", "대상", 120),
            ("asset", "자산", 170), ("kind", "유형", 100), ("sources", "출처", 140), ("status", "상태", 130), ("seen", "최근 수집", 120)])
        for item in page["items"]:
            tree.insert("", "end", iid=str(item["id"]), values=(SEV_LABEL[item["severity"]], item["title"], item["target_name"],
                item["asset"], KIND_LABEL[item["kind"]], ", ".join(item["sources"]), STATUS_LABEL[item["status"]], local_time(item["last_seen"])), tags=(item["severity"],))
        tree.bind("<Double-1>", lambda e: self.open_selected(tree))
        tree.bind("<Return>", lambda e: self.open_selected(tree))
        tree.bind("<<TreeviewSelect>>", lambda e: detail_button.state(["!disabled"] if tree.selection() else ["disabled"]))
        footer = ttk.Frame(self.content)
        footer.pack(side="bottom", before=tree.master, fill="x", pady=12)
        self.pagination = footer
        ttk.Label(footer, text=f"총 {page['total']}건 · {min(self.offset + 1, page['total'])}–{self.offset + len(page['items'])} 표시", style="Muted.TLabel").pack(side="left")
        def move(delta):
            self.offset = max(0, self.offset + delta)
            self.navigate("findings")
        next_button = Button(footer, text="다음 →", command=lambda: move(25))
        next_button.pack(side="right")
        prev_button = Button(footer, text="← 이전", command=lambda: move(-25))
        prev_button.pack(side="right", padx=7)
        if self.offset + 25 >= page["total"]:
            next_button.state(["disabled"])
        if not self.offset:
            prev_button.state(["disabled"])
        if not page["total"]:
            ttk.Label(footer, text="  대상과 API를 등록하고 수집을 실행하세요.", foreground=TEAL).pack(side="left")

    def open_selected(self, tree):
        selected = tree.selection()
        if selected:
            self.finding_detail(int(selected[0]))

    def finding_detail(self, finding_id):
        item = self.store.detail(finding_id)
        if not item:
            return
        win = tk.Toplevel(self.root)
        win.title("검색 결과 상세 · 검토")
        win.geometry("960x780")
        win.minsize(800, 650)
        win.configure(bg=BG)
        win.transient(self.root)
        win.bind("<Escape>", lambda e: win.destroy())
        body = ttk.Frame(win, padding=22)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=item["title"], font=("맑은 고딕", 15, "bold"), wraplength=880).pack(anchor="w")
        ttk.Label(body, text=f"{'데모' if item['mode']=='demo' else '실제 수집'}  ·  {SEV_LABEL[item['severity']]} 위험 후보  ·  신뢰도 {item['confidence']}  ·  {KIND_LABEL[item['kind']]}",
                  foreground=TEAL).pack(anchor="w", pady=(7, 12))
        tabs = ttk.Notebook(body)
        tabs.pack(fill="both", expand=True)
        evidence_tab, review_tab, history_tab = (ttk.Frame(tabs, padding=14) for _ in range(3))
        tabs.add(evidence_tab, text="발견 근거·출처")
        tabs.add(review_tab, text="검토·조치")
        tabs.add(history_tab, text="변경·처리 이력")
        text = self.text_area(evidence_tab)
        header = (f"자산: {item['asset']}\nURL: {item['url']}\n분류 근거: {item['reason']}\n"
                  f"최초 수집: {local_time(item['first_seen'])}\n최근 수집: {local_time(item['last_seen'])}\n"
                  f"제공자 관측: {item['observed_at'] or '제공되지 않음'}\nCVE: {', '.join(item['cves']) or '없음'}\n"
                  f"내용 변경: {item['change_count']}회\n\n{item['summary']}\n\n")
        text.insert("end", header)
        for sight in item["sightings"]:
            text.insert("end", f"{'─'*48}\n출처: {PROVIDER_MAP[sight['provider']]['name']}\n검색어: {sight['query']}\n"
                f"관측 시각: {sight['observed_at'] or '미제공'}\n수집: {local_time(sight['first_seen'])} ~ {local_time(sight['last_seen'])} · {sight['count']}회\n"
                + json.dumps(sight["evidence"], ensure_ascii=False, indent=2) + "\n\n")
        text.configure(state="disabled")
        ttk.Label(evidence_tab, text="검색 대상 URL은 자동 방문·다운로드하지 않습니다. 피싱 후보 주소도 자동으로 열지 않습니다.", style="Muted.TLabel", wraplength=850).pack(anchor="w", pady=(10, 0))
        status = tk.StringVar(value=STATUS_LABEL[item["status"]])
        owner = tk.StringVar(value=item["owner"])
        ttk.Label(review_tab, text="검토 상태").pack(anchor="w", pady=(0, 6))
        ttk.Combobox(review_tab, textvariable=status, values=list(STATUS_LABEL.values()), state="readonly", width=30).pack(anchor="w")
        ttk.Label(review_tab, text="담당자 / 부서").pack(anchor="w", pady=(15, 6))
        ttk.Entry(review_tab, textvariable=owner, width=50).pack(anchor="w")
        ttk.Label(review_tab, text="검토 근거·조치 메모").pack(anchor="w", pady=(15, 6))
        note = self.text_area(review_tab, height=8)
        note.insert("1.0", item["note"])
        def save():
            try:
                self.store.update_finding(finding_id, next(k for k,v in STATUS_LABEL.items() if v == status.get()), owner.get().strip(), note.get("1.0", "end-1c"))
                self.notify("검토 상태와 처리 이력을 저장했습니다.")
                win.destroy()
                self.refresh()
            except ValueError as exc:
                messagebox.showerror("저장 실패", str(exc), parent=win)
        Button(review_tab, text="검토 저장", style="Primary.TButton", command=save).pack(anchor="e", pady=14)
        history = self.text_area(history_tab)
        for event in item["events"]:
            history.insert("end", f"{local_time(event['created_at'])}  {event['message']}\n\n")
        history.configure(state="disabled")
        Button(body, text="닫기", command=win.destroy).pack(anchor="e", pady=(12, 0))

    def text_area(self, parent, height=12):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        text = tk.Text(frame, wrap="word", height=height, bg=WHITE, fg=TEXT, relief="flat", bd=0,
                       highlightthickness=1, highlightbackground=LINE, highlightcolor=TEAL, insertbackground=TEXT, selectbackground=SOFT, selectforeground=TEXT, padx=12, pady=10, font=("맑은 고딕", 10), undo=True)
        scroll = AutoScrollbar(frame, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return text

    def export_results(self):
        path = filedialog.asksaveasfilename(parent=self.root, title="검색 결과 CSV 내보내기", defaultextension=".csv",
            initialfile=f"sentinel-{self.mode.get()}-{datetime.now():%Y%m%d}.csv", filetypes=[("Excel 호환 CSV", "*.csv")])
        if path:
            count = export_csv(self.store, path, self.mode.get(), self.filters)
            self.notify(f"현재 필터의 결과 {count}건을 CSV로 저장했습니다.")

    def show_targets(self):
        bar = ttk.Frame(self.content)
        bar.pack(fill="x", pady=(0, 14))
        ttk.Label(bar, text="실제 점검 대상과 예시 대상은 분리되어 저장됩니다.", style="Muted.TLabel").pack(anchor="w", pady=(0, 10))
        actions = ttk.Frame(bar)
        actions.pack(fill="x")
        Button(actions, text="＋ 점검 대상 등록", style="Primary.TButton", command=self.target_form).pack(side="right")
        edit = Button(actions, text="선택 수정", command=lambda: self.edit_target(tree))
        edit.pack(side="left", padx=(0, 8))
        delete = Button(actions, text="선택 삭제", style="Danger.TButton", command=lambda: self.delete_target(tree))
        delete.pack(side="left")
        edit.state(["disabled"])
        delete.state(["disabled"])
        tree = self.table(self.content, [("name", "기관 / 대상명", 180), ("domains", "도메인", 220), ("cidrs", "IP / CIDR", 180),
            ("keywords", "키워드", 180), ("owner", "담당", 100), ("enabled", "상태", 90)])
        for target in self.store.targets(demo=self.mode.get() == "demo"):
            tree.insert("", "end", iid=str(target["id"]), values=(target["name"], ", ".join(target["domains"]), ", ".join(target["cidrs"]),
                ", ".join(target["keywords"]), target["owner"], "활성" if target["enabled"] else "중지"))
        tree.bind("<Double-1>", lambda e: self.edit_target(tree))
        def selection_changed(e):
            selected = tree.selection()
            editable = selected and not self.store.target(int(selected[0]))["demo"]
            for button in (edit, delete):
                button.state(["!disabled"] if editable else ["disabled"])
        tree.bind("<<TreeviewSelect>>", selection_changed)
        ttk.Label(self.content, text="제품명 일치는 권고 후보만 생성합니다. 취약 버전 여부를 자동으로 확정하지 않습니다.", style="Muted.TLabel", wraplength=750).pack(side="bottom", before=tree.master, anchor="w", pady=12)

    def edit_target(self, tree):
        if tree.selection():
            self.target_form(self.store.target(int(tree.selection()[0])))

    def target_form(self, target=None):
        if not self.guard_edit():
            return
        if target and target["demo"]:
            messagebox.showinfo("예시 대상", "데모 대상은 수정할 수 없습니다. 실제 점검 대상을 새로 등록하세요.", parent=self.root)
            return
        win = tk.Toplevel(self.root)
        win.title("점검 대상 수정" if target else "점검 대상 등록")
        win.geometry("750x790")
        win.configure(bg=BG)
        win.transient(self.root)
        win.bind("<Escape>", lambda e: win.destroy())
        outer, body = self.scroll_panel(win, padding=22)
        outer.pack(fill="both", expand=True)
        ttk.Label(body, style="Card.TLabel", text="기관과 점검 범위", font=("맑은 고딕", 17, "bold")).pack(anchor="w")
        ttk.Label(body, text="관리 권한이 있는 범위를 등록하세요. 목록은 쉼표 또는 줄바꿈으로 구분합니다.", style="CardMuted.TLabel", wraplength=650).pack(anchor="w", pady=(5, 15))
        fields = {}
        for key, label, hint in [("name", "기관 / 대상명 *", "예: 우리 기관"), ("owner", "담당자 / 부서", "예: 보안운영팀"),
            ("domains", "공식 도메인", "예: example.com (https:// 없이 입력)"), ("keywords", "기관명·브랜드 키워드", "예: 기관명, 영문 약칭"),
            ("cidrs", "IP / CIDR", "예: 192.0.2.0/24"), ("products", "추적 제품명", "예: Fortinet FortiOS"),
            ("cves", "추적 CVE", "예: CVE-2024-3400")]:
            row = ttk.Frame(body, style="Card.TFrame")
            row.pack(fill="x", pady=6)
            ttk.Label(row, text=label, width=18, style="Card.TLabel").pack(side="left", anchor="n", pady=7)
            right = ttk.Frame(row, style="Card.TFrame")
            right.pack(side="left", fill="x", expand=True)
            value = (target or {}).get(key, "")
            variable = tk.StringVar(value=", ".join(value) if isinstance(value, list) else value)
            ttk.Entry(right, textvariable=variable).pack(fill="x")
            ttk.Label(right, text=hint, style="CardMuted.TLabel", font=("맑은 고딕", 8)).pack(anchor="w", pady=(2, 0))
            fields[key] = variable
        enabled = tk.BooleanVar(value=(target or {}).get("enabled", True))
        ttk.Checkbutton(body, text="수집 대상 활성화", variable=enabled).pack(anchor="w", pady=15)
        error = tk.StringVar()
        ttk.Label(body, textvariable=error, foreground="#b24735", background=WHITE, wraplength=680).pack(anchor="w")
        def save():
            if not self.guard_edit():
                return
            try:
                self.store.save_target({**{key: value.get() for key, value in fields.items()}, "enabled": enabled.get()}, target["id"] if target else None)
                self.mode.set("real")
                win.destroy()
                self.switch_mode("real")
                self.notify("점검 대상과 검색 규칙을 저장했습니다.")
            except ValueError as exc:
                error.set(str(exc))
        Button(body, text="대상 저장·규칙 생성", style="Primary.TButton", command=save).pack(anchor="e", pady=15)

    def delete_target(self, tree):
        if not self.guard_edit() or not tree.selection():
            return
        target = self.store.target(int(tree.selection()[0]))
        if target["demo"]:
            messagebox.showinfo("예시 대상", "데모 대상은 삭제하지 않습니다.", parent=self.root)
            return
        if messagebox.askyesno("점검 대상 삭제", f"{target['name']}의 대상·규칙·수집 결과·검토 이력을 삭제할까요? 이 작업은 되돌릴 수 없습니다.", parent=self.root):
            self.store.delete_target(target["id"])
            self.refresh()

    def show_providers(self):
        paned = ttk.Panedwindow(self.content, orient="horizontal")
        paned.pack(fill="both", expand=True)
        left = ttk.Frame(paned)
        provider_outer, self.provider_form_area = self.scroll_panel(paned)
        paned.add(left, weight=2)
        paned.add(provider_outer, weight=3)
        tree = self.table(left, [("name", "제공자", 145), ("enabled", "상태", 90), ("key", "API 키", 90), ("usage", "요청 / 일", 100)])
        for provider in self.store.providers():
            state = "사용 중" if provider["enabled"] else "꺼짐" if provider["supported"] else "미지원"
            tree.insert("", "end", iid=provider["id"], values=(provider["name"], state,
                "등록됨" if provider["has_key"] else "불필요" if not provider["needs_key"] else "미등록",
                f"{provider['used_today']}/{provider['daily_limit']}" if provider["supported"] else "—"), tags=() if provider["supported"] else ("muted",))
        def select(e=None):
            if tree.selection():
                self.provider_form(tree.selection()[0])
        tree.bind("<<TreeviewSelect>>", select)
        tree.selection_set("brave")
        self.provider_form("brave")

    def provider_form(self, provider_id):
        body = self.provider_form_area
        body.invalidate_layout()
        body.master.yview_moveto(0)
        for child in body.winfo_children():
            child.destroy()
        provider = next(p for p in self.store.providers() if p["id"] == provider_id)
        def label(text, **options):
            widget = ttk.Label(body, text=text, style="Card.TLabel", **options)
            widget.pack(anchor="w", pady=(0, 8))
            return widget
        label(provider["name"], font=("맑은 고딕", 20, "bold"))
        label(provider["description"], wraplength=490)
        Button(body, text="공식 문서 열기 ↗", command=lambda: webbrowser.open(provider["docs"])).pack(anchor="w", pady=(0, 18))
        if not provider["supported"]:
            label("현재 버전은 이 서비스의 자동 수집을 지원하지 않습니다.", wraplength=470)
            return
        enabled = tk.BooleanVar(value=provider["enabled"])
        ttk.Checkbutton(body, text="실제 수집에 사용", variable=enabled).pack(anchor="w", pady=(0, 17))
        key = tk.StringVar()
        clear_key = tk.BooleanVar(value=False)
        backend_labels = {"HTML 직접 수집 (키 불필요)": "direct_html", "SerpApi (API 키 필요)": "serpapi"}
        backend = tk.StringVar(value=next(k for k, v in backend_labels.items() if v == provider["search_backend"]))
        if provider_id in ("google", "baidu"):
            label("검색 수집 방식")
            selector = ttk.Combobox(body, textvariable=backend, values=list(backend_labels), state="readonly")
            selector.pack(fill="x", pady=(0, 10))
            label("직접 수집: 앱 전용 Edge 세션을 재사용합니다. 수집 실행을 직접 누르면 Edge 창이 열립니다. 인증 화면은 직접 완료하면 자동 재개합니다(최대 5분). 예약 실행은 창 없이 수집하며 인증 필요 시 이력에 표시합니다. 요청 사이 최소 10초 간격입니다.", wraplength=480, font=("맑은 고딕", 9))
        if provider["needs_key"] or provider_id in ("google", "baidu"):
            key_label = "SerpApi API 키" if provider_id in ("google", "baidu", "zoneh", "xssed") else "API 키 / PAT"
            label(key_label + ("  ·  기존 키가 암호화되어 저장되어 있습니다." if provider["has_key"] else "  ·  SerpApi 선택 시 필요" if provider_id in ("google", "baidu") else "  ·  등록 필요"), wraplength=480)
            if provider_id in ("google", "baidu", "zoneh", "xssed"):
                label("동일한 SerpApi 키를 각 항목에 등록할 수 있습니다. 네 항목의 제공자 크레딧은 공유되며 아래 앱 호출 상한은 항목별입니다.", wraplength=480, font=("맑은 고딕", 9))
            entry = ttk.Entry(body, textvariable=key, show="●")
            entry.pack(fill="x")
            if provider_id in ("google", "baidu"):
                def update_key_state(_event=None):
                    entry.configure(state="disabled" if backend_labels[backend.get()] == "direct_html" else "normal")
                selector.bind("<<ComboboxSelected>>", update_key_state)
                update_key_state()
            label("비워 두면 기존 키를 유지합니다. 저장된 키는 화면에 반환하지 않습니다.", wraplength=480, font=("맑은 고딕", 9))
            show = tk.BooleanVar(value=False)
            ttk.Checkbutton(body, text="입력 중인 키 표시", variable=show, command=lambda: entry.configure(show="" if show.get() else "●")).pack(anchor="w", pady=5)
            ttk.Checkbutton(body, text="기존 키 삭제", variable=clear_key).pack(anchor="w", pady=5)
            label("키를 삭제하려면 먼저 실제 수집 사용을 해제하세요.", wraplength=480, font=("맑은 고딕", 9))
        organization = tk.StringVar(value=provider["organization_id"])
        if provider_id == "censys":
            label("Organization ID (선택)")
            ttk.Entry(body, textvariable=organization).pack(fill="x", pady=(0, 12))
        label("일일 HTTP 요청 상한 (UTC 일자 · 제공자 과금 크레딧과 다름)", wraplength=480)
        limit = tk.StringVar(value=str(provider["daily_limit"]))
        ttk.Spinbox(body, from_=1, to=10000, textvariable=limit, width=15).pack(anchor="w", pady=(0, 12))
        pages = tk.StringVar(value=str(provider["pages"]))
        if provider_id not in ("cisa", "phishtank"):
            label("규칙당 최대 페이지 (1~3)")
            ttk.Spinbox(body, from_=1, to=3, textvariable=pages, width=15).pack(anchor="w", pady=(0, 12))
        label(f"오늘 요청: {provider['used_today']}회  ·  재시도도 요청 수에 포함합니다.", wraplength=480, font=("맑은 고딕", 9))
        error = tk.StringVar()
        ttk.Label(body, textvariable=error, foreground="#b24735", background=WHITE, wraplength=470).pack(anchor="w", pady=8)
        def save():
            if not self.guard_edit():
                return
            try:
                self.store.save_provider(provider_id, dict(enabled=enabled.get(), key=key.get(), clear_key=clear_key.get(),
                    daily_limit=int(limit.get()), pages=int(pages.get()), organization_id=organization.get(),
                    search_backend=backend_labels[backend.get()]))
                key.set("")
                self.notify(f"{provider['name']} 설정 저장 완료")
                self.show_providers_refresh(provider_id)
            except (ValueError, RuntimeError) as exc:
                error.set(str(exc))
        Button(body, text="연동 설정 저장", style="Primary.TButton", command=save).pack(anchor="e", pady=10)

    def show_providers_refresh(self, provider_id):
        self.refresh()
        self.provider_form(provider_id)

    def show_rules(self):
        rules = self.store.rules(demo=self.mode.get() == "demo")
        row = ttk.Frame(self.content)
        row.pack(fill="x", pady=(0, 12))
        ttk.Label(row, text=f"총 {len(rules)}개 규칙 · 지원하지 않는 서비스는 수동 확인 링크를 제공합니다.", style="Muted.TLabel", wraplength=750).pack(anchor="w", pady=(0, 10))
        def toggle():
            if not self.guard_edit() or not tree.selection():
                return
            rule = next(r for r in rules if r["id"] == int(tree.selection()[0]))
            self.store.toggle_rule(rule["id"], not rule["enabled"])
            self.refresh()
        Button(row, text="선택 규칙 켜기 / 끄기", command=toggle).pack(side="right")
        tree = self.table(self.content, [("enabled", "상태", 75), ("target", "대상", 120), ("provider", "제공자", 100),
            ("label", "목적", 170), ("query", "검색식", 360), ("row", "원본 표 항목", 170), ("last", "최근 실행", 120)])
        for rule in rules:
            meta = PROVIDER_MAP[rule["provider"]]
            tree.insert("", "end", iid=str(rule["id"]), values=("수동 확인" if not meta["supported"] else "사용" if rule["enabled"] else "꺼짐",
                json.loads(rule["target_data"])["name"], meta["name"], rule["label"], rule["query"], rule["source_row"], local_time(rule["last_run"])),
                tags=() if meta["supported"] else ("muted",))
        def inspect(e):
            if tree.selection():
                rule = next(r for r in rules if r["id"] == int(tree.selection()[0]))
                win = tk.Toplevel(self.root)
                win.title("검색 규칙")
                win.geometry("720x360")
                body = ttk.Frame(win, padding=20)
                body.pack(fill="both", expand=True)
                text = self.text_area(body)
                text.insert("1.0", f"목적: {rule['label']}\n원본 표: {rule['source_row']}\n\n검색식:\n{rule['query']}\n\n최근 실행: {local_time(rule['last_run'])}")
                text.configure(state="disabled")
                if not PROVIDER_MAP[rule["provider"]]["supported"]:
                    Button(body, text="서비스 수동 확인 ↗", command=lambda: webbrowser.open(PROVIDER_MAP[rule["provider"]]["docs"])).pack(anchor="e", pady=10)
        tree.bind("<Double-1>", inspect)

    def show_runs(self):
        data = self.store.overview(self.mode.get())
        paned = ttk.Panedwindow(self.content, orient="vertical")
        paned.pack(fill="both", expand=True)
        upper, lower = ttk.Frame(paned), ttk.Frame(paned)
        paned.add(upper, weight=2)
        paned.add(lower, weight=3)
        tree = self.table(upper, [("id", "실행", 70), ("trigger", "실행 방식", 100), ("status", "상태", 90), ("started", "시작", 120),
            ("new", "신규", 65), ("count", "관측 건수", 80), ("message", "요약", 450)], height=6)
        for run in data["runs"]:
            tree.insert("", "end", iid=str(run["id"]), values=(f"#{run['id']}", "예약" if run["trigger"] == "schedule" else "수동",
                RUN_LABEL[run["status"]], local_time(run["started_at"]), run["new_count"], run["result_count"], run["message"]))
        ttk.Label(lower, text="선택 실행의 규칙별 결과", font=("맑은 고딕", 12, "bold")).pack(anchor="w", pady=10)
        details = self.table(lower, [("provider", "제공자", 100), ("status", "상태", 100), ("count", "결과", 65),
            ("query", "검색어", 300), ("message", "상세", 450)], height=8)
        def select(e=None):
            for child in details.get_children():
                details.delete(child)
            if not tree.selection():
                return
            run_id = int(tree.selection()[0])
            with self.store.db() as db:
                steps = [dict(r) for r in db.execute("SELECT * FROM run_steps WHERE run_id=? ORDER BY id", (run_id,))]
            for step in steps:
                details.insert("", "end", iid=str(step["id"]), values=(PROVIDER_MAP[step["provider"]]["name"], RUN_LABEL.get(step["status"], step["status"]),
                    step["result_count"], step["query"], step["message"]))
        tree.bind("<<TreeviewSelect>>", select)
        if data["runs"]:
            tree.selection_set(str(data["runs"][0]["id"]))
            select()
        def detail(e):
            if details.selection():
                messagebox.showinfo("규칙 실행 상세", "\n\n".join(str(x) for x in details.item(details.selection()[0], "values")), parent=self.root)
        details.bind("<Double-1>", detail)
        ttk.Label(self.content, text="관측 건수는 출처별 수집 횟수입니다. 중복 통합 후 결과 개수와 다를 수 있습니다.", style="Muted.TLabel").pack(anchor="w", pady=10)

    def show_settings(self):
        settings = self.store.settings()
        outer, container = self.scroll_panel(self.content, padding=0)
        outer.pack(fill="both", expand=True)
        body = ttk.Frame(container, padding=25, style="Card.TFrame")
        body.pack(fill="x")
        ttk.Label(body, text="예약 수집", font=("맑은 고딕", 15, "bold"), style="Card.TLabel").pack(anchor="w")
        enabled = tk.BooleanVar(value=settings["schedule_enabled"])
        ttk.Checkbutton(body, text="프로그램 실행 중 실제 대상 자동 수집", variable=enabled).pack(anchor="w", pady=16)
        interval, maximum = tk.StringVar(value=str(settings["interval_minutes"])), tk.StringVar(value=str(settings["max_queries_per_run"]))
        for title, var, start, end in [("실행 간격 (분, 최소 15)", interval, 15, 10080), ("실행당 최대 규칙 수 (1~500)", maximum, 1, 500)]:
            row = ttk.Frame(body, style="Card.TFrame")
            row.pack(fill="x", pady=8)
            ttk.Label(row, text=title, width=36, style="Card.TLabel").pack(side="left")
            ttk.Spinbox(row, from_=start, to=end, textvariable=var, width=15).pack(side="left")
        last = settings.get("last_scheduled_at")
        next_run = datetime.fromisoformat(last) + timedelta(minutes=settings["interval_minutes"]) if last else None
        ttk.Label(body, text=f"최근 예약 시도: {local_time(last)}\n다음 예약: {local_time(next_run.isoformat()) if next_run and enabled.get() else '켜면 즉시 또는 저장된 간격에 따라 실행'}",
                  style="Card.TLabel").pack(anchor="w", pady=14)
        error = tk.StringVar()
        ttk.Label(body, textvariable=error, foreground="#b24735", background=WHITE).pack(anchor="w")
        def save():
            try:
                if enabled.get() and (not any(t["enabled"] for t in self.store.targets(demo=False)) or not any(p["enabled"] for p in self.store.providers())):
                    raise ValueError("자동 수집을 켜려면 실제 대상과 활성 API가 각각 하나 이상 필요합니다.")
                self.store.save_settings(dict(schedule_enabled=enabled.get(), interval_minutes=int(interval.get()), max_queries_per_run=int(maximum.get())))
                self.notify("자동 수집 설정을 저장했습니다.")
                self.refresh()
            except ValueError as exc:
                error.set(str(exc))
        Button(body, text="설정 저장", style="Primary.TButton", command=save).pack(anchor="e", pady=10)
        info = ttk.Frame(container, padding=25, style="Card.TFrame")
        info.pack(fill="x", pady=18)
        ttk.Label(info, text="저장소와 실행 환경", font=("맑은 고딕", 13, "bold"), style="Card.TLabel").pack(anchor="w")
        ttk.Label(info, text=f"데이터 폴더: {self.store.directory}\n\nAPI 키: 현재 Windows 계정의 DPAPI로 암호화\n수집: 공식 API·피드 조회만 수행 / 대상 파일 다운로드·능동 스캔 없음\n피드: PhishTank·CISA 최대 1시간 캐시\n키가 필요한 API의 실제 연결은 유효한 키와 해당 요금제 권한이 필요합니다.",
                  wraplength=900, justify="left", style="Card.TLabel").pack(anchor="w", pady=12)
        Button(info, text="데이터 폴더 열기", command=lambda: os.startfile(str(self.store.directory))).pack(anchor="w")

    def callback_error(self, exception, value, trace):
        # Do not expose raw exception strings that could include request credentials.
        self.notify("화면 처리 오류가 발생했습니다. 입력값을 확인하고 새로고침하세요.")
        messagebox.showerror("화면 처리 오류", "처리를 완료하지 못했습니다. 입력값 또는 파일 접근 권한을 확인하세요.", parent=self.root)

    def close(self):
        if self.engine.lock.locked() and not messagebox.askyesno("프로그램 종료", "진행 중인 수집을 중지하고 종료할까요? 완료된 결과는 보존됩니다.", parent=self.root):
            return
        self.engine.close()
        self.root.destroy()
