"""Sentinel Desk Windows desktop entry point."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import sys


def setup_tk():
    if getattr(sys, "frozen", False):
        return  # PyInstaller's tkinter runtime hook supplies these paths.
    runtime = Path(sys.executable).parent
    if (runtime / "tcl/tcl8.6/init.tcl").exists():
        os.environ["TCL_LIBRARY"] = str(runtime / "tcl/tcl8.6")
        os.environ["TK_LIBRARY"] = str(runtime / "tcl/tk8.6")


def default_directory():
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SentinelDesk"


class InstanceLock:
    """One process per data directory; prevents duplicate scheduled collections."""
    def __init__(self, directory):
        import msvcrt
        directory.mkdir(parents=True, exist_ok=True)
        self.stream = open(directory / "instance.lock", "a+b")
        try:
            self.stream.seek(0, os.SEEK_END)
            if self.stream.tell() == 0:
                self.stream.write(b"0")
                self.stream.flush()
            self.stream.seek(0)
            msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self.stream.close()
            raise RuntimeError("같은 데이터 폴더의 Sentinel Desk가 이미 실행 중입니다.") from None

    def close(self):
        self.stream.close()


def smoke_ui(root, app, path):
    """Exercise actual native widgets without external API calls."""
    failures = []
    root.report_callback_exception = lambda *args: failures.append(args[0].__name__)
    def descendants(widget):
        for child in widget.winfo_children():
            yield child
            yield from descendants(child)

    def invoke(widget, text):
        button = next(w for w in descendants(widget) if w.winfo_class() == "TButton" and w.cget("text") == text)
        button.invoke()
        root.update()

    views = []
    for mode in ("demo", "real"):
        app.switch_mode(mode)
        for view in ("overview", "findings", "targets", "providers", "rules", "runs", "settings"):
            app.navigate(view)
            root.update()
            views.append(mode + ":" + view)
            if view == "providers":
                for provider in app.store.providers():
                    app.provider_form(provider["id"])
                    root.update()
    app.switch_mode("demo")
    app.focus_search()
    root.update()
    search_shortcut = app.view == "findings" and app.search_entry == root.focus_get()
    app.search_entry.insert(0, "no-match-ui-fixture")
    invoke(root, "검색")
    search_applied = app.filters.get("q") == "no-match-ui-fixture" and app.store.findings("demo", app.filters)["total"] == 0
    invoke(root, "필터 초기화")
    filters_reset = not app.filters and app.offset == 0
    scoped_enter = not root.bind("<Return>")
    # Exercise every view at the supported minimum window size as well.
    root.geometry("1100x740")
    minimum_layout = True
    def visible(widget):
        return widget.winfo_height() > 1 and widget.winfo_rooty() + widget.winfo_height() <= root.winfo_rooty() + root.winfo_height()
    for view in ("overview", "findings", "targets", "providers", "rules", "runs", "settings"):
        app.navigate(view)
        root.update()
        minimum_layout = minimum_layout and visible(app.footer)
        if view == "findings":
            minimum_layout = minimum_layout and visible(app.pagination)
    root.geometry("1380x900")
    app.switch_mode("demo")
    result = app.store.findings("demo", {"limit": 1})["items"][0]
    app.finding_detail(result["id"])
    root.update()
    for child in root.winfo_children():
        if child.winfo_class() == "Toplevel":
            status = next(w for w in descendants(child) if w.winfo_class() == "TCombobox")
            status.current(1)
            invoke(child, "검토 저장")
    review_saved = app.store.detail(result["id"])["status"] == "reviewing"
    app.target_form()
    root.update()
    for child in root.winfo_children():
        if child.winfo_class() == "Toplevel":
            entries = [w for w in descendants(child) if w.winfo_class() == "TEntry"]
            values = ["UI 테스트 기관", "테스트 SOC", "example.org", "ui-fixture", "198.51.100.0/24", "", "CVE-2024-3400"]
            for entry, value in zip(entries, values):
                entry.delete(0, "end")
                entry.insert(0, value)
            invoke(child, "대상 저장·규칙 생성")
    target_saved = any(t["name"] == "UI 테스트 기관" for t in app.store.targets(demo=False))
    app.navigate("providers")
    app.provider_form("brave")
    key_entry = next(w for w in descendants(app.provider_form_area) if w.winfo_class() == "TEntry")
    key_entry.insert(0, "ui-synthetic-test-key")
    check = next(w for w in descendants(app.provider_form_area) if w.winfo_class() == "TCheckbutton" and w.cget("text") == "실제 수집에 사용")
    # Ensure idempotent smoke runs: toggle only when currently disabled.
    if not next(p for p in app.store.providers() if p["id"] == "brave")["enabled"]:
        check.invoke()
    invoke(app.provider_form_area, "연동 설정 저장")
    key_saved = next(p for p in app.store.providers() if p["id"] == "brave")["has_key"]
    app.store.save_provider("brave", dict(enabled=False, clear_key=True))
    keyless_saved = True
    backend_switch = True
    for provider_id in ("google", "baidu"):
        app.provider_form(provider_id)
        root.update()
        selector = next(w for w in descendants(app.provider_form_area) if w.winfo_class() == "TCombobox")
        key_widget = next(w for w in descendants(app.provider_form_area) if w.winfo_class() == "TEntry")
        backend_switch = backend_switch and str(key_widget.cget("state")) == "disabled"
        selector.current(1)
        selector.event_generate("<<ComboboxSelected>>")
        root.update()
        backend_switch = backend_switch and str(key_widget.cget("state")) == "normal"
        selector.current(0)
        selector.event_generate("<<ComboboxSelected>>")
        check = next(w for w in descendants(app.provider_form_area) if w.winfo_class() == "TCheckbutton" and w.cget("text") == "실제 수집에 사용")
        if not next(p for p in app.store.providers() if p["id"] == provider_id)["enabled"]:
            check.invoke()
        invoke(app.provider_form_area, "연동 설정 저장")
        config = next(p for p in app.store.providers() if p["id"] == provider_id)
        keyless_saved = keyless_saved and config["enabled"] and not config["needs_key"] and config["search_backend"] == "direct_html"
        app.store.save_provider(provider_id, dict(enabled=False))
    app.switch_mode("demo")
    run_id = app.engine.start("demo")
    # Keep Tk dispatching during worker completion (including widget finalizers).
    import time
    deadline = time.monotonic() + 30
    def wait_for_demo():
        if not app.engine.worker.is_alive() or time.monotonic() >= deadline:
            root.quit()
        else:
            root.after(50, wait_for_demo)
    root.after(50, wait_for_demo)
    root.mainloop()
    app.navigate("runs")
    root.update()
    overview = app.store.overview("demo")
    ok = not failures and minimum_layout and search_shortcut and search_applied and filters_reset and scoped_enter and review_saved and target_saved and key_saved and keyless_saved and backend_switch and overview["runs"][0]["status"] == "success"
    report = dict(ok=ok, keyless_saved=keyless_saved, backend_switch=backend_switch, views=views, search_shortcut=search_shortcut, search_applied=search_applied,
                  filters_reset=filters_reset, enter_scoped_to_search=scoped_enter, minimum_size_checked="1100x740", minimum_layout_visible=minimum_layout, dialogs=["finding_detail", "target_form"], callback_errors=failures,
                  review_saved=review_saved, target_saved=target_saved, encrypted_key_saved=key_saved,
                  provider_forms_checked=len(app.store.providers()), demo_run_id=run_id,
                  demo_results=overview["total"], network_requests=0)
    Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    app.engine.close()
    root.destroy()
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description="Sentinel Desk Windows desktop")
    parser.add_argument("--data-dir", type=Path, default=default_directory())
    parser.add_argument("--smoke-ui", type=Path, help="Run offline native UI smoke checks and write a JSON report")
    args = parser.parse_args()
    if os.name != "nt":
        raise RuntimeError("이 버전은 Windows 10/11용입니다.")
    instance = InstanceLock(args.data_dir)
    try:
        setup_tk()
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SentinelDesk.Desktop.1")
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
        import tkinter as tk
        from app.desktop import Desktop
        from app.engine import Engine
        from app.store import Store
        store = Store(args.data_dir)
        engine = Engine(store)
        engine.seed_demo()
        root = tk.Tk()
        app = Desktop(root, store, engine)
        if args.smoke_ui:
            return smoke_ui(root, app, args.smoke_ui)
        engine.start_scheduler()
        root.mainloop()
        return 0
    finally:
        instance.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        if "--smoke-ui" in sys.argv:
            report = Path(sys.argv[sys.argv.index("--smoke-ui") + 1])
            report.write_text(json.dumps(dict(ok=False, startup_error=type(exc).__name__)), encoding="utf-8")
            sys.exit(1)
        if os.name == "nt":
            ctypes.windll.user32.MessageBoxW(None,
                "Sentinel Desk를 시작하지 못했습니다.\n다른 인스턴스의 실행 여부와 데이터 폴더 쓰기 권한을 확인하세요.\n\n" +
                (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__), "Sentinel Desk", 0x10)
        raise
