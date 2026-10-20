"""Offline native geometry regression for all resizable application popups."""
import ctypes
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from main import setup_tk

setup_tk()
ctypes.windll.shcore.SetProcessDpiAwareness(1)
import tkinter as tk
from tkinter import ttk
from app.desktop import Desktop
from app.engine import Engine
from app.store import Store
from app.windowing import work_area


def descendants(parent):
    for child in parent.winfo_children():
        yield child
        yield from descendants(child)


def assert_visible(widget):
    assert widget.winfo_ismapped(), widget
    assert widget.winfo_width() >= widget.winfo_reqwidth(), widget
    assert widget.winfo_height() >= widget.winfo_reqheight(), widget
    left, top = widget.winfo_rootx(), widget.winfo_rooty()
    right, bottom = left + widget.winfo_width(), top + widget.winfo_height()
    parent = widget.master
    while parent is not None:
        assert left >= parent.winfo_rootx(), widget
        assert top >= parent.winfo_rooty(), widget
        assert right <= parent.winfo_rootx() + parent.winfo_width(), widget
        assert bottom <= parent.winfo_rooty() + parent.winfo_height(), widget
        if isinstance(parent, tk.Toplevel):
            break
        parent = parent.master


def assert_centered(win, area=None):
    root.update()
    user32 = ctypes.windll.user32
    bounds = ctypes.wintypes.RECT()
    handle = user32.GetAncestor(win.winfo_id(), 2)
    assert user32.GetWindowRect(handle, ctypes.byref(bounds))
    left, top, right, bottom = area or work_area(win.master)
    assert abs(bounds.left + bounds.right - left - right) <= 2
    assert abs(bounds.top + bounds.bottom - top - bottom) <= 2
    assert bounds.left >= left and bounds.right <= right
    assert bounds.top >= top and bounds.bottom <= bottom


def audit_actions(win):
    assert_centered(win)
    minimum = win.minsize()
    for width, height in ((900, 800), minimum, (1000, 850), minimum):
        win.geometry(f'{width}x{height}')
        root.update()
        buttons = [w for w in descendants(win) if isinstance(w, ttk.Button)]
        for button in buttons:
            assert_visible(button)
        for canvas in (w for w in descendants(win) if isinstance(w, tk.Canvas)):
            for position in (0, 1):
                canvas.yview_moveto(position)
                root.update()
                for button in buttons:
                    assert_visible(button)


for scale in (1, 1.25, 1.5, 2):
    with tempfile.TemporaryDirectory() as directory:
        root = tk.Tk()
        root.tk.call('tk', 'scaling', scale * 96 / 72)
        store = Store(Path(directory))
        engine = Engine(store)
        engine.seed_demo()
        # Build the actual dialog without starting the collection scheduler or
        # loading unrelated main-window assets.
        root.geometry('1100x740')
        app = Desktop.__new__(Desktop)
        app.root, app.store, app.engine = root, store, engine
        app.mode = tk.StringVar(value='real')
        app.switch_mode = lambda mode: None
        app.configure_style()
        root.update()
        app.notify = lambda message: None
        app.refresh = lambda: None
        errors = []
        root.report_callback_exception = lambda *args: errors.append(args)
        try:
            finding_id = store.findings('demo', {'limit': 1})['items'][0]['id']
            app.finding_detail(finding_id)
            win = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
            assert_centered(win)
            notebook = next(w for w in descendants(win) if isinstance(w, ttk.Notebook))
            buttons = {w.cget('text'): w for w in descendants(win) if isinstance(w, ttk.Button)}
            note = next(w for w in descendants(win) if isinstance(w, tk.Text) and w.cget('state') == 'normal')
            form_canvas = note.master.master.master
            note.insert('1.0', 'Resize regression\n' * 80)
            for size in ('960x780', '800x650', '1200x900', '800x650'):
                win.geometry(size)
                for tab in notebook.tabs():
                    notebook.select(tab)
                    root.update()
                    assert_visible(buttons['닫기'])
                notebook.select(1)
                root.update()
                assert_visible(buttons['검토 저장'])
                assert note.winfo_height() > 20
                form_canvas.yview_moveto(1)
                root.update()
                assert form_canvas.yview()[1] == 1.0
                if form_canvas.bbox('all')[3] > form_canvas.winfo_height():
                    assert form_canvas.yview()[0] > 0
                note.yview_moveto(1)
                root.update()
                assert note.yview()[0] > 0
            buttons['검토 저장'].invoke()
            root.update()
            assert store.detail(finding_id)['note'].startswith('Resize regression\n')
            # Registration and editing share the same scrollable form/footer.
            app.target_form()
            win = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
            audit_actions(win)
            save = next(w for w in descendants(win) if isinstance(w, ttk.Button) and w.cget('text') == '대상 저장·규칙 생성')
            save.invoke()  # A validation error must not push the action offscreen.
            root.update()
            assert_visible(save)
            entries = [w for w in descendants(win) if isinstance(w, ttk.Entry)]
            entries[0].insert(0, 'Popup fixture')
            entries[2].insert(0, 'example.com')
            save.invoke()
            root.update()
            target = store.targets(demo=False)[0]
            app.target_form(target)
            win = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
            audit_actions(win)
            next(w for w in descendants(win) if isinstance(w, ttk.Button) and w.cget('text') == '대상 저장·규칙 생성').invoke()
            root.update()
            assert store.target(target['id'])['name'] == 'Popup fixture'
            from app.domain import PROVIDER_MAP
            rules = store.rules(demo=True)
            for supported in (True, False):
                rule = rules[0]
                provider = rule['provider']
                with patch.dict(PROVIDER_MAP, {provider: {**PROVIDER_MAP[provider], 'supported': supported}}):
                    win = app.rule_detail(rule)
                audit_actions(win)
                next(w for w in descendants(win) if isinstance(w, ttk.Button) and w.cget('text') == '닫기').invoke()
            win = app.text_dialog('규칙 실행 상세', 'Long execution detail\n' * 100)
            audit_actions(win)
            text = next(w for w in descendants(win) if isinstance(w, tk.Text))
            text.yview_moveto(1)
            root.update()
            assert text.yview()[0] > 0
            win.destroy()
            # Simulate a small work area and a monitor left of the primary one.
            for area in ((0, 0, 800, 600), (-1280, 0, 0, 960)):
                with patch('app.windowing.work_area', return_value=area):
                    win = app.text_dialog('Placement regression', 'Content\n' * 40)
                assert_centered(win, area)
                for button in (w for w in descendants(win) if isinstance(w, ttk.Button)):
                    assert_visible(button)
                win.destroy()
            with patch('app.windowing.work_area', return_value=(0, 0, 800, 600)):
                app.target_form()
            win = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
            assert_centered(win, (0, 0, 800, 600))
            for button in (w for w in descendants(win) if isinstance(w, ttk.Button)):
                assert_visible(button)
            win.destroy()
            assert not errors, errors
            print(f'scale={scale}: all popups centered, actions visible, forms scroll, saves persist')
        finally:
            engine.close()
            for callback in root.tk.splitlist(root.tk.call('after', 'info')):
                root.after_cancel(callback)
            root.destroy()
