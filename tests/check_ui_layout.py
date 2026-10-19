"""Offline geometry regression audit at simulated Windows font scales."""
import sys, json, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from main import setup_tk
setup_tk()
import ctypes
ctypes.windll.shcore.SetProcessDpiAwareness(1)
import tkinter as tk
from tkinter import ttk
from app.desktop import Desktop
from app.store import Store
from app.engine import Engine
from app.ui import AutoScrollbar, ResultList

def children(w):
    for child in w.winfo_children():
        yield child
        yield from children(child)

reports=[]
for ratio in (1, 1.25, 1.5, 2):
    with tempfile.TemporaryDirectory() as directory:
        root=tk.Tk()
        root.tk.call('tk', 'scaling', ratio * 96/72)
        store=Store(Path(directory)); engine=Engine(store); engine.seed_demo()
        app=Desktop(root,store,engine)
        errors=[]
        root.report_callback_exception=lambda kind, value, trace: errors.append(kind.__name__)
        for size in ('1100x740', '1380x900'):
            root.geometry(size)
            for view in ('overview','findings','targets','providers','rules','runs','settings'):
                app.navigate(view);root.update()
                for widget in children(root):
                    if isinstance(widget,ttk.Button) and widget.winfo_manager() and widget.master.winfo_ismapped():
                        # Offscreen canvas content is intentionally scrollable. Its own
                        # allocated rectangle must still hold the complete button label.
                        if widget.winfo_width()<widget.winfo_reqwidth() or widget.winfo_height()<widget.winfo_reqheight():
                            errors.append(dict(size=size,view=view,text=widget.cget('text'),
                                               allocated=[widget.winfo_width(),widget.winfo_height()],
                                               requested=[widget.winfo_reqwidth(),widget.winfo_reqheight()]))
        # Regression: scrollbar visibility and empty overlays follow live list content.
        win = tk.Toplevel(root)
        win.geometry('400x240')
        win.rowconfigure(0, weight=1);win.columnconfigure(0, weight=1)
        tree = ResultList(win, columns=('name',), show='headings', height=3)
        tree.column('name', width=900, minwidth=900, stretch=False)
        vertical = AutoScrollbar(win, orient='vertical', command=tree.yview)
        horizontal = AutoScrollbar(win, orient='horizontal', command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0,column=0,sticky='nsew')
        vertical.grid(row=0,column=1,sticky='ns')
        horizontal.grid(row=1,column=0,sticky='ew')
        root.update()
        empty_initial = bool(tree.empty.winfo_ismapped())
        for i in range(20):
            tree.insert('', 'end', values=(f'Fixture {i}',))
        root.update()
        populated = not tree.empty.winfo_ismapped() and vertical.winfo_ismapped() and horizontal.winfo_ismapped()
        # Exercise the actual native thumb binding, not just programmatic yview.
        thumb_points = [(vertical.winfo_width()//2, y) for y in range(vertical.winfo_height())
                        if vertical.identify(vertical.winfo_width()//2,y).endswith('thumb')]
        dragged = False
        if thumb_points:
            x,y = thumb_points[len(thumb_points)//2]
            vertical.event_generate('<ButtonPress-1>', x=x,y=y)
            vertical.event_generate('<B1-Motion>', x=x,y=min(vertical.winfo_height()-2,y+80))
            vertical.event_generate('<ButtonRelease-1>', x=x,y=min(vertical.winfo_height()-2,y+80))
            root.update()
            dragged = tree.yview()[0] > 0
        tree.yview_moveto(1);root.update()
        scrolled = tree.yview()[0] > 0 and dragged
        tree.delete(*tree.get_children())
        tree.column('name', width=100, minwidth=100)
        root.update()
        empty_restored = tree.empty.winfo_ismapped() and not vertical.winfo_ismapped() and not horizontal.winfo_ismapped()
        components = bool(empty_initial and populated and scrolled and empty_restored)
        if not components:
            errors.append(dict(component_regression=dict(empty_initial=bool(empty_initial),populated=bool(populated),
                                                       scrolled=bool(scrolled),empty_restored=bool(empty_restored))))
        win.destroy()
        corners_clean = True
        for (base, backdrop), photos in root._desk_button_images.items():
            expected = tuple(c//257 for c in root.winfo_rgb(backdrop))
            for photo in photos:
                for x,y in ((0,0),(photo.width()-1,0),(0,photo.height()-1),(photo.width()-1,photo.height()-1)):
                    corners_clean = corners_clean and photo.get(x,y) == expected and not photo.transparency_get(x,y)
        if not corners_clean:
            errors.append('Button corner backdrop regression')
        reports.append(dict(scale=ratio, errors=errors, scrollbar_and_list_states=components, opaque_button_corners=corners_clean))
        engine.close()
        for callback in root.tk.splitlist(root.tk.call('after','info')):
            root.after_cancel(callback)
        root.destroy()
Path('test-artifacts/geometry-audit.json').write_text(json.dumps(reports,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(reports,ensure_ascii=True,indent=2))
sys.exit(any(r['errors'] for r in reports))
