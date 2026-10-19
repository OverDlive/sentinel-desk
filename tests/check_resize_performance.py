"""Repeatable native resize workload with latency and Tcl-call profiling."""
import argparse, cProfile, json, pstats, sys, tempfile, time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from main import setup_tk
setup_tk()
import ctypes
ctypes.windll.shcore.SetProcessDpiAwareness(1)
import tkinter as tk
from app.desktop import Desktop
from app.engine import Engine
from app.store import Store
parser=argparse.ArgumentParser()
parser.add_argument('--output',default='test-artifacts/resize-performance.json')
parser.add_argument('--frames',type=int,default=50)
parser.add_argument('--views',default='overview,findings,providers,settings')
parser.add_argument('--ablation',choices=('none','buttons','corners','callbacks'),default='none')
args=parser.parse_args()
if args.ablation == 'buttons':
    from tkinter import ttk
    import app.desktop
    app.desktop.Button = ttk.Button
elif args.ablation == 'corners':
    import app.desktop
    class PlainTable(tk.Frame):
        def __init__(self,parent):
            super().__init__(parent,bg='#c5cede')
            self.edge=2
    app.desktop.TableFrame=PlainTable
results=[]
with tempfile.TemporaryDirectory() as directory:
    root=tk.Tk();store=Store(Path(directory));engine=Engine(store);engine.seed_demo()
    app=Desktop(root,store,engine)
    errors=[]
    def callback_error(kind,value,trace):
        if not errors:
            import traceback
            traceback.print_exception(kind,value,trace)
        errors.append(kind.__name__)
    root.report_callback_exception=callback_error
    root.update()
    for view in args.views.split(','):
        app.navigate(view);root.update()
        if args.ablation == 'callbacks':
            def detach(widget):
                widget.unbind('<Configure>')
                for child in widget.winfo_children():detach(child)
            detach(root)
        samples=[]
        profiler=cProfile.Profile()
        profiler.enable()
        for i in range(args.frames):
            # Both shrinking and expanding cross responsive wrapping thresholds.
            phase=i if i<args.frames//2 else args.frames-i
            w=1100+phase*16;h=740+phase*7
            start=time.perf_counter()
            root.geometry(f'{w}x{h}')
            root.update()
            # Allow deferred/coalesced layout work to run, as it does during dragging.
            root.after(20,root.quit);root.mainloop()
            samples.append((time.perf_counter()-start)*1000)
        profiler.disable()
        stats=pstats.Stats(profiler)
        top=[]
        for (filename,line,name),(primitive,calls,own,cumulative,callers) in stats.stats.items():
            if filename.endswith(('desktop.py','ui.py')) or name in ('<method \'call\' of \'_tkinter.tkapp\' objects>',):
                top.append(dict(function=f'{Path(filename).name}:{line}:{name}',calls=calls,own_ms=round(own*1000,2),total_ms=round(cumulative*1000,2)))
        samples.sort()
        results.append(dict(view=view,frames=len(samples),median_ms=round(samples[len(samples)//2],2),
                            p95_ms=round(samples[min(len(samples)-1,int(len(samples)*.95))],2),max_ms=round(max(samples),2),
                            top=sorted(top,key=lambda x:x['total_ms'],reverse=True)[:18]))
        print(view,results[-1]['median_ms'],results[-1]['p95_ms'],flush=True)
    engine.close()
    for callback in root.tk.splitlist(root.tk.call('after','info')):root.after_cancel(callback)
    root.destroy()
Path(args.output).write_text(json.dumps(dict(results=results,callback_errors=errors),ensure_ascii=False,indent=2),encoding='utf-8')
sys.exit(bool(errors))
