"""Shared placement for native, resizable application dialogs."""
import ctypes
from ctypes import wintypes


def work_area(parent):
    """Use the parent's monitor, excluding the taskbar (also on secondary screens)."""
    class MonitorInfo(ctypes.Structure):
        _fields_ = [('cbSize', wintypes.DWORD), ('monitor', wintypes.RECT),
                    ('work', wintypes.RECT), ('flags', wintypes.DWORD)]

    user32 = ctypes.windll.user32
    user32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
    user32.MonitorFromWindow.restype = wintypes.HANDLE
    user32.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MonitorInfo)]
    info = MonitorInfo(cbSize=ctypes.sizeof(MonitorInfo))
    monitor = user32.MonitorFromWindow(parent.winfo_id(), 2)
    if user32.GetMonitorInfoW(monitor, ctypes.byref(info)):
        return info.work.left, info.work.top, info.work.right, info.work.bottom
    return (parent.winfo_vrootx(), parent.winfo_vrooty(),
            parent.winfo_vrootx() + parent.winfo_vrootwidth(),
            parent.winfo_vrooty() + parent.winfo_vrootheight())


def show_centered(win, size, minimum):
    """Place once on opening; subsequent user resizing/moving stays untouched."""
    win.update_idletasks()
    left, top, right, bottom = work_area(win.master)
    # Leave room for native borders and the title bar on small work areas.
    width = min(size[0], max(1, right - left - 32))
    height = min(size[1], max(1, bottom - top - 64))
    win.minsize(min(minimum[0], width), min(minimum[1], height))
    x = left + (right - left - width) // 2
    y = top + (bottom - top - height) // 2
    win.geometry(f'{width}x{height}+{x}+{y}')
    win.deiconify()
    win.update_idletasks()
    # Measure the native frame, including the title bar, before final placement.
    user32 = ctypes.windll.user32
    user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetAncestor.restype = wintypes.HWND
    user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    handle = user32.GetAncestor(win.winfo_id(), 2)
    bounds = wintypes.RECT()
    if user32.GetWindowRect(handle, ctypes.byref(bounds)):
        x = left + (right - left - (bounds.right - bounds.left)) // 2
        y = top + (bottom - top - (bounds.bottom - bounds.top)) // 2
        # The explicit '+' makes negative coordinates absolute (e.g. '+-900'),
        # rather than Tk's '-900' offset from the right/bottom screen edge.
        win.geometry(f'{width}x{height}+{x}+{y}')
    win.lift()
