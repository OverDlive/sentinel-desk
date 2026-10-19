"""Shared ttk component theme, including rounded buttons and quiet scrollbars."""
import math
import tkinter as tk
from tkinter import ttk, font as tkfont

BG, WHITE, NAVY, TEAL = '#f6f7f9', '#ffffff', '#f0f2f5', '#5262d8'
TEXT, MUTED, LINE = '#24283d', '#687185', '#e5e8f0'
SOFT, GREEN, AMBER = '#eef0ff', '#20836c', '#b66c30'
TABLE_BORDER, TABLE_HEADER = '#c5cede', '#e8edf6'


class LayoutTask:
    """Coalesce geometry bursts; cancel callbacks with their owning widget."""
    def __init__(self, owner, callback):
        self.owner, self.callback, self.pending = owner, callback, None
        owner.bind('<Destroy>', self.destroy, add='+')

    def schedule(self, event=None):
        if self.pending is None:
            self.pending = self.owner.after_idle(self.run)

    def run(self):
        self.pending = None
        self.callback()

    def destroy(self, event):
        if event.widget == self.owner and self.pending is not None:
            self.owner.after_cancel(self.pending)
            self.pending = None


def bind_resize(widget, callback, size=False):
    # Cheap geometry changes must run before Tk's idle paint, so the same frame
    # is not painted once for geometry and again for a delayed decoration.
    last = None
    def apply(event=None):
        nonlocal last
        if event is None:
            current = (widget.winfo_width(), widget.winfo_height()) if size else (widget.winfo_width(),)
        else:
            current = (event.width, event.height) if size else (event.width,)
        if current != last and current[0] > 1:
            last = current
            callback(*current)
    task = LayoutTask(widget, apply)
    widget.bind('<Configure>', apply, add='+')
    return task


def bind_wrap(widget, labels):
    def update(width):
        width = max(100, width)
        for label in labels:
            if int(label.cget('wraplength') or 0) != width:
                label.configure(wraplength=width)
    return bind_resize(widget, update)


class CanvasLayout:
    """Fit only when width/content changes; height changes update the scroll extent."""
    def __init__(self, canvas, inner, window, padding=0, wrap=False):
        self.canvas, self.inner, self.window = canvas, inner, window
        self.padding, self.wrap = padding, wrap
        self.width, self.region, self.dirty = None, None, True
        self.labels = []
        self.task = LayoutTask(canvas, self.apply)
        bind_resize(canvas, self.resize)
        inner.bind('<Configure>', self.task.schedule, add='+')
        inner.invalidate_layout = self.invalidate

    def invalidate(self):
        self.dirty = True
        self.task.schedule()

    def resize(self, width):
        if int(float(self.canvas.itemcget(self.window, 'width'))) != width:
            self.canvas.itemconfigure(self.window, width=width)

    def apply(self):
        width = self.inner.winfo_width()
        if self.wrap and self.inner.cget('style') == 'Card.TFrame' and (self.dirty or width != self.width):
            if self.dirty:
                self.labels = []
                def collect(parent):
                    for child in parent.winfo_children():
                        if isinstance(child, (ttk.Label, tk.Label)):
                            length = int(child.cget('wraplength') or 0)
                            if length > 0:
                                self.labels.append((child, getattr(child, 'max_wrap', length)))
                        collect(child)
                collect(self.inner)
            for label, maximum in self.labels:
                length = min(maximum, max(100, label.master.winfo_width() - self.padding*2))
                if int(label.cget('wraplength') or 0) != length:
                    label.configure(wraplength=length)
        self.width, self.dirty = width, False
        region = self.canvas.bbox('all')
        if region != self.region:
            self.region = region
            self.canvas.configure(scrollregion=region)


class AutoScrollbar(ttk.Scrollbar):
    """Hide unused tracks; all owners use grid so restored order stays stable."""
    def set(self, first, last):
        if float(first) <= 0 and float(last) >= 1:
            if self.winfo_manager():
                self.grid_remove()
        elif not self.winfo_manager():
            self.grid()
        super().set(first, last)


class ResultList(ttk.Treeview):
    """One list appearance and empty state for every screen."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tag_configure('alternate', background='#fafbfe')
        self.empty = ttk.Label(self, text='아직 표시할 항목이 없습니다.\n대상·연동 설정 또는 검색 조건을 확인해 주세요.',
                               background=WHITE, foreground=MUTED, justify='center', anchor='center')
        self.after_idle(self.update_empty)

    def update_empty(self):
        if self.get_children():
            self.empty.place_forget()
        else:
            self.empty.place(relx=.5, rely=.5, anchor='center')

    def insert(self, parent, index, iid=None, **kwargs):
        if len(self.get_children(parent)) % 2:
            kwargs['tags'] = tuple(self.tk.splitlist(kwargs.get('tags', ()))) + ('alternate',)
        result = super().insert(parent, index, iid=iid, **kwargs)
        self.update_empty()
        return result

    def delete(self, *items):
        super().delete(*items)
        self.update_empty()


def background_of(widget):
    try:
        return widget.cget('background')
    except tk.TclError:
        return ttk.Style(widget).lookup(widget.cget('style') or widget.winfo_class(), 'background') or BG


class Button(ttk.Button):
    """Opaque corner pixels match the actual parent, in every button state."""
    def __init__(self, parent, **kwargs):
        self.base_style = kwargs.get('style', 'TButton')
        kwargs['style'] = parent._root()._desk_button_style(self.base_style, background_of(parent))
        super().__init__(parent, **kwargs)

    def configure(self, cnf=None, **kwargs):
        if cnf is not None:
            return super().configure(cnf, **kwargs)
        if 'style' in kwargs:
            self.base_style = kwargs['style']
            kwargs['style'] = self._root()._desk_button_style(self.base_style, background_of(self.master))
        return super().configure(**kwargs)

    config = configure


class TableFrame(tk.Frame):
    """Mask the four native list corners without changing list interactions."""
    def __init__(self, parent):
        self.backdrop = background_of(parent)
        super().__init__(parent, background=TABLE_BORDER, bd=0, highlightthickness=0)
        self.edge = max(1, round(float(self.tk.call('tk', 'scaling')) / (96/72)))
        self.radius = max(8, round(12 * float(self.tk.call('tk', 'scaling')) / (96/72)))
        self.corner_images, self.corners = [], []
        r = self.radius
        for bottom, right in ((False, False), (False, True), (True, False), (True, True)):
            photo = tk.PhotoImage(master=self, width=r, height=r)
            inside = WHITE if bottom else TABLE_HEADER
            for y in range(r):
                for x in range(r):
                    dx = x + .5 if right else r-x-.5
                    dy = y + .5 if bottom else r-y-.5
                    distance = math.sqrt(dx*dx+dy*dy)
                    color = self.backdrop if distance > r else TABLE_BORDER if distance > r-self.edge else inside
                    photo.put(color, to=(x,y))
            corner = tk.Label(self, image=photo, bd=0, highlightthickness=0)
            self.corner_images.append(photo)
            self.corners.append((corner, bottom, right))
        self._corner_size = None
        self._corners_raised = False
        bind_resize(self, self.draw_corners, size=True)

    def draw_corners(self, width, height):
        previous = self._corner_size
        for corner, bottom, right in self.corners:
            if previous is None or (right and previous[0] != width) or (bottom and previous[1] != height):
                corner.place(x=width-self.radius if right else 0, y=height-self.radius if bottom else 0,
                             width=self.radius, height=self.radius)
            if not self._corners_raised:
                corner.lift()
        self._corners_raised = True
        self._corner_size = width, height


def install_theme(root):
    style = ttk.Style(root)
    style.theme_use('clam')
    images = []
    scale = float(root.tk.call('tk', 'scaling')) / (96 / 72)
    px = lambda value: max(1, round(value * scale))
    font = ('맑은 고딕', 10)
    style.configure('.', font=font, bordercolor=LINE, lightcolor=LINE, darkcolor=LINE)
    for name, color in [('TFrame', BG), ('Card.TFrame', WHITE)]:
        style.configure(name, background=color)
    for name, bg, fg in [('TLabel', BG, TEXT), ('Card.TLabel', WHITE, TEXT),
                         ('Muted.TLabel', BG, MUTED), ('CardMuted.TLabel', WHITE, MUTED)]:
        style.configure(name, background=bg, foreground=fg)
    style.configure('Heading.TLabel', font=('맑은 고딕', 23, 'bold'))

    def surface(fill, border, backdrop=BG, radius=None, width=None, height=None):
        radius = px(8) if radius is None else radius
        # Keep a broad solid centre: ttk repeats its centre image region when
        # stretching. Tiny centres cause many native image copies on every paint.
        width, height = width or px(240), height or px(64)
        image = tk.PhotoImage(master=root, width=width, height=height)
        # Transparent ttk images leave old state pixels behind on Windows.
        # Paint every pixel, including the surrounding parent-colour corners.
        image.put(backdrop, to=(0, 0, width, height))
        for y in range(height):
            dy = max(radius - y - .5, y + .5 - (height - radius), 0)
            inset = math.ceil(radius - math.sqrt(max(0, radius * radius - dy * dy))) if dy else 0
            if inset < width - inset:
                image.put(border, to=(inset, y, width-inset, y+1))
                inner = inset + 1
                if 0 < y < height-1 and inner < width-inner:
                    image.put(fill, to=(inner, y, width-inner, y+1))
        images.append(image)
        return image

    palettes = {
        'TButton': (WHITE, '#f0f2fc', '#e5e9fa', LINE, TEXT),
        'Primary.TButton': (TEAL, '#4656c7', '#3949b5', TEAL, WHITE),
        'Soft.TButton': (SOFT, '#e2e6fc', '#d7ddfa', SOFT, TEAL),
        'Danger.TButton': ('#fff1f1', '#ffe4e4', '#fbd6d9', '#f3d5d8', '#a73b4d'),
        'Nav.TButton': (NAVY, '#e8ebf5', '#e0e5fc', NAVY, MUTED),
        'Selected.Nav.TButton': ('#e0e5fc', '#d9dffb', '#d2daf8', '#e0e5fc', TEAL),
        'Card.TButton': (WHITE, SOFT, '#e2e6fc', WHITE, MUTED),
    }
    registered = {}
    root._desk_button_images = {}
    def button_style(base, backdrop):
        key = (base, backdrop)
        if key in registered:
            return registered[key]
        normal, hover, pressed, edge, foreground = palettes[base]
        name = 'Parent' + backdrop.replace('#','') + '.' + base
        state_images = [surface(fill, border, backdrop, width=px(800) if base == 'Card.TButton' else None) for fill, border in
                        [(normal, edge), ('#f0f2f6', '#e5e8ef'), (pressed, pressed), (hover, hover), (normal, TEAL)]]
        element = name + '.surface'
        # Natural button geometry still follows text/padding, not bitmap size.
        style.element_create(element, 'image', state_images[0], ('disabled', state_images[1]),
                             ('pressed', state_images[2]), ('active', state_images[3]), ('focus', state_images[4]),
                             border=px(8), padding=0, width=px(17), height=px(17), sticky='nsew')
        style.layout(name, [(element, {'sticky': 'nsew', 'children': [
            ('Button.padding', {'sticky': 'nsew', 'children': [('Button.label', {'sticky': 'nsew'})]})]})])
        style.configure(name, font=font, padding=(px(12), px(7)), foreground=foreground,
                        anchor='w' if 'Nav.' in base or base == 'Card.TButton' else 'center',
                        width=0, borderwidth=0, background=backdrop)
        style.map(name, foreground=[('disabled', '#8991a3'), ('!disabled', foreground)])
        registered[key] = name
        root._desk_button_images[key] = state_images
        return name
    root._desk_button_style = button_style
    # Custom image thumbs replace clam's built-in thumb, including its grip marks.
    for orient in ('Vertical', 'Horizontal'):
        vertical = orient == 'Vertical'
        width, height = (px(10), px(28)) if vertical else (px(28), px(10))
        thumb_images = [surface(color, color, BG, radius=px(5), width=width, height=height)
                        for color in ('#bec7d9', '#96a4c3', '#7f90b5')]
        thumb = 'Desk.' + orient + '.Scrollbar.thumb'
        style.element_create(thumb, 'image', thumb_images[0], ('pressed', thumb_images[2]),
                             ('active', thumb_images[1]), border=px(5), padding=0, sticky='nsew')
        style.layout(orient + '.TScrollbar', [(orient + '.Scrollbar.trough', {
            'sticky': 'nsew', 'children': [(thumb, {'expand': '1', 'sticky': 'nsew'})]})])
        style.configure(orient + '.TScrollbar', background=BG, troughcolor=BG, bordercolor=BG,
                        lightcolor=BG, darkcolor=BG, borderwidth=0, width=px(10), arrowsize=px(10))
    style.configure('TEntry', fieldbackground=WHITE, padding=(px(9), px(7)), borderwidth=1)
    style.map('TEntry', bordercolor=[('focus', TEAL)])
    style.configure('TCombobox', padding=(px(9), px(7)), arrowsize=px(12), arrowcolor=MUTED)
    style.map('TCombobox', fieldbackground=[('readonly', WHITE)], background=[('readonly', WHITE)],
              selectbackground=[('readonly', WHITE)], selectforeground=[('readonly', TEXT)],
              foreground=[('disabled', '#8991a3'), ('!disabled', TEXT)], bordercolor=[('focus', TEAL)])
    style.configure('TSpinbox', padding=(px(9), px(7)), fieldbackground=WHITE, arrowcolor=MUTED)
    for key, value in [('font', font), ('background', WHITE), ('foreground', TEXT),
                       ('selectBackground', SOFT), ('selectForeground', TEAL),
                       ('relief', 'flat'), ('borderWidth', 0), ('highlightThickness', 0),
                       ('selectBorderWidth', 0), ('activeStyle', 'none')]:
        root.option_add('*TCombobox*Listbox.' + key, value)
    rowheight = tkfont.Font(root=root, font=font).metrics('linespace') + px(18)
    style.configure('Treeview', font=font, rowheight=rowheight, background=WHITE,
                    fieldbackground=WHITE, foreground=TEXT, borderwidth=0, relief='flat')
    # Explicit heading cells provide a visible lower rule and column separators.
    def heading_image(color):
        photo = tk.PhotoImage(master=root, width=px(20), height=px(20))
        photo.put(color, to=(0,0,photo.width(),photo.height()))
        photo.put(TABLE_BORDER, to=(0,photo.height()-px(1),photo.width(),photo.height()))
        photo.put(TABLE_BORDER, to=(photo.width()-px(1),0,photo.width(),photo.height()))
        images.append(photo)
        return photo
    heading_normal, heading_hover = heading_image(TABLE_HEADER), heading_image('#dde5f3')
    style.element_create('Desk.Treeheading.cell', 'image', heading_normal, ('active', heading_hover),
                         border=(0,0,px(1),px(1)), padding=0, sticky='nsew')
    style.layout('Treeview.Heading', [('Desk.Treeheading.cell', {'sticky':'nsew','children':[
        ('Treeheading.padding', {'sticky':'nsew','children':[
            ('Treeheading.image', {'side':'right','sticky':''}),
            ('Treeheading.text', {'sticky':'we'})]})]})])
    style.layout('Treeview', [('Treeview.treearea', {'sticky':'nsew'})])
    style.configure('Treeview.Heading', font=('맑은 고딕', 10, 'bold'), padding=(px(6), px(11)),
                    background=TABLE_HEADER, foreground='#35415d', relief='flat', borderwidth=0)
    style.map('Treeview', background=[('selected', '#e2e8ff')], foreground=[('selected', TEXT)])
    style.configure('TNotebook', background=BG, borderwidth=0, tabmargins=(0, 0, 0, px(8)))
    style.configure('TNotebook.Tab', padding=(px(15), px(8)), background=BG, foreground=MUTED)
    style.map('TNotebook.Tab', background=[('selected', WHITE)], foreground=[('selected', TEAL)])
    style.configure('TLabelframe', background=WHITE, bordercolor=LINE)
    style.configure('TLabelframe.Label', background=WHITE, foreground=TEXT, font=('맑은 고딕', 11, 'bold'))
    style.configure('TCheckbutton', background=WHITE, foreground=TEXT, padding=px(4))
    style.map('TCheckbutton', background=[('active', SOFT)])
    style.configure('TPanedwindow', background=BG)
    style.configure('Sash', sashthickness=px(8), sashpad=px(4), background=BG)
    return images
