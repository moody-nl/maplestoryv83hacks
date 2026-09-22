import ctypes
import ctypes.wintypes
import struct
import threading
import time
import tkinter as tk
from tkinter import ttk

import pymem
import pymem.process


TARGET = "SlimeTale.exe"

# Confirmed v72 CMob signature from the working direct test.
VT0_RVA = 0x5D4010
VT1_RVA = 0x5D3FEC
VT2_RVA = 0x5D3FE8

# Confirmed player resolver.
CHAR_ROOT_RVA = 0x6A4E88
CHAR_X_OFF = 0x5C8
CHAR_Y_OFF = 0x5CC

# Confirmed from the working CMob candidates:
# CMob+0x4A8/+0x4AC = position A
# CMob+0x4B0/+0x4B4 = position B
MOB_X_OFF = 0x4A8
MOB_Y_OFF = 0x4AC
MOB_PREV_X_OFF = 0x4B0
MOB_PREV_Y_OFF = 0x4B4

DEFAULT_X_OFFSET = -25
DEFAULT_Y_OFFSET = 0

HOLD_INTERVAL = 0.003
RESCAN_SECONDS = 2.0

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000

PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

WRITABLE = {
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
}


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


def read_u32(pm, addr):
    try:
        return pm.read_uint(addr)
    except Exception:
        return None


def read_i32(pm, addr):
    try:
        return pm.read_int(addr)
    except Exception:
        return None


def iter_regions(pm):
    mbi = MBI()
    addr = 0

    while addr < 0x7FFFFFFF:
        result = ctypes.windll.kernel32.VirtualQueryEx(
            pm.process_handle,
            ctypes.c_void_p(addr),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if not result:
            break

        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize)
        protect = int(mbi.Protect) & 0xFF

        if (
            mbi.State == MEM_COMMIT
            and mbi.Type == MEM_PRIVATE
            and protect in WRITABLE
            and 0 < size <= 32 * 1024 * 1024
        ):
            yield base, size

        if size <= 0:
            break

        addr = base + size


def scan_sig(pm, sig):
    hits = []

    for base, size in iter_regions(pm):
        try:
            data = pm.read_bytes(base, size)
        except Exception:
            continue

        pos = 0
        while True:
            pos = data.find(sig, pos)
            if pos < 0:
                break

            addr = base + pos

            if addr % 4 == 0:
                hits.append(addr)

            pos += 4

    return hits


def get_player(pm, module_base):
    root = read_u32(pm, module_base + CHAR_ROOT_RVA)
    if not root:
        return None

    x = read_i32(pm, root + CHAR_X_OFF)
    y = read_i32(pm, root + CHAR_Y_OFF)

    if x is None or y is None:
        return None

    return root, x, y


def valid_mob(pm, mob, sig):
    try:
        if pm.read_bytes(mob, len(sig)) != sig:
            return False

        ax = pm.read_int(mob + MOB_X_OFF)
        ay = pm.read_int(mob + MOB_Y_OFF)
        bx = pm.read_int(mob + MOB_PREV_X_OFF)
        by = pm.read_int(mob + MOB_PREV_Y_OFF)

        return all(-30000 <= v <= 30000 for v in (ax, ay, bx, by))
    except Exception:
        return False


def write_mob_position(pm, mob, x, y):
    pm.write_int(mob + MOB_X_OFF, x)
    pm.write_int(mob + MOB_Y_OFF, y)
    pm.write_int(mob + MOB_PREV_X_OFF, x)
    pm.write_int(mob + MOB_PREV_Y_OFF, y)


class SlimeTaleVacGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SlimeTale v72 VAC")
        self.root.geometry("620x430")
        self.root.resizable(False, False)
        self.root.configure(bg="#0f172a")

        self.pm = None
        self.base = None
        self.sig = None

        self.mobs = []
        self.mob_lock = threading.RLock()

        self.vac_enabled = False
        self.stop_event = threading.Event()
        self.worker = None
        self.scanner = None

        self.offset_x = DEFAULT_X_OFFSET
        self.offset_y = DEFAULT_Y_OFFSET

        self.status_var = tk.StringVar(value="Niet verbonden")
        self.player_var = tk.StringVar(value="Player: --")
        self.mob_var = tk.StringVar(value="CMobs: --")
        self.target_var = tk.StringVar(value="Target: --")

        self.x_var = tk.IntVar(value=self.offset_x)
        self.y_var = tk.IntVar(value=self.offset_y)
        self.x_text = tk.StringVar()
        self.y_text = tk.StringVar()

        self.hotkeys = {0x74: False, 0x75: False}  # F5/F6

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.connect()

        self.root.after(60, self.poll_hotkeys)
        self.root.after(150, self.refresh_ui)

    def _build_ui(self):
        bg = "#0f172a"
        panel = "#172033"
        fg = "#f8fafc"
        muted = "#94a3b8"
        cyan = "#38bdf8"

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Vac.Horizontal.TScale",
            background=panel,
            troughcolor="#334155",
        )

        header = tk.Frame(self.root, bg=bg)
        header.pack(fill="x", padx=24, pady=(20, 10))

        tk.Label(
            header,
            text="SLIMETALE v72 VAC",
            bg=bg,
            fg=cyan,
            font=("Segoe UI Semibold", 20),
        ).pack(side="left")

        tk.Label(
            header,
            text="F5 START   F6 STOP",
            bg="#1e3a5f",
            fg="#bfdbfe",
            padx=10,
            pady=5,
            font=("Consolas", 9, "bold"),
        ).pack(side="right")

        status = tk.Frame(
            self.root,
            bg=panel,
            highlightbackground="#334155",
            highlightthickness=1,
        )
        status.pack(fill="x", padx=24, pady=8)

        for var in (
            self.status_var,
            self.player_var,
            self.mob_var,
            self.target_var,
        ):
            tk.Label(
                status,
                textvariable=var,
                bg=panel,
                fg=fg if var == self.status_var else muted,
                anchor="w",
                font=("Consolas", 10),
                padx=14,
                pady=4,
            ).pack(fill="x")

        controls = tk.Frame(self.root, bg=panel, padx=18, pady=16)
        controls.pack(fill="x", padx=24, pady=8)

        self.x_text.set(self._format_x())
        self.y_text.set(self._format_y())

        tk.Label(
            controls,
            textvariable=self.x_text,
            bg=panel,
            fg=fg,
            font=("Segoe UI Semibold", 10),
        ).pack(anchor="w")

        self.x_scale = ttk.Scale(
            controls,
            from_=-350,
            to=350,
            orient="horizontal",
            style="Vac.Horizontal.TScale",
            command=self.on_x_slider,
        )
        self.x_scale.set(self.offset_x)
        self.x_scale.pack(fill="x", pady=(4, 12))

        tk.Label(
            controls,
            textvariable=self.y_text,
            bg=panel,
            fg=fg,
            font=("Segoe UI Semibold", 10),
        ).pack(anchor="w")

        self.y_scale = ttk.Scale(
            controls,
            from_=-250,
            to=250,
            orient="horizontal",
            style="Vac.Horizontal.TScale",
            command=self.on_y_slider,
        )
        self.y_scale.set(self.offset_y)
        self.y_scale.pack(fill="x", pady=(4, 10))

        presets = tk.Frame(controls, bg=panel)
        presets.pack(fill="x", pady=(2, 0))

        for label, xoff, yoff in (
            ("Links -120", -120, 0),
            ("Links -80", -80, 0),
            ("Links -25", -25, 0),
            ("Op speler", 0, 0),
            ("Rechts +80", 80, 0),
        ):
            tk.Button(
                presets,
                text=label,
                command=lambda x=xoff, y=yoff: self.set_offset(x, y),
                bg="#334155",
                fg="white",
                relief="flat",
                activebackground="#475569",
                activeforeground="white",
                padx=7,
                pady=5,
            ).pack(side="left", padx=(0, 5))

        actions = tk.Frame(self.root, bg=bg)
        actions.pack(fill="x", padx=24, pady=(12, 0))

        self.start_btn = tk.Button(
            actions,
            text="▶  VAC AAN",
            command=self.start_vac,
            bg="#16a34a",
            fg="white",
            activebackground="#15803d",
            activeforeground="white",
            relief="flat",
            font=("Segoe UI Semibold", 12),
            padx=26,
            pady=11,
        )
        self.start_btn.pack(side="left", expand=True, fill="x", padx=(0, 6))

        self.stop_btn = tk.Button(
            actions,
            text="■  VAC UIT",
            command=self.stop_vac,
            bg="#dc2626",
            fg="white",
            activebackground="#b91c1c",
            activeforeground="white",
            relief="flat",
            font=("Segoe UI Semibold", 12),
            padx=26,
            pady=11,
            state="disabled",
        )
        self.stop_btn.pack(side="left", expand=True, fill="x", padx=(6, 0))

        bottom = tk.Frame(self.root, bg=bg)
        bottom.pack(fill="x", padx=24, pady=12)

        tk.Button(
            bottom,
            text="Reconnect",
            command=self.connect,
            bg="#2563eb",
            fg="white",
            activebackground="#1d4ed8",
            activeforeground="white",
            relief="flat",
            padx=16,
            pady=7,
        ).pack(side="left")

        tk.Button(
            bottom,
            text="Rescan CMobs",
            command=self.rescan_now,
            bg="#475569",
            fg="white",
            activebackground="#64748b",
            activeforeground="white",
            relief="flat",
            padx=16,
            pady=7,
        ).pack(side="right")

    def _format_x(self):
        side = "links" if self.offset_x < 0 else ("rechts" if self.offset_x > 0 else "op speler")
        return f"X offset: {self.offset_x:+d}px  ({side})"

    def _format_y(self):
        direction = "boven" if self.offset_y < 0 else ("onder" if self.offset_y > 0 else "zelfde hoogte")
        return f"Y offset: {self.offset_y:+d}px  ({direction})"

    def on_x_slider(self, raw):
        try:
            self.offset_x = int(round(float(raw)))
            self.x_var.set(self.offset_x)
            self.x_text.set(self._format_x())
        except Exception:
            pass

    def on_y_slider(self, raw):
        try:
            self.offset_y = int(round(float(raw)))
            self.y_var.set(self.offset_y)
            self.y_text.set(self._format_y())
        except Exception:
            pass

    def set_offset(self, x, y=0):
        self.offset_x = int(x)
        self.offset_y = int(y)
        self.x_scale.set(self.offset_x)
        self.y_scale.set(self.offset_y)
        self.x_text.set(self._format_x())
        self.y_text.set(self._format_y())

    def connect(self):
        self.stop_vac()

        try:
            self.pm = pymem.Pymem(TARGET)
            module = pymem.process.module_from_name(
                self.pm.process_handle,
                TARGET,
            )
            self.base = int(module.lpBaseOfDll)

            self.sig = struct.pack(
                "<III",
                self.base + VT0_RVA,
                self.base + VT1_RVA,
                self.base + VT2_RVA,
            )

            self.status_var.set(
                f"Connected — PID {self.pm.process_id} — base 0x{self.base:08X}"
            )

            self.scan_and_set_mobs()

        except Exception as e:
            self.pm = None
            self.base = None
            self.sig = None
            self.status_var.set(f"Connect fout: {e}")
            self.mob_var.set("CMobs: --")

    def scan_and_set_mobs(self):
        if not self.pm or not self.sig:
            return

        try:
            found = []

            for mob in scan_sig(self.pm, self.sig):
                if valid_mob(self.pm, mob, self.sig):
                    found.append(mob)

            with self.mob_lock:
                self.mobs = found

            self.mob_var.set(f"CMobs: {len(found)}")

        except Exception as e:
            self.status_var.set(f"Scan fout: {e}")

    def rescan_now(self):
        if not self.pm:
            self.connect()
            return

        threading.Thread(
            target=self.scan_and_set_mobs,
            daemon=True,
        ).start()

    def start_vac(self):
        if self.vac_enabled:
            return

        if not self.pm or not self.base:
            self.connect()

        if not self.pm:
            return

        self.scan_and_set_mobs()

        self.vac_enabled = True
        self.stop_event.clear()

        self.start_btn.config(
            text="VAC ACTIEF",
            state="disabled",
            bg="#166534",
        )
        self.stop_btn.config(state="normal")
        self.status_var.set("VAC AAN")

        self.worker = threading.Thread(
            target=self.vac_loop,
            daemon=True,
        )
        self.worker.start()

        self.scanner = threading.Thread(
            target=self.scan_loop,
            daemon=True,
        )
        self.scanner.start()

    def stop_vac(self):
        self.vac_enabled = False
        self.stop_event.set()

        if hasattr(self, "start_btn"):
            self.start_btn.config(
                text="▶  VAC AAN",
                state="normal",
                bg="#16a34a",
            )

        if hasattr(self, "stop_btn"):
            self.stop_btn.config(state="disabled")

        if self.pm:
            self.status_var.set("VAC UIT")

    def vac_loop(self):
        while self.vac_enabled and not self.stop_event.is_set():
            try:
                player = get_player(self.pm, self.base)

                if not player:
                    time.sleep(0.02)
                    continue

                _, px, py = player

                tx = px + int(self.offset_x)
                ty = py + int(self.offset_y)

                with self.mob_lock:
                    mobs = list(self.mobs)

                alive = []

                for mob in mobs:
                    if not valid_mob(self.pm, mob, self.sig):
                        continue

                    try:
                        write_mob_position(
                            self.pm,
                            mob,
                            tx,
                            ty,
                        )
                        alive.append(mob)
                    except Exception:
                        pass

                with self.mob_lock:
                    self.mobs = alive

                time.sleep(HOLD_INTERVAL)

            except Exception:
                time.sleep(0.03)

    def scan_loop(self):
        while self.vac_enabled and not self.stop_event.is_set():
            for _ in range(int(RESCAN_SECONDS / 0.1)):
                if not self.vac_enabled or self.stop_event.is_set():
                    return
                time.sleep(0.1)

            try:
                self.scan_and_set_mobs()
            except Exception:
                pass

    def refresh_ui(self):
        try:
            if self.pm and self.base:
                player = get_player(self.pm, self.base)

                if player:
                    _, px, py = player
                    tx = px + int(self.offset_x)
                    ty = py + int(self.offset_y)

                    self.player_var.set(
                        f"Player: ({px}, {py})"
                    )
                    self.target_var.set(
                        f"Target: ({tx}, {ty})"
                    )

                with self.mob_lock:
                    count = len(self.mobs)

                self.mob_var.set(
                    f"CMobs: {count}   |   VAC: {'AAN' if self.vac_enabled else 'UIT'}"
                )

        except Exception:
            pass

        try:
            if self.root.winfo_exists():
                self.root.after(150, self.refresh_ui)
        except Exception:
            pass

    def poll_hotkeys(self):
        try:
            user32 = ctypes.windll.user32

            for vk, action in (
                (0x74, self.start_vac),  # F5
                (0x75, self.stop_vac),   # F6
            ):
                down = bool(
                    user32.GetAsyncKeyState(vk) & 0x8000
                )

                if down and not self.hotkeys[vk]:
                    action()

                self.hotkeys[vk] = down

        except Exception:
            pass

        try:
            if self.root.winfo_exists():
                self.root.after(60, self.poll_hotkeys)
        except Exception:
            pass

    def close(self):
        self.stop_vac()
        time.sleep(0.05)

        try:
            self.root.destroy()
        except Exception:
            pass

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    SlimeTaleVacGUI().run()
