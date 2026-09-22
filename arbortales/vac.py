import ctypes
import ctypes.wintypes as wt
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

import pymem
import pymem.process
import pymem.exception


TARGET = "ArborTales.exe"

# ---------------- Confirmed ArborTales / v83 layout ----------------

# Player
CHAR_ROOT_RVA = 0x7ED788
CHAR_X_OFF = 0x5D4
CHAR_Y_OFF = 0x5D8

# CMob vtables / OID
VT0_RVA = 0x6F8270
VT1_RVA = 0x6F824C
VT2_RVA = 0x6F8248

OID_A_OFF = 0x17C
OID_B_OFF = 0x180
OID_CHECK_OFF = 0x184

# CMob current / previous position
MOB_X_OFF = 0x510
MOB_Y_OFF = 0x514
MOB_PREV_X_OFF = 0x518
MOB_PREV_Y_OFF = 0x51C

# Internal body position object
BODY_PTR_OFF = 0x4C0
BODY_X1_OFF = 0x54
BODY_Y1_OFF = 0x58
BODY_X2_OFF = 0x5C
BODY_Y2_OFF = 0x60

# Mirrored body position fields observed in the same v83 layout
BODY_X3_OFF = 0x84
BODY_Y3_OFF = 0x88
BODY_X4_OFF = 0x8C
BODY_Y4_OFF = 0x90

DEFAULT_X_OFFSET = 80
DEFAULT_Y_OFFSET = 0

# Conservative POC timings
HOLD_INTERVAL = 0.003
RESCAN_SECONDS = 3.0

# Memory constants
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

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


kernel32 = ctypes.windll.kernel32
shell32 = ctypes.windll.shell32
user32 = ctypes.windll.user32


# ---------------- Process helpers ----------------

def is_admin():
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    params = " ".join(f'"{arg}"' for arg in sys.argv)
    rc = shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        None,
        1,
    )
    return rc > 32


def find_pids_by_name(exe_name):
    exe_name = exe_name.lower()
    result = []

    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return result

    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    try:
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == exe_name:
                result.append(int(entry.th32ProcessID))
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)

    return result


# ---------------- v83 helpers ----------------

def rol32(v, n):
    v &= 0xFFFFFFFF
    n &= 31
    if not n:
        return v
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def ror32(v, n):
    v &= 0xFFFFFFFF
    n &= 31
    if not n:
        return v
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def secure_checksum(a, b):
    return (ror32(a ^ 0xBAADF00D, 5) + b) & 0xFFFFFFFF


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


def get_oid(pm, mob):
    a = read_u32(pm, mob + OID_A_OFF)
    b = read_u32(pm, mob + OID_B_OFF)
    c = read_u32(pm, mob + OID_CHECK_OFF)

    if None in (a, b, c):
        return None

    if secure_checksum(a, b) != c:
        return None

    return (rol32(b, 5) ^ a) & 0xFFFFFFFF


def iter_regions(pm):
    mbi = MBI()
    addr = 0

    while addr < 0x7FFFFFFF:
        result = kernel32.VirtualQueryEx(
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

            address = base + pos

            if address % 4 == 0:
                hits.append(address)

            pos += 4

    return hits


def get_player(pm, module_base):
    ptr = read_u32(pm, module_base + CHAR_ROOT_RVA)
    if not ptr:
        return None

    x = read_i32(pm, ptr + CHAR_X_OFF)
    y = read_i32(pm, ptr + CHAR_Y_OFF)

    if x is None or y is None:
        return None

    return ptr, x, y


def valid_mob(pm, mob, sig):
    try:
        if pm.read_bytes(mob, len(sig)) != sig:
            return False

        oid = get_oid(pm, mob)
        if oid is None:
            return False

        x = pm.read_int(mob + MOB_X_OFF)
        y = pm.read_int(mob + MOB_Y_OFF)

        return -30000 <= x <= 30000 and -30000 <= y <= 30000

    except Exception:
        return False


def scan_mobs(pm, module_base, sig):
    result = {}

    for mob in scan_sig(pm, sig):
        oid = get_oid(pm, mob)
        if oid is None:
            continue

        x = read_i32(pm, mob + MOB_X_OFF)
        y = read_i32(pm, mob + MOB_Y_OFF)

        if x is None or y is None:
            continue

        if not (-30000 <= x <= 30000 and -30000 <= y <= 30000):
            continue

        result[oid] = mob

    return result


def write_mob_position(pm, mob, x, y):
    """
    POC write path:
    - CMob current + previous position
    - internal body object position mirrors
    """
    pm.write_int(mob + MOB_X_OFF, x)
    pm.write_int(mob + MOB_Y_OFF, y)
    pm.write_int(mob + MOB_PREV_X_OFF, x)
    pm.write_int(mob + MOB_PREV_Y_OFF, y)

    body = read_u32(pm, mob + BODY_PTR_OFF)
    if not body:
        return False

    try:
        pm.write_int(body + BODY_X1_OFF, x)
        pm.write_int(body + BODY_Y1_OFF, y)
        pm.write_int(body + BODY_X2_OFF, x)
        pm.write_int(body + BODY_Y2_OFF, y)

        pm.write_int(body + BODY_X3_OFF, x)
        pm.write_int(body + BODY_Y3_OFF, y)
        pm.write_int(body + BODY_X4_OFF, x)
        pm.write_int(body + BODY_Y4_OFF, y)

        return True
    except Exception:
        return False


# ---------------- GUI ----------------

class ArborVacPOC:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ArborTales v83 VAC POC")
        self.root.geometry("780x610")
        self.root.minsize(720, 560)

        self.bg = "#0b1020"
        self.panel = "#121a2d"
        self.panel2 = "#18233b"
        self.text = "#f8fafc"
        self.muted = "#8ea0bd"
        self.cyan = "#38bdf8"
        self.green = "#16a34a"
        self.red = "#dc2626"

        self.root.configure(bg=self.bg)

        self.pm = None
        self.base = None
        self.sig = None
        self.mobs = {}

        self.vac_enabled = False
        self.stop_event = threading.Event()
        self.worker = None
        self.scanner = None
        self.mob_lock = threading.RLock()

        self.offset_x = DEFAULT_X_OFFSET
        self.offset_y = DEFAULT_Y_OFFSET

        self.last_scan_count = 0
        self.last_verified = 0

        self.hotkeys = {
            0x74: False,  # F5
            0x75: False,  # F6
        }

        self.status_var = tk.StringVar(value="Niet verbonden")
        self.player_var = tk.StringVar(value="Player: --")
        self.mob_var = tk.StringVar(value="CMobs: --")
        self.target_var = tk.StringVar(value="Target: --")
        self.verify_var = tk.StringVar(value="Verified: --")
        self.offset_x_var = tk.StringVar()
        self.offset_y_var = tk.StringVar()

        self._build_ui()
        self._update_offset_labels()

        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(100, self.poll_hotkeys)
        self.root.after(150, self.refresh_ui)

        self.connect()

    def _build_ui(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Arbor.Horizontal.TScale",
            background=self.panel,
            troughcolor="#334155",
        )

        header = tk.Frame(self.root, bg=self.bg)
        header.pack(fill="x", padx=24, pady=(20, 8))

        tk.Label(
            header,
            text="ARBORTALES v83 VAC POC",
            bg=self.bg,
            fg=self.cyan,
            font=("Segoe UI Semibold", 20),
        ).pack(side="left")

        tk.Label(
            header,
            text="F5 AAN   F6 UIT",
            bg="#1e3a5f",
            fg="#bfdbfe",
            padx=10,
            pady=5,
            font=("Consolas", 9, "bold"),
        ).pack(side="right")

        tk.Label(
            self.root,
            text="Eigen/private testomgeving • expliciete client-side mob-position POC",
            bg=self.bg,
            fg=self.muted,
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=24)

        status = tk.Frame(
            self.root,
            bg=self.panel,
            highlightbackground="#334155",
            highlightthickness=1,
        )
        status.pack(fill="x", padx=24, pady=(14, 8))

        for var in (
            self.status_var,
            self.player_var,
            self.mob_var,
            self.target_var,
            self.verify_var,
        ):
            tk.Label(
                status,
                textvariable=var,
                bg=self.panel,
                fg=self.text if var == self.status_var else self.muted,
                anchor="w",
                font=("Consolas", 10),
                padx=14,
                pady=4,
            ).pack(fill="x")

        controls = tk.Frame(
            self.root,
            bg=self.panel,
            highlightbackground="#334155",
            highlightthickness=1,
            padx=18,
            pady=16,
        )
        controls.pack(fill="x", padx=24, pady=8)

        tk.Label(
            controls,
            textvariable=self.offset_x_var,
            bg=self.panel,
            fg=self.text,
            font=("Segoe UI Semibold", 10),
        ).pack(anchor="w")

        self.x_scale = ttk.Scale(
            controls,
            from_=-350,
            to=350,
            orient="horizontal",
            style="Arbor.Horizontal.TScale",
            command=self.on_x_slider,
        )
        self.x_scale.set(self.offset_x)
        self.x_scale.pack(fill="x", pady=(4, 13))

        tk.Label(
            controls,
            textvariable=self.offset_y_var,
            bg=self.panel,
            fg=self.text,
            font=("Segoe UI Semibold", 10),
        ).pack(anchor="w")

        self.y_scale = ttk.Scale(
            controls,
            from_=-250,
            to=250,
            orient="horizontal",
            style="Arbor.Horizontal.TScale",
            command=self.on_y_slider,
        )
        self.y_scale.set(self.offset_y)
        self.y_scale.pack(fill="x", pady=(4, 12))

        presets = tk.Frame(controls, bg=self.panel)
        presets.pack(fill="x")

        for label, x, y in (
            ("Links -120", -120, 0),
            ("Links -80", -80, 0),
            ("Links -25", -25, 0),
            ("Op speler", 0, 0),
            ("Rechts +80", 80, 0),
            ("Rechts +120", 120, 0),
        ):
            tk.Button(
                presets,
                text=label,
                command=lambda a=x, b=y: self.set_offset(a, b),
                bg="#334155",
                fg="white",
                relief="flat",
                activebackground="#475569",
                activeforeground="white",
                padx=7,
                pady=5,
            ).pack(side="left", padx=(0, 5))

        actions = tk.Frame(self.root, bg=self.bg)
        actions.pack(fill="x", padx=24, pady=(10, 0))

        self.start_btn = tk.Button(
            actions,
            text="▶  VAC AAN",
            command=self.start_vac,
            bg=self.green,
            fg="white",
            activebackground="#15803d",
            activeforeground="white",
            relief="flat",
            font=("Segoe UI Semibold", 12),
            padx=24,
            pady=11,
        )
        self.start_btn.pack(side="left", expand=True, fill="x", padx=(0, 6))

        self.stop_btn = tk.Button(
            actions,
            text="■  VAC UIT",
            command=self.stop_vac,
            bg=self.red,
            fg="white",
            activebackground="#b91c1c",
            activeforeground="white",
            relief="flat",
            font=("Segoe UI Semibold", 12),
            padx=24,
            pady=11,
            state="disabled",
        )
        self.stop_btn.pack(side="left", expand=True, fill="x", padx=(6, 0))

        secondary = tk.Frame(self.root, bg=self.bg)
        secondary.pack(fill="x", padx=24, pady=12)

        tk.Button(
            secondary,
            text="Reconnect",
            command=self.connect,
            bg="#2563eb",
            fg="white",
            activebackground="#1d4ed8",
            activeforeground="white",
            relief="flat",
            padx=18,
            pady=7,
        ).pack(side="left")

        tk.Button(
            secondary,
            text="Rescan CMobs",
            command=self.rescan_now,
            bg="#475569",
            fg="white",
            activebackground="#64748b",
            activeforeground="white",
            relief="flat",
            padx=18,
            pady=7,
        ).pack(side="right")

        info = tk.Frame(
            self.root,
            bg=self.panel2,
            highlightbackground="#334155",
            highlightthickness=1,
        )
        info.pack(fill="both", expand=True, padx=24, pady=(0, 18))

        tk.Label(
            info,
            text=(
                "POC gedrag\n\n"
                "• VAC UIT: alleen player/CMob status uitlezen.\n"
                "• VAC AAN: alle gevalideerde CMob-objecten worden lokaal op de ingestelde\n"
                "  offset t.o.v. je character gehouden.\n"
                "• De scanner controleert de v83 vtable-signature + secure OID voordat een\n"
                "  object als CMob wordt gebruikt.\n"
                "• Geen debugger, injectie, stealth of anti-detectie in deze POC.\n\n"
                "Tip: begin met +80 X / 0 Y. F5 activeert, F6 stopt direct."
            ),
            bg=self.panel2,
            fg=self.muted,
            justify="left",
            anchor="nw",
            font=("Segoe UI", 9),
            padx=16,
            pady=14,
        ).pack(fill="both", expand=True)

    def _update_offset_labels(self):
        sx = "links" if self.offset_x < 0 else ("rechts" if self.offset_x > 0 else "op speler")
        sy = "boven" if self.offset_y < 0 else ("onder" if self.offset_y > 0 else "zelfde hoogte")
        self.offset_x_var.set(f"X offset: {self.offset_x:+d}px  ({sx})")
        self.offset_y_var.set(f"Y offset: {self.offset_y:+d}px  ({sy})")

    def on_x_slider(self, raw):
        try:
            self.offset_x = int(round(float(raw)))
            self._update_offset_labels()
        except Exception:
            pass

    def on_y_slider(self, raw):
        try:
            self.offset_y = int(round(float(raw)))
            self._update_offset_labels()
        except Exception:
            pass

    def set_offset(self, x, y=0):
        self.offset_x = int(x)
        self.offset_y = int(y)
        self.x_scale.set(self.offset_x)
        self.y_scale.set(self.offset_y)
        self._update_offset_labels()

    def _ui(self, fn, *args, **kwargs):
        try:
            self.root.after(0, lambda: fn(*args, **kwargs))
        except Exception:
            pass

    def connect(self):
        self.stop_vac()

        try:
            pids = find_pids_by_name(TARGET)

            if not pids:
                self.status_var.set(f"{TARGET} niet gevonden")
                self.pm = None
                self.base = None
                return

            pid = pids[-1]

            pm = pymem.Pymem()
            try:
                pm.open_process_from_id(pid)
            except pymem.exception.CouldNotOpenProcess:
                self.status_var.set(
                    f"Geen toegang tot PID {pid} — start deze tool als administrator"
                )
                self.pm = None
                self.base = None
                return

            module = pymem.process.module_from_name(
                pm.process_handle,
                TARGET,
            )

            if not module:
                self.status_var.set("Module ArborTales.exe niet gevonden")
                try:
                    pm.close_process()
                except Exception:
                    pass
                return

            self.pm = pm
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

            self.rescan_now()

        except Exception as e:
            self.pm = None
            self.base = None
            self.sig = None
            self.status_var.set(f"Connect fout: {e}")

    def scan_and_set_mobs(self):
        if not self.pm or not self.base or not self.sig:
            return

        try:
            found = scan_mobs(
                self.pm,
                self.base,
                self.sig,
            )

            with self.mob_lock:
                self.mobs = found
                self.last_scan_count = len(found)

            self._ui(
                self.mob_var.set,
                f"CMobs: {len(found)} gevonden"
            )

        except Exception as e:
            self._ui(self.status_var.set, f"Scan fout: {e}")

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

        # Initial scan first
        self.scan_and_set_mobs()

        self.vac_enabled = True
        self.stop_event.clear()

        self.start_btn.config(
            text="VAC ACTIEF",
            state="disabled",
            bg="#166534",
        )
        self.stop_btn.config(state="normal")
        self.status_var.set("VAC AAN — client-side CMob position POC actief")

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
                bg=self.green,
            )

        if hasattr(self, "stop_btn"):
            self.stop_btn.config(state="disabled")

        if self.pm:
            self.status_var.set("VAC UIT — normale client physics")

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
                    mob_items = list(self.mobs.items())

                alive = {}
                verified = 0

                for oid, mob in mob_items:
                    if get_oid(self.pm, mob) != oid:
                        continue

                    if not valid_mob(self.pm, mob, self.sig):
                        continue

                    try:
                        write_mob_position(
                            self.pm,
                            mob,
                            tx,
                            ty,
                        )

                        alive[oid] = mob

                        rx = read_i32(self.pm, mob + MOB_X_OFF)
                        ry = read_i32(self.pm, mob + MOB_Y_OFF)

                        if (
                            rx is not None and ry is not None
                            and abs(rx - tx) <= 4
                            and abs(ry - ty) <= 4
                        ):
                            verified += 1

                    except Exception:
                        pass

                with self.mob_lock:
                    self.mobs = alive
                    self.last_verified = verified

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
                discovered = scan_mobs(
                    self.pm,
                    self.base,
                    self.sig,
                )

                with self.mob_lock:
                    self.mobs.update(discovered)
                    self.last_scan_count = len(discovered)

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
                        f"VAC target: ({tx}, {ty})"
                    )

                with self.mob_lock:
                    count = len(self.mobs)
                    verified = self.last_verified

                self.mob_var.set(
                    f"CMobs: {count} actief • laatste scan {self.last_scan_count}"
                )

                self.verify_var.set(
                    f"Verified op target: {verified}/{count}"
                    if self.vac_enabled
                    else "Verified: VAC uit"
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

        if self.pm:
            try:
                self.pm.close_process()
            except Exception:
                pass

        try:
            self.root.destroy()
        except Exception:
            pass

    def run(self):
        self.root.mainloop()


def main():
    # If the game is elevated and this process is not, request the same rights.
    if not is_admin():
        pids = find_pids_by_name(TARGET)
        if pids:
            try:
                test_pm = pymem.Pymem()
                test_pm.open_process_from_id(pids[-1])
                test_pm.close_process()
            except Exception:
                if relaunch_as_admin():
                    return

    app = ArborVacPOC()
    app.run()


if __name__ == "__main__":
    main()
