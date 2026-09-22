import ctypes
import ctypes.wintypes as wt
import struct
import threading
import time
import tkinter as tk
from tkinter import ttk

import pymem
import pymem.process


# ============================================================
# YUNA MOB VAC
# ============================================================

PROCESS = "YunaMS.exe"

# ---------------- Player ----------------

CHAR_ROOT_RVA = 0x7ED788
CHAR_X_OFF = 0x5D4
CHAR_Y_OFF = 0x5D8

# ---------------- CMob vtables ----------------

VT0_RVA = 0x6F8270
VT1_RVA = 0x6F824C
VT2_RVA = 0x6F8248

# ---------------- Secure OID ----------------

OID_A_OFF = 0x17C
OID_B_OFF = 0x180
OID_CHECK_OFF = 0x184

# ---------------- CMob positions ----------------

MOB_X_OFF = 0x510
MOB_Y_OFF = 0x514

MOB_PREV_X_OFF = 0x518
MOB_PREV_Y_OFF = 0x51C

# ---------------- Settings ----------------

DEFAULT_X_OFFSET = -80

HOLD_INTERVAL = 0.005
RESCAN_SECONDS = 2.0


# ============================================================
# MEMORY CONSTANTS
# ============================================================

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
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32


# ============================================================
# BASIC HELPERS
# ============================================================

def rol32(v, n):
    v &= 0xFFFFFFFF
    n &= 31

    if n == 0:
        return v

    return (
        ((v << n) | (v >> (32 - n)))
        & 0xFFFFFFFF
    )


def ror32(v, n):
    v &= 0xFFFFFFFF
    n &= 31

    if n == 0:
        return v

    return (
        ((v >> n) | (v << (32 - n)))
        & 0xFFFFFFFF
    )


def secure_checksum(a, b):
    return (
        ror32(a ^ 0xBAADF00D, 5)
        + b
    ) & 0xFFFFFFFF


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


# ============================================================
# MOB HELPERS
# ============================================================

def get_oid(pm, mob):
    a = read_u32(
        pm,
        mob + OID_A_OFF
    )

    b = read_u32(
        pm,
        mob + OID_B_OFF
    )

    c = read_u32(
        pm,
        mob + OID_CHECK_OFF
    )

    if None in (a, b, c):
        return None

    if secure_checksum(a, b) != c:
        return None

    return (
        rol32(b, 5) ^ a
    ) & 0xFFFFFFFF


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

        base = int(
            mbi.BaseAddress or 0
        )

        size = int(
            mbi.RegionSize
        )

        protect = (
            int(mbi.Protect)
            & 0xFF
        )

        if (
            mbi.State == MEM_COMMIT
            and
            mbi.Type == MEM_PRIVATE
            and
            protect in WRITABLE
            and
            0 < size <= 32 * 1024 * 1024
        ):
            yield base, size

        if size <= 0:
            break

        addr = base + size


def scan_sig(pm, sig):
    hits = []

    for region_base, size in iter_regions(pm):

        try:
            data = pm.read_bytes(
                region_base,
                size
            )
        except Exception:
            continue

        pos = 0

        while True:

            pos = data.find(
                sig,
                pos
            )

            if pos < 0:
                break

            address = (
                region_base + pos
            )

            if address % 4 == 0:
                hits.append(address)

            pos += 4

    return hits


def valid_mob(pm, mob, sig):
    try:

        if (
            pm.read_bytes(
                mob,
                len(sig)
            )
            != sig
        ):
            return False

        oid = get_oid(
            pm,
            mob
        )

        if oid is None:
            return False

        x = pm.read_int(
            mob + MOB_X_OFF
        )

        y = pm.read_int(
            mob + MOB_Y_OFF
        )

        return (
            -30000 <= x <= 30000
            and
            -30000 <= y <= 30000
        )

    except Exception:
        return False


def scan_mobs(pm, sig):
    result = {}

    for mob in scan_sig(
        pm,
        sig
    ):

        oid = get_oid(
            pm,
            mob
        )

        if oid is None:
            continue

        if valid_mob(
            pm,
            mob,
            sig
        ):
            result[oid] = mob

    return result


# ============================================================
# GUI
# ============================================================

class YunaVac:

    def __init__(self):

        self.root = tk.Tk()

        self.root.title(
            "Yuna Mob VAC"
        )

        self.root.geometry(
            "420x300"
        )

        self.root.resizable(
            False,
            False
        )

        # ---------------- Runtime ----------------

        self.pm = None
        self.base = None
        self.sig = None

        self.enabled = False
        self.running = True

        self.offset_x = (
            DEFAULT_X_OFFSET
        )

        self.mobs = {}

        self.mob_lock = (
            threading.RLock()
        )

        self.last_f5 = False
        self.last_f6 = False

        self.worker_started = False

        # ---------------- GUI vars ----------------

        self.status_var = (
            tk.StringVar(
                value="YunaMS zoeken..."
            )
        )

        self.mob_var = (
            tk.StringVar(
                value="Mobs: 0"
            )
        )

        self.offset_var = (
            tk.StringVar(
                value=(
                    f"X offset: "
                    f"{DEFAULT_X_OFFSET:+d}"
                )
            )
        )

        # ---------------- UI ----------------

        self.build_ui()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close
        )

        self.root.after(
            50,
            self.poll_hotkeys
        )

        self.root.after(
            100,
            self.connection_tick
        )

    # ========================================================

    def build_ui(self):

        bg = "#0e131d"
        panel = "#171e2b"

        text = "#ffffff"
        muted = "#a9b6ca"

        self.green = "#166534"
        self.red = "#991b1b"

        self.root.configure(
            bg=bg
        )

        # ---------------- Header ----------------

        tk.Label(
            self.root,
            text="YUNA MOB VAC",
            bg=bg,
            fg=text,
            font=(
                "Segoe UI",
                18,
                "bold",
            ),
        ).pack(
            pady=(18, 3)
        )

        tk.Label(
            self.root,
            text=(
                "F5 = AAN      "
                "F6 = UIT"
            ),
            bg=bg,
            fg=muted,
            font=(
                "Consolas",
                10,
            ),
        ).pack()

        # ---------------- Status ----------------

        info = tk.Frame(
            self.root,
            bg=panel,
        )

        info.pack(
            fill="x",
            padx=20,
            pady=(15, 12),
        )

        tk.Label(
            info,
            textvariable=(
                self.status_var
            ),
            bg=panel,
            fg=text,
            font=(
                "Segoe UI",
                10,
                "bold",
            ),
        ).pack(
            pady=(11, 3)
        )

        tk.Label(
            info,
            textvariable=(
                self.mob_var
            ),
            bg=panel,
            fg=muted,
            font=(
                "Consolas",
                11,
            ),
        ).pack(
            pady=(3, 11)
        )

        # ---------------- Offset label ----------------

        tk.Label(
            self.root,
            textvariable=(
                self.offset_var
            ),
            bg=bg,
            fg=text,
            font=(
                "Segoe UI",
                11,
            ),
        ).pack(
            pady=(3, 4)
        )

        # ---------------- Slider ----------------

        self.slider = ttk.Scale(
            self.root,
            from_=-250,
            to=250,
            orient="horizontal",
            length=350,
            command=(
                self.slider_changed
            ),
        )

        self.slider.set(
            DEFAULT_X_OFFSET
        )

        self.slider.pack(
            pady=(0, 14)
        )

        # ---------------- VAC state ----------------

        self.state_label = tk.Label(
            self.root,
            text="VAC UIT",
            bg=self.red,
            fg="white",
            width=25,
            pady=6,
            font=(
                "Segoe UI",
                11,
                "bold",
            ),
        )

        self.state_label.pack()

    # ========================================================

    def slider_changed(
        self,
        value
    ):

        try:

            self.offset_x = int(
                round(
                    float(value)
                )
            )

            self.offset_var.set(
                f"X offset: "
                f"{self.offset_x:+d}"
            )

        except Exception:
            pass

    # ========================================================
    # CONNECTION
    # ========================================================

    def connect(self):

        if self.pm:
            return True

        try:

            pm = pymem.Pymem(
                PROCESS
            )

            module = (
                pymem.process.module_from_name(
                    pm.process_handle,
                    PROCESS,
                )
            )

            if not module:

                try:
                    pm.close_process()
                except Exception:
                    pass

                self.status_var.set(
                    "YunaMS module niet gevonden"
                )

                return False

            self.pm = pm

            self.base = int(
                module.lpBaseOfDll
            )

            self.sig = struct.pack(
                "<III",
                self.base + VT0_RVA,
                self.base + VT1_RVA,
                self.base + VT2_RVA,
            )

            self.status_var.set(
                f"Connected PID "
                f"{self.pm.process_id}"
            )

            if not self.worker_started:

                self.worker_started = True

                threading.Thread(
                    target=self.scan_loop,
                    daemon=True,
                ).start()

                threading.Thread(
                    target=self.vac_loop,
                    daemon=True,
                ).start()

            return True

        except Exception:

            self.pm = None
            self.base = None
            self.sig = None

            self.status_var.set(
                "YunaMS niet gevonden / geen toegang"
            )

            return False

    # ========================================================

    def disconnect(self):

        self.enabled = False

        self.state_label.config(
            text="VAC UIT",
            bg=self.red,
        )

        with self.mob_lock:
            self.mobs = {}

        self.mob_var.set(
            "Mobs: 0"
        )

        if self.pm:

            try:
                self.pm.close_process()
            except Exception:
                pass

        self.pm = None
        self.base = None
        self.sig = None

    # ========================================================

    def connection_tick(self):

        if not self.running:
            return

        if not self.pm:

            self.connect()

        else:

            try:

                # Alleen simpele read om te zien
                # of process nog leeft.
                self.pm.read_bytes(
                    self.base,
                    1
                )

            except Exception:

                self.disconnect()

                self.status_var.set(
                    "Verbinding verloren..."
                )

        self.root.after(
            1500,
            self.connection_tick
        )

    # ========================================================
    # PLAYER
    # ========================================================

    def get_player_position(self):

        if (
            not self.pm
            or
            not self.base
        ):
            return None

        ptr = read_u32(
            self.pm,
            self.base
            + CHAR_ROOT_RVA,
        )

        if not ptr:
            return None

        x = read_i32(
            self.pm,
            ptr + CHAR_X_OFF
        )

        y = read_i32(
            self.pm,
            ptr + CHAR_Y_OFF
        )

        if (
            x is None
            or
            y is None
        ):
            return None

        return x, y

    # ========================================================
    # VAC CONTROL
    # ========================================================

    def start_vac(self):

        if not self.pm:

            self.connect()

        if not self.pm:
            return

        self.enabled = True

        self.state_label.config(
            text="VAC AAN",
            bg=self.green,
        )

    # ========================================================

    def stop_vac(self):

        self.enabled = False

        self.state_label.config(
            text="VAC UIT",
            bg=self.red,
        )

    # ========================================================
    # MOB SCANNER
    # ========================================================

    def scan_loop(self):

        while self.running:

            if (
                not self.pm
                or
                not self.sig
            ):

                time.sleep(0.5)
                continue

            try:

                found = scan_mobs(
                    self.pm,
                    self.sig,
                )

                with self.mob_lock:
                    self.mobs = found

                self.root.after(
                    0,
                    lambda n=len(found):
                    self.mob_var.set(
                        f"Mobs: {n}"
                    )
                )

            except Exception:
                pass

            time.sleep(
                RESCAN_SECONDS
            )

    # ========================================================
    # VAC LOOP
    # ========================================================

    def vac_loop(self):

        while self.running:

            if (
                not self.enabled
                or
                not self.pm
            ):

                time.sleep(0.02)
                continue

            try:

                player = (
                    self.get_player_position()
                )

                if not player:

                    time.sleep(0.02)
                    continue

                px, py = player

                tx = (
                    px
                    + int(
                        self.offset_x
                    )
                )

                # Y stays equal to player Y.
                ty = py

                with self.mob_lock:

                    mob_items = list(
                        self.mobs.items()
                    )

                alive = {}

                for oid, mob in mob_items:

                    try:

                        if (
                            get_oid(
                                self.pm,
                                mob
                            )
                            != oid
                        ):
                            continue

                        if not valid_mob(
                            self.pm,
                            mob,
                            self.sig
                        ):
                            continue

                        # ====================================
                        # ONLY these four fields
                        # ====================================

                        self.pm.write_int(
                            mob + MOB_X_OFF,
                            tx,
                        )

                        self.pm.write_int(
                            mob + MOB_Y_OFF,
                            ty,
                        )

                        self.pm.write_int(
                            mob
                            + MOB_PREV_X_OFF,
                            tx,
                        )

                        self.pm.write_int(
                            mob
                            + MOB_PREV_Y_OFF,
                            ty,
                        )

                        alive[oid] = mob

                    except Exception:
                        pass

                with self.mob_lock:

                    self.mobs = alive

            except Exception:
                pass

            time.sleep(
                HOLD_INTERVAL
            )

    # ========================================================
    # HOTKEYS
    # ========================================================

    def poll_hotkeys(self):

        if not self.running:
            return

        try:

            f5 = bool(
                user32.GetAsyncKeyState(
                    0x74
                )
                & 0x8000
            )

            f6 = bool(
                user32.GetAsyncKeyState(
                    0x75
                )
                & 0x8000
            )

            if (
                f5
                and
                not self.last_f5
            ):
                self.start_vac()

            if (
                f6
                and
                not self.last_f6
            ):
                self.stop_vac()

            self.last_f5 = f5
            self.last_f6 = f6

        except Exception:
            pass

        self.root.after(
            50,
            self.poll_hotkeys
        )

    # ========================================================

    def close(self):

        self.enabled = False
        self.running = False

        if self.pm:

            try:
                self.pm.close_process()
            except Exception:
                pass

        try:
            self.root.destroy()
        except Exception:
            pass

    # ========================================================

    def run(self):

        self.root.mainloop()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    app = YunaVac()
    app.run()