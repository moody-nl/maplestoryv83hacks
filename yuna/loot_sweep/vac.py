import ctypes
import ctypes.wintypes as wt
import struct
import threading
import time
import tkinter as tk

import pymem
import pymem.process


PROCESS = "YunaMS.exe"


# ============================================================
# PLAYER
# ============================================================

CHAR_ROOT_RVA = 0x7ED788

CHAR_X_OFF = 0x5D4
CHAR_Y_OFF = 0x5D8
MAP_ID_OFF = 0x668


# ============================================================
# WORKING PLAYER TELEPORT
# ============================================================

TELEPORT_ROOT_RVA = 0x7EBF98

TP_X1 = 0x2B18
TP_Y1 = 0x2B1C
TP_X2 = 0x2B20
TP_Y2 = 0x2B24


# ============================================================
# YUNA DROP OBJECTS
#
# Strong active object:
#
# +00 = base + 0x6F3788
# +0C = base + 0x6F3784
# +30 = OID
#
# Spatial position node:
#
# +00 = base + 0x6F3774
# +04 = 0
# +08 = OID
# +0C = X
# +10 = Y
# +14 = 0x14
#
# ============================================================

DROP_OBJECT_VT0_RVA = 0x6F3788
DROP_OBJECT_VT1_RVA = 0x6F3784

DROP_OBJECT_OID_OFF = 0x30


DROP_NODE_VT_RVA = 0x6F3774

DROP_NODE_OID_OFF = 0x08
DROP_NODE_X_OFF = 0x0C
DROP_NODE_Y_OFF = 0x10
DROP_NODE_MAGIC_OFF = 0x14


# Fallback only
DROP_CHILD_PTR_OFF = 0x4C
DROP_CHILD_X_OFF = 0x1C
DROP_CHILD_Y_OFF = 0x20


# ============================================================
# LOOT SETTINGS
# ============================================================

# Default exact drop Y.
DEFAULT_Y_ADJUST = 0

# Drops within this distance are treated as ONE pickup location.
CLUSTER_DISTANCE = 12

# First pause after teleport.
TELEPORT_SETTLE = 0.08

# Repeated Z presses at each location.
PICKUP_TAPS = 5

# If drops remain at that location, perform one extra burst.
EXTRA_PICKUP_TAPS = 3

Z_DOWN_TIME = 0.035
Z_UP_TIME = 0.045

# Fresh rescan for leftovers.
MAX_PASSES = 2


# ============================================================
# WINDOWS
# ============================================================

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32


VK_F1 = 0x70
VK_F2 = 0x71
VK_F3 = 0x72
VK_F4 = 0x73

VK_Z = 0x5A

KEYEVENTF_KEYUP = 0x0002


# ============================================================
# MEMORY
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


# ============================================================
# BASIC MEMORY HELPERS
# ============================================================

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


def sane_coord(v):
    return (
        v is not None
        and -30000 <= v <= 30000
    )


# ============================================================
# MEMORY REGIONS
# ============================================================

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


# ============================================================
# SIGNATURE SCAN
# ============================================================

def scan_signature(pm, signature):
    hits = []

    for base, size in iter_regions(pm):
        try:
            data = pm.read_bytes(
                base,
                size,
            )

        except Exception:
            continue

        pos = 0

        while True:
            pos = data.find(
                signature,
                pos,
            )

            if pos < 0:
                break

            address = (
                base
                + pos
            )

            if address % 4 == 0:
                hits.append(
                    address
                )

            pos += 1

    return hits


# ============================================================
# STRONG DROP OBJECTS
# ============================================================

def scan_active_drop_objects(
    pm,
    module_base,
):
    vt0 = (
        module_base
        + DROP_OBJECT_VT0_RVA
    )

    vt1 = (
        module_base
        + DROP_OBJECT_VT1_RVA
    )

    signature = struct.pack(
        "<I",
        vt0,
    )

    result = {}

    for obj in scan_signature(
        pm,
        signature,
    ):
        try:
            if read_u32(
                pm,
                obj,
            ) != vt0:
                continue

            if read_u32(
                pm,
                obj + 0x0C,
            ) != vt1:
                continue

            ref_count = read_u32(
                pm,
                obj + 0x04,
            )

            if (
                ref_count is None
                or ref_count > 16
            ):
                continue

            oid = read_u32(
                pm,
                obj + DROP_OBJECT_OID_OFF,
            )

            if (
                oid is None
                or oid == 0
                or oid == 0xFFFFFFFF
            ):
                continue

            result[oid] = obj

        except Exception:
            continue

    return result


def object_is_live(
    pm,
    module_base,
    obj,
    expected_oid,
):
    vt0 = (
        module_base
        + DROP_OBJECT_VT0_RVA
    )

    vt1 = (
        module_base
        + DROP_OBJECT_VT1_RVA
    )

    try:
        if read_u32(
            pm,
            obj,
        ) != vt0:
            return False

        if read_u32(
            pm,
            obj + 0x0C,
        ) != vt1:
            return False

        oid = read_u32(
            pm,
            obj + DROP_OBJECT_OID_OFF,
        )

        return (
            oid == expected_oid
        )

    except Exception:
        return False


# ============================================================
# POSITION NODES
# ============================================================

def scan_drop_nodes(
    pm,
    module_base,
    active_objects,
):
    node_vt = (
        module_base
        + DROP_NODE_VT_RVA
    )

    signature = struct.pack(
        "<I",
        node_vt,
    )

    result = {}

    for node in scan_signature(
        pm,
        signature,
    ):
        try:
            if read_u32(
                pm,
                node,
            ) != node_vt:
                continue

            # The spatial node observed in this layout uses 0 here.
            if read_u32(
                pm,
                node + 0x04,
            ) != 0:
                continue

            if read_u32(
                pm,
                node + DROP_NODE_MAGIC_OFF,
            ) != 0x14:
                continue

            oid = read_u32(
                pm,
                node + DROP_NODE_OID_OFF,
            )

            # Critical:
            # only accept nodes linked to a currently live strong object.
            if oid not in active_objects:
                continue

            x = read_i32(
                pm,
                node + DROP_NODE_X_OFF,
            )

            y = read_i32(
                pm,
                node + DROP_NODE_Y_OFF,
            )

            if not (
                sane_coord(x)
                and
                sane_coord(y)
            ):
                continue

            result[oid] = {
                "oid": oid,
                "obj": active_objects[oid],
                "node": node,
                "x": x,
                "y": y,
                "source": "node",
            }

        except Exception:
            continue

    return result


# ============================================================
# FALLBACK POSITION
# ============================================================

def fallback_object_position(
    pm,
    obj,
):
    ptr = read_u32(
        pm,
        obj + DROP_CHILD_PTR_OFF,
    )

    if not ptr:
        return None

    x = read_i32(
        pm,
        ptr + DROP_CHILD_X_OFF,
    )

    y = read_i32(
        pm,
        ptr + DROP_CHILD_Y_OFF,
    )

    if not (
        sane_coord(x)
        and
        sane_coord(y)
    ):
        return None

    return x, y


# ============================================================
# COMPLETE DROP SNAPSHOT
# ============================================================

def scan_drops(
    pm,
    module_base,
):
    active = scan_active_drop_objects(
        pm,
        module_base,
    )

    nodes = scan_drop_nodes(
        pm,
        module_base,
        active,
    )

    drops = {}

    # Prefer spatial node positions.
    for oid, info in nodes.items():
        drops[oid] = info

    fallback_count = 0

    # Only fallback when there was no matching spatial node.
    for oid, obj in active.items():
        if oid in drops:
            continue

        pos = fallback_object_position(
            pm,
            obj,
        )

        if not pos:
            continue

        x, y = pos

        drops[oid] = {
            "oid": oid,
            "obj": obj,
            "node": None,
            "x": x,
            "y": y,
            "source": "fallback",
        }

        fallback_count += 1

    return (
        list(drops.values()),
        len(active),
        len(nodes),
        fallback_count,
    )


# ============================================================
# GROUP DROPS BY LOCATION
# ============================================================

def make_clusters(drops):
    clusters = []

    r2 = (
        CLUSTER_DISTANCE
        * CLUSTER_DISTANCE
    )

    for drop in drops:
        found = None

        for cluster in clusters:
            dx = (
                drop["x"]
                - cluster["x"]
            )

            dy = (
                drop["y"]
                - cluster["y"]
            )

            if (
                dx * dx
                + dy * dy
                <= r2
            ):
                found = cluster
                break

        if found is None:
            clusters.append(
                {
                    "x": drop["x"],
                    "y": drop["y"],
                    "drops": [drop],
                }
            )

        else:
            found["drops"].append(
                drop
            )

            # Average position for the cluster.
            count = len(
                found["drops"]
            )

            sx = sum(
                d["x"]
                for d in found["drops"]
            )

            sy = sum(
                d["y"]
                for d in found["drops"]
            )

            found["x"] = int(
                round(
                    sx / count
                )
            )

            found["y"] = int(
                round(
                    sy / count
                )
            )

    return clusters


# ============================================================
# APP
# ============================================================

class YunaLootSweep:

    def __init__(self):
        self.root = tk.Tk()

        self.root.title(
            "Yuna Loot Sweep"
        )

        self.root.geometry(
            "570x395"
        )

        self.root.resizable(
            False,
            False
        )

        self.pm = None
        self.base = None

        self.running = True

        self.worker = None

        self.stop_event = (
            threading.Event()
        )

        self.y_adjust = (
            DEFAULT_Y_ADJUST
        )

        self.last_f1 = False
        self.last_f2 = False
        self.last_f3 = False
        self.last_f4 = False

        self.status_var = tk.StringVar(
            value="YunaMS zoeken..."
        )

        self.pos_var = tk.StringVar(
            value="Player: --"
        )

        self.scan_var = tk.StringVar(
            value="Scan: --"
        )

        self.drop_var = tk.StringVar(
            value="Drops: --"
        )

        self.progress_var = tk.StringVar(
            value="Progress: --"
        )

        self.adjust_var = tk.StringVar(
            value="Target Y adjust: +0"
        )

        self.input_var = tk.StringVar(
            value="Pickup: repeated Z taps"
        )

        self.build_ui()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close,
        )

        self.root.after(
            100,
            self.connection_tick,
        )

        self.root.after(
            30,
            self.hotkey_tick,
        )

        self.root.after(
            100,
            self.player_tick,
        )

    # ========================================================
    # UI
    # ========================================================

    def build_ui(self):
        bg = "#0e131d"
        panel = "#171e2b"

        fg = "#ffffff"
        muted = "#9aa7b8"

        self.root.configure(
            bg=bg
        )

        tk.Label(
            self.root,
            text="YUNA LOOT SWEEP",
            bg=bg,
            fg=fg,
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
                "F1 START   "
                "F2 STOP   "
                "F3 Y-5   "
                "F4 Y+5"
            ),
            bg=bg,
            fg=muted,
            font=(
                "Consolas",
                10,
                "bold",
            ),
        ).pack()

        box = tk.Frame(
            self.root,
            bg=panel,
        )

        box.pack(
            fill="x",
            padx=22,
            pady=16,
        )

        for variable in (
            self.status_var,
            self.pos_var,
            self.scan_var,
            self.drop_var,
            self.progress_var,
            self.adjust_var,
            self.input_var,
        ):
            tk.Label(
                box,
                textvariable=variable,
                bg=panel,
                fg=fg,
                font=(
                    "Consolas",
                    10,
                ),
            ).pack(
                pady=3
            )

        buttons = tk.Frame(
            self.root,
            bg=bg,
        )

        buttons.pack()

        tk.Button(
            buttons,
            text="START [F1]",
            command=self.start_sweep,
            width=18,
            pady=8,
            bg="#166534",
            fg="white",
            relief="flat",
        ).pack(
            side="left",
            padx=6,
        )

        tk.Button(
            buttons,
            text="STOP [F2]",
            command=self.stop_sweep,
            width=18,
            pady=8,
            bg="#991b1b",
            fg="white",
            relief="flat",
        ).pack(
            side="left",
            padx=6,
        )

    # ========================================================

    def ui_set(
        self,
        variable,
        value,
    ):
        try:
            self.root.after(
                0,
                lambda v=variable, x=value: v.set(x),
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
                return False

            self.pm = pm

            self.base = int(
                module.lpBaseOfDll
            )

            self.status_var.set(
                f"Connected PID "
                f"{pm.process_id}"
            )

            return True

        except Exception:
            self.pm = None
            self.base = None

            self.status_var.set(
                "YunaMS niet gevonden"
            )

            return False

    # ========================================================
    # PLAYER
    # ========================================================

    def get_player(self):
        if not self.pm:
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
            ptr + CHAR_X_OFF,
        )

        y = read_i32(
            self.pm,
            ptr + CHAR_Y_OFF,
        )

        map_id = read_i32(
            self.pm,
            ptr + MAP_ID_OFF,
        )

        if (
            x is None
            or
            y is None
            or
            map_id is None
        ):
            return None

        return (
            ptr,
            x,
            y,
            map_id,
        )

    # ========================================================
    # TELEPORT
    # ========================================================

    def teleport(
        self,
        x,
        y,
    ):
        tp = read_u32(
            self.pm,
            self.base
            + TELEPORT_ROOT_RVA,
        )

        if not tp:
            return False

        try:
            x = int(x)
            y = int(y)

            self.pm.write_int(
                tp + TP_X1,
                x,
            )

            self.pm.write_int(
                tp + TP_Y1,
                y,
            )

            self.pm.write_int(
                tp + TP_X2,
                x,
            )

            self.pm.write_int(
                tp + TP_Y2,
                y,
            )

            return True

        except Exception:
            return False

    # ========================================================
    # YUNA FOCUS
    # ========================================================

    def yuna_is_foreground(self):
        if not self.pm:
            return False

        try:
            hwnd = (
                user32.GetForegroundWindow()
            )

            if not hwnd:
                return False

            pid = wt.DWORD()

            user32.GetWindowThreadProcessId(
                hwnd,
                ctypes.byref(pid),
            )

            return (
                pid.value
                ==
                self.pm.process_id
            )

        except Exception:
            return False

    def wait_for_game(self):
        while not self.stop_event.is_set():
            if self.yuna_is_foreground():
                return True

            self.ui_set(
                self.status_var,
                "PAUSED - klik YunaMS aan",
            )

            time.sleep(
                0.10
            )

        return False

    # ========================================================
    # Z INPUT
    # ========================================================

    def z_up_safety(self):
        scan = user32.MapVirtualKeyW(
            VK_Z,
            0,
        )

        user32.keybd_event(
            VK_Z,
            scan,
            KEYEVENTF_KEYUP,
            0,
        )

    def tap_z(self):
        scan = user32.MapVirtualKeyW(
            VK_Z,
            0,
        )

        user32.keybd_event(
            VK_Z,
            scan,
            0,
            0,
        )

        time.sleep(
            Z_DOWN_TIME
        )

        user32.keybd_event(
            VK_Z,
            scan,
            KEYEVENTF_KEYUP,
            0,
        )

        time.sleep(
            Z_UP_TIME
        )

    # ========================================================
    # STOPPABLE WAIT
    # ========================================================

    def wait_stop(
        self,
        seconds,
    ):
        end = (
            time.perf_counter()
            + seconds
        )

        while (
            time.perf_counter()
            < end
        ):
            if self.stop_event.is_set():
                return True

            time.sleep(
                0.01
            )

        return False

    # ========================================================
    # CLUSTER LIVE COUNT
    # ========================================================

    def cluster_live_count(
        self,
        cluster,
    ):
        count = 0

        for drop in cluster["drops"]:
            if object_is_live(
                self.pm,
                self.base,
                drop["obj"],
                drop["oid"],
            ):
                count += 1

        return count

    # ========================================================
    # PICKUP BURST
    # ========================================================

    def pickup_burst(
        self,
        cluster,
        target_x,
        target_y,
        tap_count,
    ):
        for _ in range(
            tap_count
        ):
            if self.stop_event.is_set():
                return False

            if not self.wait_for_game():
                return False

            # Important:
            # re-assert position before every pickup press.
            #
            # This prevents gravity from moving the character
            # away from the drop before Z is processed.
            self.teleport(
                target_x,
                target_y,
            )

            time.sleep(
                0.025
            )

            self.tap_z()

            # Stop early if the entire location is already gone.
            if (
                self.cluster_live_count(
                    cluster
                )
                == 0
            ):
                return True

        return True

    # ========================================================
    # START / STOP
    # ========================================================

    def start_sweep(self):
        if (
            self.worker
            and
            self.worker.is_alive()
        ):
            self.status_var.set(
                "Sweep draait al"
            )

            return

        if not self.pm:
            if not self.connect():
                return

        self.stop_event.clear()

        self.status_var.set(
            "F1 ontvangen - scanning..."
        )

        self.progress_var.set(
            "Progress: starten..."
        )

        self.worker = threading.Thread(
            target=self.sweep,
            daemon=True,
        )

        self.worker.start()

    def stop_sweep(self):
        self.stop_event.set()

        self.z_up_safety()

        self.status_var.set(
            "STOP..."
        )

    # ========================================================
    # Y ADJUST
    # ========================================================

    def adjust_up(self):
        self.y_adjust -= 5

        self.adjust_var.set(
            f"Target Y adjust: "
            f"{self.y_adjust:+d}"
        )

    def adjust_down(self):
        self.y_adjust += 5

        self.adjust_var.set(
            f"Target Y adjust: "
            f"{self.y_adjust:+d}"
        )

    # ========================================================
    # SWEEP
    # ========================================================

    def sweep(self):
        start = self.get_player()

        if not start:
            self.ui_set(
                self.status_var,
                "Player niet gevonden",
            )

            return

        (
            _,
            start_x,
            start_y,
            start_map,
        ) = start

        visited_locations = 0
        disappeared_total = 0

        try:
            for pass_num in range(
                1,
                MAX_PASSES + 1,
            ):
                if self.stop_event.is_set():
                    break

                self.ui_set(
                    self.status_var,
                    (
                        f"Pass {pass_num}: "
                        f"drops zoeken..."
                    ),
                )

                (
                    drops,
                    active_count,
                    node_count,
                    fallback_count,
                ) = scan_drops(
                    self.pm,
                    self.base,
                )

                clusters = make_clusters(
                    drops
                )

                self.ui_set(
                    self.scan_var,
                    (
                        f"Active={active_count}  "
                        f"NodePos={node_count}  "
                        f"Fallback={fallback_count}"
                    ),
                )

                self.ui_set(
                    self.drop_var,
                    (
                        f"Drops={len(drops)}  "
                        f"Locations={len(clusters)}"
                    ),
                )

                print("")
                print(
                    f"=== PASS {pass_num} ==="
                )

                print(
                    f"active={active_count} "
                    f"nodepos={node_count} "
                    f"fallback={fallback_count}"
                )

                print(
                    f"{len(drops)} drops -> "
                    f"{len(clusters)} locaties"
                )

                if not clusters:
                    break

                player = self.get_player()

                if player:
                    _, px, py, _ = player
                else:
                    px = start_x
                    py = start_y

                # Nearest pickup location first.
                clusters.sort(
                    key=lambda c: (
                        (c["x"] - px) ** 2
                        +
                        (c["y"] - py) ** 2
                    )
                )

                for index, cluster in enumerate(
                    clusters,
                    start=1,
                ):
                    if self.stop_event.is_set():
                        break

                    player = self.get_player()

                    if not player:
                        break

                    (
                        _,
                        _,
                        _,
                        current_map,
                    ) = player

                    if current_map != start_map:
                        self.stop_event.set()

                        self.ui_set(
                            self.status_var,
                            "Map veranderd - STOP",
                        )

                        break

                    live_before = (
                        self.cluster_live_count(
                            cluster
                        )
                    )

                    if live_before == 0:
                        continue

                    target_x = (
                        cluster["x"]
                    )

                    target_y = (
                        cluster["y"]
                        + self.y_adjust
                    )

                    visited_locations += 1

                    self.ui_set(
                        self.progress_var,
                        (
                            f"Pass {pass_num}: "
                            f"locatie {index}/{len(clusters)} "
                            f"({target_x},{target_y}) "
                            f"drops={live_before}"
                        ),
                    )

                    self.ui_set(
                        self.status_var,
                        (
                            f"Teleport -> "
                            f"({target_x},{target_y})"
                        ),
                    )

                    print(
                        f"[{index}/{len(clusters)}] "
                        f"target=({target_x},{target_y}) "
                        f"drops={live_before}"
                    )

                    if not self.teleport(
                        target_x,
                        target_y,
                    ):
                        print(
                            "    teleport FAIL"
                        )

                        continue

                    if self.wait_stop(
                        TELEPORT_SETTLE
                    ):
                        break

                    # First pickup burst.
                    if not self.pickup_burst(
                        cluster,
                        target_x,
                        target_y,
                        PICKUP_TAPS,
                    ):
                        break

                    live_after = (
                        self.cluster_live_count(
                            cluster
                        )
                    )

                    # One extra burst only if needed.
                    if (
                        live_after > 0
                        and
                        not self.stop_event.is_set()
                    ):
                        print(
                            f"    {live_after} nog live, "
                            f"extra Z burst"
                        )

                        self.pickup_burst(
                            cluster,
                            target_x,
                            target_y,
                            EXTRA_PICKUP_TAPS,
                        )

                        live_after = (
                            self.cluster_live_count(
                                cluster
                            )
                        )

                    disappeared = (
                        live_before
                        - live_after
                    )

                    disappeared_total += max(
                        0,
                        disappeared,
                    )

                    print(
                        f"    voor={live_before} "
                        f"na={live_after}"
                    )

                if self.stop_event.is_set():
                    break

                # Short pause before final fresh rescan.
                self.wait_stop(
                    0.15
                )

        except Exception as e:
            self.ui_set(
                self.status_var,
                f"ERROR: {e}",
            )

            print(
                "SWEEP ERROR:",
                repr(e),
            )

        finally:
            self.z_up_safety()

            if self.stop_event.is_set():
                result = (
                    f"GESTOPT - "
                    f"{visited_locations} locaties bezocht"
                )

            else:
                result = (
                    f"KLAAR - "
                    f"{visited_locations} locaties bezocht, "
                    f"{disappeared_total} drops verdwenen"
                )

            self.ui_set(
                self.status_var,
                result,
            )

            self.ui_set(
                self.progress_var,
                "Progress: klaar",
            )

            print(
                result
            )

    # ========================================================
    # LIVE PLAYER
    # ========================================================

    def player_tick(self):
        if not self.running:
            return

        if self.pm:
            try:
                player = self.get_player()

                if player:
                    (
                        _,
                        x,
                        y,
                        map_id,
                    ) = player

                    self.pos_var.set(
                        (
                            f"Player: "
                            f"X={x} Y={y} "
                            f"Map={map_id}"
                        )
                    )

            except Exception:
                pass

        self.root.after(
            100,
            self.player_tick,
        )

    # ========================================================
    # CONNECTION
    # ========================================================

    def connection_tick(self):
        if not self.running:
            return

        if not self.pm:
            self.connect()

        else:
            try:
                self.pm.read_bytes(
                    self.base,
                    1,
                )

            except Exception:
                self.stop_event.set()

                self.z_up_safety()

                try:
                    self.pm.close_process()
                except Exception:
                    pass

                self.pm = None
                self.base = None

                self.status_var.set(
                    "Verbinding verloren"
                )

        self.root.after(
            1500,
            self.connection_tick,
        )

    # ========================================================
    # HOTKEYS
    # ========================================================

    def hotkey_tick(self):
        if not self.running:
            return

        try:
            f1 = bool(
                user32.GetAsyncKeyState(
                    VK_F1
                )
                & 0x8000
            )

            f2 = bool(
                user32.GetAsyncKeyState(
                    VK_F2
                )
                & 0x8000
            )

            f3 = bool(
                user32.GetAsyncKeyState(
                    VK_F3
                )
                & 0x8000
            )

            f4 = bool(
                user32.GetAsyncKeyState(
                    VK_F4
                )
                & 0x8000
            )

            if (
                f1
                and not self.last_f1
            ):
                self.start_sweep()

            if (
                f2
                and not self.last_f2
            ):
                self.stop_sweep()

            if (
                f3
                and not self.last_f3
            ):
                self.adjust_up()

            if (
                f4
                and not self.last_f4
            ):
                self.adjust_down()

            self.last_f1 = f1
            self.last_f2 = f2
            self.last_f3 = f3
            self.last_f4 = f4

        except Exception:
            pass

        self.root.after(
            30,
            self.hotkey_tick,
        )

    # ========================================================
    # CLOSE
    # ========================================================

    def close(self):
        self.running = False

        self.stop_event.set()

        self.z_up_safety()

        if self.pm:
            try:
                self.pm.close_process()
            except Exception:
                pass

        self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = YunaLootSweep()
    app.run()