import ctypes
import ctypes.wintypes as wt
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


# ============================================================
# MOUSE
# ============================================================

MOUSE_ROOT_RVA = 0x7EC20C

MOUSE_X_OFF = 0x9C
MOUSE_Y_OFF = 0xA0


# ============================================================
# TELEPORT
# ============================================================

TELEPORT_ROOT_RVA = 0x7EBF98

TP_X1 = 0x2B18
TP_Y1 = 0x2B1C
TP_X2 = 0x2B20
TP_Y2 = 0x2B24


# ============================================================
# MAP BOUNDS
# ============================================================

WALL_ROOT_RVA = 0x7EBFA0

LEFT_WALL_OFF   = 0x24
TOP_WALL_OFF    = 0x28
RIGHT_WALL_OFF  = 0x2C
BOTTOM_WALL_OFF = 0x30


# Keep a little distance from map borders.
LEFT_MARGIN = 15
RIGHT_MARGIN = 15
BOTTOM_MARGIN = 20


# ============================================================
# INPUT
# ============================================================

VK_F9 = 0x78
VK_MBUTTON = 0x04

DOUBLE_CLICK_SECONDS = 0.35


# ============================================================
# WINDOWS
# ============================================================

user32 = ctypes.windll.user32


# ============================================================
# MEMORY HELPERS
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


def sane_coord(value):
    return (
        value is not None
        and -100000 <= value <= 100000
    )


# ============================================================
# APP
# ============================================================

class YunaMouseTeleport:

    def __init__(self):
        self.root = tk.Tk()

        self.root.title(
            "Yuna Mouse Teleport"
        )

        self.root.geometry(
            "550x385"
        )

        self.root.resizable(
            False,
            False
        )

        self.pm = None
        self.base = None

        self.running = True

        # F9 calibration
        self.player_screen_x = None
        self.player_screen_y = None

        # Input states
        self.last_f9 = False
        self.last_middle = False

        self.last_middle_click_time = 0.0

        # GUI
        self.status_var = tk.StringVar(
            value="YunaMS zoeken..."
        )

        self.player_var = tk.StringVar(
            value="Player world: --"
        )

        self.mouse_var = tk.StringVar(
            value="Mouse screen: --"
        )

        self.bounds_var = tk.StringVar(
            value="Map bounds: --"
        )

        self.safe_var = tk.StringVar(
            value="Safe area: --"
        )

        self.calibration_var = tk.StringVar(
            value="Calibration: NIET ingesteld"
        )

        self.mode_var = tk.StringVar(
            value="Double middle-click teleport: ALWAYS ON"
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
            50,
            self.position_tick,
        )

        self.root.after(
            20,
            self.hotkey_tick,
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
            text="YUNA MOUSE TELEPORT",
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
                "F9 = CALIBRATE   |   "
                "DOUBLE MIDDLE CLICK = TELEPORT"
            ),
            bg=bg,
            fg=muted,
            font=(
                "Consolas",
                9,
                "bold",
            ),
        ).pack()

        panel_frame = tk.Frame(
            self.root,
            bg=panel,
        )

        panel_frame.pack(
            fill="x",
            padx=20,
            pady=16,
        )

        for variable in (
            self.status_var,
            self.mode_var,
            self.player_var,
            self.mouse_var,
            self.bounds_var,
            self.safe_var,
            self.calibration_var,
        ):
            tk.Label(
                panel_frame,
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

        tk.Button(
            self.root,
            text="CALIBRATE PLAYER [F9]",
            command=self.calibrate,
            width=30,
            pady=8,
            bg="#854d0e",
            fg="white",
            relief="flat",
            font=(
                "Segoe UI",
                10,
                "bold",
            ),
        ).pack(
            pady=4
        )

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
                f"Connected PID {pm.process_id}"
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
    # FOREGROUND
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

    # ========================================================
    # PLAYER
    # ========================================================

    def get_player_position(self):
        if not self.pm:
            return None

        player = read_u32(
            self.pm,
            self.base + CHAR_ROOT_RVA,
        )

        if not player:
            return None

        x = read_i32(
            self.pm,
            player + CHAR_X_OFF,
        )

        y = read_i32(
            self.pm,
            player + CHAR_Y_OFF,
        )

        if not (
            sane_coord(x)
            and sane_coord(y)
        ):
            return None

        return x, y

    # ========================================================
    # MOUSE
    # ========================================================

    def get_mouse_position(self):
        if not self.pm:
            return None

        mouse = read_u32(
            self.pm,
            self.base + MOUSE_ROOT_RVA,
        )

        if not mouse:
            return None

        x = read_i32(
            self.pm,
            mouse + MOUSE_X_OFF,
        )

        y = read_i32(
            self.pm,
            mouse + MOUSE_Y_OFF,
        )

        if not (
            sane_coord(x)
            and sane_coord(y)
        ):
            return None

        return x, y

    # ========================================================
    # MAP BOUNDS
    # ========================================================

    def get_map_bounds(self):
        if not self.pm:
            return None

        wall = read_u32(
            self.pm,
            self.base + WALL_ROOT_RVA,
        )

        if not wall:
            return None

        left = read_i32(
            self.pm,
            wall + LEFT_WALL_OFF,
        )

        top = read_i32(
            self.pm,
            wall + TOP_WALL_OFF,
        )

        right = read_i32(
            self.pm,
            wall + RIGHT_WALL_OFF,
        )

        bottom = read_i32(
            self.pm,
            wall + BOTTOM_WALL_OFF,
        )

        if not all(
            sane_coord(v)
            for v in (
                left,
                top,
                right,
                bottom,
            )
        ):
            return None

        # Reject obviously broken data.
        if right <= left:
            return None

        if bottom <= top:
            return None

        return (
            left,
            top,
            right,
            bottom,
        )

    # ========================================================
    # HARD MAP CLAMP
    # ========================================================

    def clamp_to_map(
        self,
        x,
        y,
    ):
        bounds = self.get_map_bounds()

        if not bounds:
            return (
                x,
                y,
                False,
            )

        (
            left,
            top,
            right,
            bottom,
        ) = bounds

        min_x = (
            left
            + LEFT_MARGIN
        )

        max_x = (
            right
            - RIGHT_MARGIN
        )

        max_y = (
            bottom
            - BOTTOM_MARGIN
        )

        old_x = x
        old_y = y

        # -----------------------------------------------
        # LEFT
        # -----------------------------------------------

        if x < min_x:
            x = min_x

        # -----------------------------------------------
        # RIGHT
        # -----------------------------------------------

        if x > max_x:
            x = max_x

        # -----------------------------------------------
        # BOTTOM
        #
        # This is the OLD behaviour again:
        #
        # DO NOT cancel.
        # FORCE Y back above the bottom.
        # -----------------------------------------------

        if y > max_y:
            y = max_y

        changed = (
            x != old_x
            or
            y != old_y
        )

        return (
            int(x),
            int(y),
            changed,
        )

    # ========================================================
    # CALIBRATION
    # ========================================================

    def calibrate(self):
        if not self.pm:
            if not self.connect():
                return

        mouse = self.get_mouse_position()

        if not mouse:
            self.status_var.set(
                "Mousepositie niet gevonden"
            )

            return

        (
            self.player_screen_x,
            self.player_screen_y,
        ) = mouse

        self.calibration_var.set(
            (
                "Calibration: "
                f"screen X={self.player_screen_x} "
                f"Y={self.player_screen_y}"
            )
        )

        self.status_var.set(
            "CALIBRATED - teleport altijd actief"
        )

    # ========================================================
    # CURRENT MOUSE -> WORLD
    # ========================================================

    def calculate_mouse_world_target(self):
        if (
            self.player_screen_x is None
            or
            self.player_screen_y is None
        ):
            return None

        player = self.get_player_position()
        mouse = self.get_mouse_position()

        if not player or not mouse:
            return None

        player_x, player_y = player
        mouse_x, mouse_y = mouse

        delta_x = (
            mouse_x
            - self.player_screen_x
        )

        delta_y = (
            mouse_y
            - self.player_screen_y
        )

        target_x = (
            player_x
            + delta_x
        )

        target_y = (
            player_y
            + delta_y
        )

        return (
            int(target_x),
            int(target_y),
        )

    # ========================================================
    # WRITE TELEPORT
    # ========================================================

    def write_teleport(
        self,
        x,
        y,
    ):
        tp = read_u32(
            self.pm,
            self.base + TELEPORT_ROOT_RVA,
        )

        if not tp:
            return False

        try:
            self.pm.write_int(
                tp + TP_X1,
                int(x),
            )

            self.pm.write_int(
                tp + TP_Y1,
                int(y),
            )

            self.pm.write_int(
                tp + TP_X2,
                int(x),
            )

            self.pm.write_int(
                tp + TP_Y2,
                int(y),
            )

            return True

        except Exception:
            return False

    # ========================================================
    # DOUBLE MIDDLE CLICK TELEPORT
    # ========================================================

    def teleport_to_mouse(self):
        if not self.yuna_is_foreground():
            return

        if (
            self.player_screen_x is None
            or
            self.player_screen_y is None
        ):
            self.status_var.set(
                "Eerst F9 calibreren"
            )

            return

        target = (
            self.calculate_mouse_world_target()
        )

        if not target:
            self.status_var.set(
                "Target niet beschikbaar"
            )

            return

        raw_x, raw_y = target

        (
            x,
            y,
            clamped,
        ) = self.clamp_to_map(
            raw_x,
            raw_y,
        )

        if not self.write_teleport(
            x,
            y,
        ):
            self.status_var.set(
                "Teleport write mislukt"
            )

            return

        if clamped:
            self.status_var.set(
                (
                    f"CLAMPED "
                    f"({raw_x},{raw_y}) "
                    f"-> ({x},{y})"
                )
            )

        else:
            self.status_var.set(
                (
                    f"TELEPORT -> "
                    f"({x},{y})"
                )
            )

    # ========================================================
    # HOTKEYS
    # ========================================================

    def hotkey_tick(self):
        if not self.running:
            return

        try:
            # -----------------------------------------------
            # F9
            # -----------------------------------------------

            f9 = bool(
                user32.GetAsyncKeyState(
                    VK_F9
                )
                & 0x8000
            )

            if (
                f9
                and not self.last_f9
            ):
                self.calibrate()

            self.last_f9 = f9

            # -----------------------------------------------
            # MIDDLE MOUSE
            # -----------------------------------------------

            middle = bool(
                user32.GetAsyncKeyState(
                    VK_MBUTTON
                )
                & 0x8000
            )

            if (
                middle
                and not self.last_middle
            ):
                now = (
                    time.perf_counter()
                )

                dt = (
                    now
                    - self.last_middle_click_time
                )

                if (
                    0
                    < dt
                    <= DOUBLE_CLICK_SECONDS
                ):
                    # Reset immediately so triple-click cannot
                    # accidentally count as another pair.
                    self.last_middle_click_time = 0.0

                    self.teleport_to_mouse()

                else:
                    self.last_middle_click_time = now

            self.last_middle = middle

        except Exception:
            pass

        self.root.after(
            20,
            self.hotkey_tick,
        )

    # ========================================================
    # LIVE DISPLAY
    # ========================================================

    def position_tick(self):
        if not self.running:
            return

        if self.pm:
            try:
                player = self.get_player_position()

                if player:
                    px, py = player

                    self.player_var.set(
                        (
                            "Player world: "
                            f"X={px} Y={py}"
                        )
                    )

                mouse = self.get_mouse_position()

                if mouse:
                    mx, my = mouse

                    self.mouse_var.set(
                        (
                            "Mouse screen: "
                            f"X={mx} Y={my}"
                        )
                    )

                bounds = self.get_map_bounds()

                if bounds:
                    (
                        left,
                        top,
                        right,
                        bottom,
                    ) = bounds

                    self.bounds_var.set(
                        (
                            f"Bounds: "
                            f"L={left} "
                            f"R={right} "
                            f"B={bottom}"
                        )
                    )

                    self.safe_var.set(
                        (
                            f"Safe: "
                            f"X={left + LEFT_MARGIN}"
                            f"..{right - RIGHT_MARGIN}   "
                            f"max Y={bottom - BOTTOM_MARGIN}"
                        )
                    )

                else:
                    self.bounds_var.set(
                        "Map bounds: --"
                    )

                    self.safe_var.set(
                        "Safe area: --"
                    )

            except Exception:
                pass

        self.root.after(
            50,
            self.position_tick,
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
    # CLOSE
    # ========================================================

    def close(self):
        self.running = False

        if self.pm:
            try:
                self.pm.close_process()
            except Exception:
                pass

        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    app = YunaMouseTeleport()
    app.run()