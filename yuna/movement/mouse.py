import ctypes
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
# MOUSE / CLIENT COORDINATES
# ============================================================

MOUSE_ROOT_RVA = 0x7EC20C

MOUSE_X_OFF = 0x9C
MOUSE_Y_OFF = 0xA0


# ============================================================
# WORKING TELEPORT STRUCTURE
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

BOTTOM_WALL_OFF = 0x30


# Keep player slightly above the absolute bottom boundary.
#
# Increase this if you still get too close to the bottom.
#
SAFE_BOTTOM_MARGIN = 20


# ============================================================
# WINDOWS
# ============================================================

user32 = ctypes.windll.user32


VK_F7 = 0x76
VK_F8 = 0x77
VK_F9 = 0x78


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
            "500x425"
        )

        self.root.resizable(
            False,
            False
        )

        # ----------------------------------------------------
        # PROCESS
        # ----------------------------------------------------

        self.pm = None
        self.base = None

        self.running = True

        # ----------------------------------------------------
        # SAVED TELEPORT TARGET
        # ----------------------------------------------------

        self.saved_x = None
        self.saved_y = None

        # ----------------------------------------------------
        # CALIBRATED PLAYER SCREEN POSITION
        #
        # F9 with mouse placed on character.
        # ----------------------------------------------------

        self.player_screen_x = None
        self.player_screen_y = None

        # ----------------------------------------------------
        # HOTKEY STATE
        # ----------------------------------------------------

        self.last_f7 = False
        self.last_f8 = False
        self.last_f9 = False

        # ----------------------------------------------------
        # GUI VARIABLES
        # ----------------------------------------------------

        self.status_var = tk.StringVar(
            value="YunaMS zoeken..."
        )

        self.player_var = tk.StringVar(
            value="Player world: --"
        )

        self.mouse_var = tk.StringVar(
            value="Mouse screen: --"
        )

        self.bottom_var = tk.StringVar(
            value="Bottom wall: --"
        )

        self.calibration_var = tk.StringVar(
            value="Calibration: druk F9 met muis op je character"
        )

        self.saved_var = tk.StringVar(
            value="Saved target: --"
        )

        self.build_ui()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close,
        )

        # ----------------------------------------------------
        # LOOPS
        # ----------------------------------------------------

        self.root.after(
            100,
            self.connection_tick,
        )

        self.root.after(
            60,
            self.position_tick,
        )

        self.root.after(
            40,
            self.hotkey_tick,
        )

    # ========================================================
    # UI
    # ========================================================

    def build_ui(self):
        bg = "#0e131d"
        panel = "#171e2b"

        text = "#ffffff"
        muted = "#9aa7b8"
        cyan = "#67e8f9"
        yellow = "#facc15"
        green = "#86efac"

        self.root.configure(
            bg=bg
        )

        tk.Label(
            self.root,
            text="YUNA MOUSE TELEPORT",
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
                "F9 CALIBRATE   "
                "F8 SAVE TARGET   "
                "F7 TELEPORT"
            ),
            bg=bg,
            fg=muted,
            font=(
                "Consolas",
                9,
                "bold",
            ),
        ).pack()

        # ----------------------------------------------------

        info = tk.Frame(
            self.root,
            bg=panel,
        )

        info.pack(
            fill="x",
            padx=20,
            pady=(16, 12),
        )

        tk.Label(
            info,
            textvariable=self.status_var,
            bg=panel,
            fg=text,
            font=(
                "Segoe UI",
                10,
                "bold",
            ),
        ).pack(
            pady=(12, 5)
        )

        tk.Label(
            info,
            textvariable=self.player_var,
            bg=panel,
            fg=muted,
            font=(
                "Consolas",
                10,
            ),
        ).pack(
            pady=2
        )

        tk.Label(
            info,
            textvariable=self.mouse_var,
            bg=panel,
            fg=cyan,
            font=(
                "Consolas",
                10,
                "bold",
            ),
        ).pack(
            pady=2
        )

        tk.Label(
            info,
            textvariable=self.bottom_var,
            bg=panel,
            fg=green,
            font=(
                "Consolas",
                10,
                "bold",
            ),
        ).pack(
            pady=2
        )

        tk.Label(
            info,
            textvariable=self.calibration_var,
            bg=panel,
            fg=yellow,
            font=(
                "Consolas",
                10,
            ),
        ).pack(
            pady=2
        )

        tk.Label(
            info,
            textvariable=self.saved_var,
            bg=panel,
            fg=text,
            font=(
                "Consolas",
                10,
                "bold",
            ),
        ).pack(
            pady=(2, 12)
        )

        # ----------------------------------------------------

        tk.Button(
            self.root,
            text="CALIBRATE PLAYER SCREEN POS  [F9]",
            command=self.calibrate,
            bg="#854d0e",
            fg="white",
            relief="flat",
            font=(
                "Segoe UI",
                10,
                "bold",
            ),
            width=35,
            pady=7,
        ).pack(
            pady=(4, 6)
        )

        tk.Button(
            self.root,
            text="SAVE MOUSE TARGET  [F8]",
            command=self.save_mouse_target,
            bg="#334155",
            fg="white",
            relief="flat",
            font=(
                "Segoe UI",
                10,
                "bold",
            ),
            width=35,
            pady=7,
        ).pack(
            pady=6
        )

        tk.Button(
            self.root,
            text="TELEPORT TO SAVED  [F7]",
            command=self.teleport_saved,
            bg="#166534",
            fg="white",
            relief="flat",
            font=(
                "Segoe UI",
                10,
                "bold",
            ),
            width=35,
            pady=7,
        ).pack(
            pady=6
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

            module = pymem.process.module_from_name(
                pm.process_handle,
                PROCESS,
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

            self.status_var.set(
                f"Connected PID {self.pm.process_id}"
            )

            return True

        except Exception:
            self.pm = None
            self.base = None

            self.status_var.set(
                "YunaMS niet gevonden / geen toegang"
            )

            return False

    # ========================================================
    # PLAYER WORLD POSITION
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
    # RAW MOUSE SCREEN POSITION
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
    # BOTTOM WALL
    # ========================================================

    def get_bottom_wall(self):
        if not self.pm:
            return None

        wall = read_u32(
            self.pm,
            self.base + WALL_ROOT_RVA,
        )

        if not wall:
            return None

        bottom = read_i32(
            self.pm,
            wall + BOTTOM_WALL_OFF,
        )

        if not sane_coord(bottom):
            return None

        return bottom

    # ========================================================
    # BOTTOM SAFETY
    # ========================================================

    def clamp_bottom(self, y):
        bottom = self.get_bottom_wall()

        if bottom is None:
            return y, False

        max_safe_y = (
            bottom
            - SAFE_BOTTOM_MARGIN
        )

        if y > max_safe_y:
            return (
                max_safe_y,
                True,
            )

        return (
            y,
            False,
        )

    # ========================================================
    # F9
    #
    # Put mouse directly on your character.
    # ========================================================

    def calibrate(self):
        if not self.pm:
            if not self.connect():
                return

        mouse = self.get_mouse_position()

        if not mouse:
            self.status_var.set(
                "Mousepositie niet beschikbaar"
            )

            return

        (
            self.player_screen_x,
            self.player_screen_y,
        ) = mouse

        self.calibration_var.set(
            (
                "Calibration: "
                f"X={self.player_screen_x} "
                f"Y={self.player_screen_y}"
            )
        )

        self.status_var.set(
            "Calibratie opgeslagen"
        )

    # ========================================================
    # F8
    #
    # Convert mouse/client position to world position.
    # Then immediately apply bottom-wall protection.
    # ========================================================

    def save_mouse_target(self):
        if (
            self.player_screen_x is None
            or
            self.player_screen_y is None
        ):
            self.status_var.set(
                "Eerst F9 calibreren met muis op je character"
            )

            return

        player = self.get_player_position()
        mouse = self.get_mouse_position()

        if not player or not mouse:
            self.status_var.set(
                "Positie niet beschikbaar"
            )

            return

        player_x, player_y = player
        mouse_x, mouse_y = mouse

        # ----------------------------------------------------
        # Difference between cursor and calibrated character
        # position on the client.
        # ----------------------------------------------------

        delta_x = (
            mouse_x
            - self.player_screen_x
        )

        delta_y = (
            mouse_y
            - self.player_screen_y
        )

        # ----------------------------------------------------
        # Screen delta -> world position
        # ----------------------------------------------------

        target_x = (
            player_x
            + delta_x
        )

        target_y = (
            player_y
            + delta_y
        )

        # ----------------------------------------------------
        # NEVER save target beneath bottom wall.
        # ----------------------------------------------------

        target_y, clamped = self.clamp_bottom(
            target_y
        )

        self.saved_x = int(
            target_x
        )

        self.saved_y = int(
            target_y
        )

        self.saved_var.set(
            (
                "Saved target: "
                f"X={self.saved_x} "
                f"Y={self.saved_y}"
            )
        )

        if clamped:
            bottom = self.get_bottom_wall()

            self.status_var.set(
                (
                    "F8 saved - BOTTOM CLAMP "
                    f"(bottom={bottom}, "
                    f"safe Y={self.saved_y})"
                )
            )

        else:
            self.status_var.set(
                (
                    "F8 target saved "
                    f"(delta {delta_x:+d}, "
                    f"{delta_y:+d})"
                )
            )

    # ========================================================
    # TELEPORT OBJECT
    # ========================================================

    def get_teleport_object(self):
        if not self.pm:
            return None

        return read_u32(
            self.pm,
            self.base + TELEPORT_ROOT_RVA,
        )

    # ========================================================
    # F7
    #
    # Clamp AGAIN before writing.
    #
    # This means even if bottom wall changed since F8,
    # F7 still won't write below it.
    # ========================================================

    def teleport_saved(self):
        if (
            self.saved_x is None
            or
            self.saved_y is None
        ):
            self.status_var.set(
                "Eerst F8 om doelpositie op te slaan"
            )

            return

        if not self.pm:
            if not self.connect():
                return

        tp = self.get_teleport_object()

        if not tp:
            self.status_var.set(
                "Teleport object niet beschikbaar"
            )

            return

        x = int(
            self.saved_x
        )

        y = int(
            self.saved_y
        )

        # ----------------------------------------------------
        # FINAL bottom safety check
        # ----------------------------------------------------

        y, clamped = self.clamp_bottom(
            y
        )

        # Keep saved position equal to the safe position.
        self.saved_y = y

        self.saved_var.set(
            (
                "Saved target: "
                f"X={self.saved_x} "
                f"Y={self.saved_y}"
            )
        )

        try:
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

            if clamped:
                bottom = self.get_bottom_wall()

                self.status_var.set(
                    (
                        "F7 teleport - BOTTOM CLAMP "
                        f"-> ({x}, {y}) "
                        f"bottom={bottom}"
                    )
                )

            else:
                self.status_var.set(
                    (
                        "F7 teleport -> "
                        f"({x}, {y})"
                    )
                )

        except Exception as e:
            self.status_var.set(
                f"Teleport fout: {e}"
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

                else:
                    self.player_var.set(
                        "Player world: --"
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

                else:
                    self.mouse_var.set(
                        "Mouse screen: --"
                    )

                bottom = self.get_bottom_wall()

                if bottom is not None:
                    safe_bottom = (
                        bottom
                        - SAFE_BOTTOM_MARGIN
                    )

                    self.bottom_var.set(
                        (
                            f"Bottom wall: {bottom}   "
                            f"Max teleport Y: {safe_bottom}"
                        )
                    )

                else:
                    self.bottom_var.set(
                        "Bottom wall: --"
                    )

            except Exception:
                pass

        self.root.after(
            60,
            self.position_tick,
        )

    # ========================================================
    # CONNECTION CHECK
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
                    "Verbinding verloren..."
                )

        self.root.after(
            1500,
            self.connection_tick,
        )

    # ========================================================
    # GLOBAL F7 / F8 / F9
    # ========================================================

    def hotkey_tick(self):
        if not self.running:
            return

        try:
            f7 = bool(
                user32.GetAsyncKeyState(
                    VK_F7
                )
                & 0x8000
            )

            f8 = bool(
                user32.GetAsyncKeyState(
                    VK_F8
                )
                & 0x8000
            )

            f9 = bool(
                user32.GetAsyncKeyState(
                    VK_F9
                )
                & 0x8000
            )

            # F9 = calibrate character screen position
            if (
                f9
                and
                not self.last_f9
            ):
                self.calibrate()

            # F8 = save mouse target
            if (
                f8
                and
                not self.last_f8
            ):
                self.save_mouse_target()

            # F7 = teleport
            if (
                f7
                and
                not self.last_f7
            ):
                self.teleport_saved()

            self.last_f7 = f7
            self.last_f8 = f8
            self.last_f9 = f9

        except Exception:
            pass

        self.root.after(
            40,
            self.hotkey_tick,
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

    # ========================================================

    def run(self):
        self.root.mainloop()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    app = YunaMouseTeleport()
    app.run()