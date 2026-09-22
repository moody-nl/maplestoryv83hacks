"""
YunaMS v83 - Blink Godmode
F3 = ON
F4 = OFF / restore

This ports the same v83 Blink-Godmode mechanism used by the supplied Kuro
script, but does NOT blindly assume that Yuna's surrounding bytes are the
same as Kuro.

Historical GMS v83 patch:
    sub edi, 0x1E    83 EF 1E
 -> add edi, 0x1E    83 C7 1E

The historical v83 VA is 0x00932501 at image base 0x00400000.

Safety/validation:
  1. Check the historical RVA first.
  2. Require the expected instruction shape around it.
  3. If it moved, scan the YunaMS main image for that v83 instruction shape.
  4. Only accept a unique candidate.
  5. Before every write, revalidate the full 16-byte context captured at attach.
  6. F4 and normal script exit restore the exact original 3 bytes.

No CRC/integrity bypass, stealth, DLL injection, remote thread, packet hook,
or anti-cheat evasion is used.
"""

from __future__ import annotations

import atexit
import ctypes
import ctypes.wintypes as wt
import struct
import time
from datetime import datetime

import pymem
import pymem.process


TARGET = "YunaMS.exe"

IMAGE_BASE = 0x00400000

# Canonical GMS v83 Blink-Godmode address.
HISTORICAL_PATCH_VA = 0x00932501
HISTORICAL_PATCH_RVA = HISTORICAL_PATCH_VA - IMAGE_BASE

ORIGINAL = bytes.fromhex("83 EF 1E")  # sub edi, 0x1E
PATCHED  = bytes.fromhex("83 C7 1E")  # add edi, 0x1E

# Shared instruction shape seen in public v83 and the supplied working Kuro
# build. Relocation/build-sensitive bytes are wildcarded:
#
#   83 EF/C7 1E
#   57
#   8D 8B xx xx 00 00
#   E8 xx xx xx xx
#   3B
#
CONTEXT_SIZE = 16

PAGE_EXECUTE_READWRITE = 0x40

VK_F3 = 0x72
VK_F4 = 0x73

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)

kernel32.VirtualProtectEx.argtypes = [
    wt.HANDLE,
    wt.LPVOID,
    ctypes.c_size_t,
    wt.DWORD,
    ctypes.POINTER(wt.DWORD),
]
kernel32.VirtualProtectEx.restype = wt.BOOL

kernel32.FlushInstructionCache.argtypes = [
    wt.HANDLE,
    wt.LPCVOID,
    ctypes.c_size_t,
]
kernel32.FlushInstructionCache.restype = wt.BOOL

user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
user32.GetAsyncKeyState.restype = ctypes.c_short


def stamp():
    return datetime.now().strftime("%H:%M:%S")


def log(msg):
    print(f"[{stamp()}] {msg}", flush=True)


def hx(v):
    return f"0x{int(v):08X}"


def beep(freq=900, duration=120):
    try:
        import winsound
        winsound.Beep(freq, duration)
    except Exception:
        pass


def read_u16(pm, addr):
    return struct.unpack("<H", pm.read_bytes(addr, 2))[0]


def read_u32(pm, addr):
    return struct.unpack("<I", pm.read_bytes(addr, 4))[0]


def get_image_size(pm, base):
    if pm.read_bytes(base, 2) != b"MZ":
        raise RuntimeError("YunaMS main module does not start with MZ")

    e_lfanew = read_u32(pm, base + 0x3C)
    nt = base + e_lfanew

    if pm.read_bytes(nt, 4) != b"PE\x00\x00":
        raise RuntimeError("Invalid PE signature")

    optional = nt + 4 + 20
    magic = read_u16(pm, optional)

    if magic not in (0x10B, 0x20B):
        raise RuntimeError(
            f"Unknown PE optional-header magic 0x{magic:04X}"
        )

    return read_u32(pm, optional + 0x38)


def attach():
    pm = pymem.Pymem(TARGET)

    mod = pymem.process.module_from_name(
        pm.process_handle,
        TARGET,
    )

    if mod is None:
        try:
            pm.close_process()
        except Exception:
            pass
        raise RuntimeError(f"Could not resolve {TARGET}")

    base = int(mod.lpBaseOfDll)
    size = int(get_image_size(pm, base))

    return pm, base, size


def context_shape_matches(blob):
    if len(blob) < CONTEXT_SIZE:
        return False

    # OFF or ON first instruction.
    if blob[:3] not in (ORIGINAL, PATCHED):
        return False

    return (
        blob[3] == 0x57
        and blob[4:6] == b"\x8D\x8B"
        and blob[8:10] == b"\x00\x00"
        and blob[10] == 0xE8
        and blob[15] == 0x3B
    )


def find_candidates(image):
    candidates = []

    # Search for the stable bytes at positions 3..5 first.
    needle = b"\x57\x8D\x8B"
    pos = 0

    while True:
        hit = image.find(needle, pos)

        if hit < 0:
            break

        start = hit - 3

        if start >= 0 and start + CONTEXT_SIZE <= len(image):
            blob = image[start:start + CONTEXT_SIZE]

            if context_shape_matches(blob):
                candidates.append(start)

        pos = hit + 1

    return candidates


class BlinkGodmode:
    def __init__(self):
        self.pm = None
        self.base = 0
        self.size = 0
        self.addr = 0

        self.original_context = None
        self.patched_context = None

        self.closed = False

        self._connect_and_locate()

    def _connect_and_locate(self):
        pm, base, size = attach()

        try:
            historical = base + HISTORICAL_PATCH_RVA

            if (
                base <= historical
                and historical + CONTEXT_SIZE <= base + size
            ):
                blob = pm.read_bytes(
                    historical,
                    CONTEXT_SIZE,
                )

                if context_shape_matches(blob):
                    addr = historical
                    method = "historical v83 RVA"
                else:
                    addr = 0
                    method = None
            else:
                addr = 0
                method = None

            if not addr:
                image = pm.read_bytes(base, size)
                hits = find_candidates(image)

                if len(hits) == 0:
                    raise RuntimeError(
                        "Yuna Blink-Godmode signature not found. "
                        "Nothing was written."
                    )

                if len(hits) != 1:
                    addresses = ", ".join(
                        hx(base + off)
                        for off in hits[:12]
                    )

                    raise RuntimeError(
                        "Blink-Godmode signature is not unique "
                        f"({len(hits)} matches): {addresses}. "
                        "Nothing was written."
                    )

                addr = base + hits[0]
                method = "unique v83 signature"

            context = pm.read_bytes(
                addr,
                CONTEXT_SIZE,
            )

            if not context_shape_matches(context):
                raise RuntimeError(
                    f"Candidate validation failed at {hx(addr)}"
                )

            # Keep the exact Yuna-specific context from this run.
            #
            # If the script starts while already ON, we cannot reconstruct the
            # original context from memory alone except for the known first
            # instruction, so rebuild only those first three bytes.
            if context[:3] == ORIGINAL:
                original_context = context
                patched_context = PATCHED + context[3:]

            elif context[:3] == PATCHED:
                patched_context = context
                original_context = ORIGINAL + context[3:]

            else:
                raise RuntimeError("Unexpected candidate state")

            self.pm = pm
            self.base = base
            self.size = size
            self.addr = addr
            self.original_context = original_context
            self.patched_context = patched_context

            log(
                f"Yuna PID={pm.process_id} base={hx(base)} "
                f"Blink site={hx(addr)} ({method})"
            )
            log(
                "Context: "
                + context.hex(" ").upper()
            )

        except Exception:
            try:
                pm.close_process()
            except Exception:
                pass
            raise

    def read_context(self):
        return self.pm.read_bytes(
            self.addr,
            CONTEXT_SIZE,
        )

    def state(self):
        blob = self.read_context()

        if blob == self.original_context:
            return "OFF"

        if blob == self.patched_context:
            return "ON"

        return "UNKNOWN"

    def _protect(self, size, new_prot):
        old = wt.DWORD()

        if not kernel32.VirtualProtectEx(
            self.pm.process_handle,
            ctypes.c_void_p(self.addr),
            size,
            new_prot,
            ctypes.byref(old),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        return old.value

    def _write_verified(self, expected_context, replacement3):
        current = self.read_context()

        if current != expected_context:
            raise RuntimeError(
                f"Refusing write at {hx(self.addr)}: "
                f"current context = {current.hex(' ').upper()}"
            )

        old = self._protect(
            len(replacement3),
            PAGE_EXECUTE_READWRITE,
        )

        try:
            self.pm.write_bytes(
                self.addr,
                replacement3,
                len(replacement3),
            )

            kernel32.FlushInstructionCache(
                self.pm.process_handle,
                ctypes.c_void_p(self.addr),
                len(replacement3),
            )

        finally:
            ignored = wt.DWORD()

            kernel32.VirtualProtectEx(
                self.pm.process_handle,
                ctypes.c_void_p(self.addr),
                len(replacement3),
                old,
                ctypes.byref(ignored),
            )

    def enable(self):
        state = self.state()

        if state == "ON":
            log("F3: Blink Godmode is already ON.")
            return

        if state != "OFF":
            raise RuntimeError(
                "F3 refused: Yuna code context changed/unknown."
            )

        self._write_verified(
            self.original_context,
            PATCHED,
        )

        if self.read_context() != self.patched_context:
            raise RuntimeError(
                "Patched-context verification failed"
            )

        log(
            f"F3: BLINK GODMODE ON "
            f"({hx(self.addr)}: 83 EF 1E -> 83 C7 1E)"
        )
        beep(1100, 140)

    def disable(self, quiet=False):
        state = self.state()

        if state == "OFF":
            if not quiet:
                log("F4: Blink Godmode is already OFF.")
            return

        if state != "ON":
            if not quiet:
                log(
                    "F4 refused: Yuna code context "
                    "changed/unknown."
                )
            return

        self._write_verified(
            self.patched_context,
            ORIGINAL,
        )

        if self.read_context() != self.original_context:
            raise RuntimeError(
                "Restore-context verification failed"
            )

        if not quiet:
            log(
                f"F4: BLINK GODMODE OFF "
                f"({hx(self.addr)} restored to 83 EF 1E)"
            )
            beep(650, 140)

    def close(self):
        if self.closed:
            return

        self.closed = True

        try:
            self.disable(quiet=True)
        except Exception:
            pass

        if self.pm is not None:
            try:
                self.pm.close_process()
            except Exception:
                pass

            self.pm = None


def key_pressed(vk, previous):
    down = bool(
        user32.GetAsyncKeyState(vk)
        & 0x8000
    )

    pressed = down and not previous

    return down, pressed


trainer = None


def cleanup():
    global trainer

    if trainer is not None:
        try:
            trainer.close()
        except Exception:
            pass


def main():
    global trainer

    trainer = BlinkGodmode()
    atexit.register(cleanup)

    print()
    print("YunaMS v83 - Blink Godmode")
    print("---------------------------")
    print("F3 = ON")
    print("F4 = OFF / restore")
    print()
    print(f"Current state: {trainer.state()}")
    print()

    prev_f3 = False
    prev_f4 = False

    while True:
        prev_f3, f3 = key_pressed(
            VK_F3,
            prev_f3,
        )

        prev_f4, f4 = key_pressed(
            VK_F4,
            prev_f4,
        )

        try:
            if f3:
                trainer.enable()

            if f4:
                trainer.disable()

        except Exception as exc:
            log(
                f"ERROR: {type(exc).__name__}: {exc}"
            )

        time.sleep(0.03)


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print()
        log("Ctrl+C: restoring before exit...")
        cleanup()

    except Exception as exc:
        log(
            f"STARTUP ERROR: {type(exc).__name__}: {exc}"
        )
        cleanup()
        raise
