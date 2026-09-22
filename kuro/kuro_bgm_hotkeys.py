import atexit
import ctypes
import ctypes.wintypes as wt
import time
from datetime import datetime

import pymem
import pymem.process


TARGET = "Kuro.exe"

# Verified Kuro build / historical v83 Blink-Godmode site.
IMAGE_BASE = 0x00400000
PATCH_VA = 0x00932501
PATCH_RVA = PATCH_VA - IMAGE_BASE

ORIGINAL = bytes.fromhex("83 EF 1E")  # sub edi, 0x1E
PATCHED  = bytes.fromhex("83 C7 1E")  # add edi, 0x1E

# Full verified Kuro-specific context.
EXPECTED_ORIGINAL_CONTEXT = bytes.fromhex(
    "83 EF 1E 57 8D 8B B8 1E 00 00 E8 E2 62 AF FF 3B"
)
EXPECTED_PATCHED_CONTEXT = PATCHED + EXPECTED_ORIGINAL_CONTEXT[3:]

PAGE_EXECUTE_READWRITE = 0x40

VK_F1 = 0x70
VK_F2 = 0x71
VK_F3 = 0x72
VK_F12 = 0x7B

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)

kernel32.VirtualProtectEx.argtypes = [
    wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD, ctypes.POINTER(wt.DWORD)
]
kernel32.VirtualProtectEx.restype = wt.BOOL

kernel32.FlushInstructionCache.argtypes = [
    wt.HANDLE, wt.LPCVOID, ctypes.c_size_t
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


def attach():
    pm = pymem.Pymem(TARGET)
    mod = pymem.process.module_from_name(pm.process_handle, TARGET)
    if mod is None:
        raise RuntimeError(f"Could not resolve {TARGET}")
    base = int(mod.lpBaseOfDll)
    addr = base + PATCH_RVA
    return pm, base, addr


def read_context(pm, addr):
    return pm.read_bytes(addr, len(EXPECTED_ORIGINAL_CONTEXT))


def classify(blob):
    if blob == EXPECTED_ORIGINAL_CONTEXT:
        return "OFF"
    if blob == EXPECTED_PATCHED_CONTEXT:
        return "ON"
    return "UNKNOWN"


def protect(pm, addr, size, new_prot):
    old = wt.DWORD()
    if not kernel32.VirtualProtectEx(
        pm.process_handle,
        ctypes.c_void_p(addr),
        size,
        new_prot,
        ctypes.byref(old),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return old.value


def write_verified(pm, addr, expected, replacement):
    current = pm.read_bytes(addr, len(expected))
    if current != expected:
        raise RuntimeError(
            f"Refusing write at {hx(addr)}: found {current.hex(' ')}, "
            f"expected {expected.hex(' ')}"
        )

    old_prot = protect(pm, addr, len(replacement), PAGE_EXECUTE_READWRITE)
    try:
        pm.write_bytes(addr, replacement, len(replacement))
        kernel32.FlushInstructionCache(
            pm.process_handle,
            ctypes.c_void_p(addr),
            len(replacement),
        )
    finally:
        protect(pm, addr, len(replacement), old_prot)

    verify = pm.read_bytes(addr, len(replacement))
    if verify != replacement:
        raise RuntimeError(
            f"Write verify failed at {hx(addr)}: "
            f"{verify.hex(' ')} != {replacement.hex(' ')}"
        )


def status():
    try:
        pm, base, addr = attach()
    except Exception as e:
        log(f"Kuro not available: {e}")
        return None

    blob = read_context(pm, addr)
    state = classify(blob)
    log(
        f"PID={pm.process_id} base={hx(base)} site={hx(addr)} "
        f"GODMODE={state}"
    )

    if state == "UNKNOWN":
        log(f"UNKNOWN BYTES: {blob.hex(' ')}")
        log("No write will be attempted on an unknown build/state.")
    return state


def enable():
    try:
        pm, base, addr = attach()
        blob = read_context(pm, addr)
        state = classify(blob)

        if state == "ON":
            log("F1: Godmode is already ON.")
            return True
        if state != "OFF":
            log(f"F1 REFUSED: unknown bytes: {blob.hex(' ')}")
            return False

        # Revalidate the complete context immediately before the write.
        if read_context(pm, addr) != EXPECTED_ORIGINAL_CONTEXT:
            log("F1 REFUSED: code changed during validation.")
            return False

        write_verified(pm, addr, ORIGINAL, PATCHED)

        if read_context(pm, addr) != EXPECTED_PATCHED_CONTEXT:
            raise RuntimeError("Full patched context verification failed")

        log(f"F1: GODMODE ON  ({hx(addr)}: 83 EF 1E -> 83 C7 1E)")
        beep(1100, 140)
        return True

    except Exception as e:
        log(f"F1 ERROR: {type(e).__name__}: {e}")
        return False


def disable(quiet=False):
    try:
        pm, base, addr = attach()
        blob = read_context(pm, addr)
        state = classify(blob)

        if state == "OFF":
            if not quiet:
                log("F2: Godmode code is already OFF.")
            return True

        if state != "ON":
            if not quiet:
                log(f"F2 REFUSED: unknown bytes: {blob.hex(' ')}")
            return False

        write_verified(pm, addr, PATCHED, ORIGINAL)

        if read_context(pm, addr) != EXPECTED_ORIGINAL_CONTEXT:
            raise RuntimeError("Full restore-context verification failed")

        if not quiet:
            log(f"F2: GODMODE OFF ({hx(addr)} restored to 83 EF 1E)")
            log(
                "Note: if blinking/invulnerability remains briefly, the patched "
                "code may already have updated a timer/state value. F2 restores "
                "the code immediately but does not guess/reset that state."
            )
            beep(650, 140)
        return True

    except Exception as e:
        if not quiet:
            log(f"F2 ERROR: {type(e).__name__}: {e}")
        return False


def key_pressed(vk, previous):
    down = bool(user32.GetAsyncKeyState(vk) & 0x8000)
    pressed = down and not previous
    return down, pressed


def cleanup():
    # Best-effort safety restore. If Kuro has exited, the process patch is gone
    # with it anyway.
    try:
        disable(quiet=True)
    except Exception:
        pass


def main():
    atexit.register(cleanup)

    print()
    print("Kuro Blink-Godmode Hotkeys")
    print("---------------------------")
    print("F1  = Godmode ON")
    print("F2  = Godmode OFF / restore original code")
    print("F3  = Show current status")
    print("F12 = Restore + exit")
    print()
    print("No VAC, packet hook, DLL injection, remote thread or security patch is used.")
    print("The script validates the exact Kuro code context before every write.")
    print()

    status()

    prev = {
        VK_F1: False,
        VK_F2: False,
        VK_F3: False,
        VK_F12: False,
    }

    while True:
        for vk in tuple(prev):
            now, pressed = key_pressed(vk, prev[vk])
            prev[vk] = now

            if not pressed:
                continue

            if vk == VK_F1:
                enable()
            elif vk == VK_F2:
                disable()
            elif vk == VK_F3:
                status()
            elif vk == VK_F12:
                log("F12: restoring before exit...")
                disable(quiet=True)
                log("Exiting.")
                return

        time.sleep(0.03)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("Ctrl+C: restoring before exit...")
        cleanup()
