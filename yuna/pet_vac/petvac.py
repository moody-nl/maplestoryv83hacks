"""
YunaMS v83 - Pet Item Vac (F1 ON / F2 OFF)
===========================================

Target:
    YunaMS.exe

Hotkeys:
    F1  = Pet Item Vac ON
    F2  = Pet Item Vac OFF
    ESC = stop script and restore both hook entries

What this implementation uses
-----------------------------
Confirmed Yuna / v83 addresses and layouts from the previous probes:

    CDropPool**                = image + 0x7ED6AC
    CDropPool count            = +0x14
    CDropPool iterator root    = +0x2C

    iterator:
        view       = [current + 0x04]
        active     = [view + 0x48] == 3
        OID        = [view + 0x20]
        nextOwner  = [(current - 0x10) + 0x04]
        next       = nextOwner + 0x10

    CPet/update entry          = image + 0x305C5D  (0x00705C5D)
    periodic callback          = image + 0x5CB992  (0x009CB992)
    secure coordinate getter   = image + 0x02873D  (0x0042873D)
    pet-aware pickup function  = image + 0x10483A  (0x0050483A)

The periodic callback is the same game-thread context used by the
MapleRoyals pet-vac state machine.  The script feeds one iterator entry at a
time into a very small in-process call gate.  The gate obtains the exact drop
coordinates through the game's normal secure-coordinate getter and then calls
the game's existing pet-aware pickup function.

IMPORTANT
---------
This is NOT a read-only probe. It installs two ordinary 5-byte detours and
allocates a small executable page in YunaMS. Existing E9 hooks are preserved:
our cave jumps to the target that was present before this script started.

There is intentionally NO integrity-monitor bypass, stealth, manual mapping,
anti-cheat evasion, packet forging or packet replay. If your own integrity
monitor treats .text changes as violations, these two detours can be reported.

The script restores the exact bytes it observed at startup when ESC/Ctrl+C is
used, provided nobody else replaced our detour after installation.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import time
from dataclasses import dataclass


# ============================================================================
# CONFIG
# ============================================================================

PROCESS_NAME = "YunaMS.exe"
EXPECTED_IMAGE_BASE = 0x00400000

# RVAs so the script still rebases correctly.
DROP_POOL_GLOBAL_RVA = 0x7ED6AC
PET_UPDATE_RVA = 0x305C5D
GAME_TICK_RVA = 0x5CB992
SECURE_COORD_GET_RVA = 0x02873D
PET_PICKUP_RVA = 0x10483A

POOL_COUNT_OFF = 0x14
POOL_ROOT_OFF = 0x2C

ITER_VIEW_OFF = 0x04
ITER_OWNER_BACK = 0x10
ITER_NEXT_OWNER_OFF = 0x04

VIEW_OID_OFF = 0x20
VIEW_STATE_OFF = 0x48
VIEW_X_SECURE_OFF = 0x74   # copied exactly from MapleRoyals pet-vac path
VIEW_Y_SECURE_OFF = 0x68
ACTIVE_DROP_STATE = 3

MAX_ITER_EXTRA = 128
RETRY_SAME_OID_AFTER = 0.80
LOOP_SLEEP = 0.010
STATUS_EVERY = 1.0

VK_F1 = 0x70
VK_F2 = 0x71
VK_ESCAPE = 0x1B


# ============================================================================
# REMOTE BLOCK LAYOUT
# ============================================================================

REMOTE_SIZE = 0x1000

PET_CAVE_OFF = 0x000
TICK_CAVE_OFF = 0x100

PET_TRAMP_OFF = 0x300
TICK_TRAMP_OFF = 0x380

DATA_OFF = 0x500

ENABLED_OFF = DATA_OFF + 0x00
PET_PTR_OFF = DATA_OFF + 0x04
PENDING_OFF = DATA_OFF + 0x08
VIEW_PTR_OFF = DATA_OFF + 0x0C
OID_OFF = DATA_OFF + 0x10
BUSY_OFF = DATA_OFF + 0x14
POINT_X_OFF = DATA_OFF + 0x18
POINT_Y_OFF = DATA_OFF + 0x1C
CALL_COUNT_OFF = DATA_OFF + 0x20


# ============================================================================
# WIN32
# ============================================================================

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020

ACCESS = (
    PROCESS_QUERY_INFORMATION
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE
)

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000

PAGE_EXECUTE_READWRITE = 0x40

MAX_PATH = 260
MAX_MODULE_NAME32 = 255

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)


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
        ("szExeFile", wt.WCHAR * MAX_PATH),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wt.DWORD),
        ("hModule", ctypes.c_void_p),
        ("szModule", wt.WCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", wt.WCHAR * MAX_PATH),
    ]


kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE

kernel32.Process32FirstW.argtypes = [
    wt.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
]
kernel32.Process32FirstW.restype = wt.BOOL

kernel32.Process32NextW.argtypes = [
    wt.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
]
kernel32.Process32NextW.restype = wt.BOOL

kernel32.Module32FirstW.argtypes = [
    wt.HANDLE,
    ctypes.POINTER(MODULEENTRY32W),
]
kernel32.Module32FirstW.restype = wt.BOOL

kernel32.Module32NextW.argtypes = [
    wt.HANDLE,
    ctypes.POINTER(MODULEENTRY32W),
]
kernel32.Module32NextW.restype = wt.BOOL

kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = wt.HANDLE

kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE,
    wt.LPCVOID,
    wt.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wt.BOOL

kernel32.WriteProcessMemory.argtypes = [
    wt.HANDLE,
    wt.LPVOID,
    wt.LPCVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.WriteProcessMemory.restype = wt.BOOL

kernel32.VirtualAllocEx.argtypes = [
    wt.HANDLE,
    wt.LPVOID,
    ctypes.c_size_t,
    wt.DWORD,
    wt.DWORD,
]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p

kernel32.VirtualFreeEx.argtypes = [
    wt.HANDLE,
    wt.LPVOID,
    ctypes.c_size_t,
    wt.DWORD,
]
kernel32.VirtualFreeEx.restype = wt.BOOL

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

kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.CloseHandle.restype = wt.BOOL

user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
user32.GetAsyncKeyState.restype = wt.SHORT


def invalid_handle(h):
    if not h:
        return True
    return ctypes.cast(h, ctypes.c_void_p).value in (
        None,
        ctypes.c_void_p(-1).value,
    )


def close_handle(h):
    if not invalid_handle(h):
        kernel32.CloseHandle(h)


def find_pid(name: str) -> int:
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    if invalid_handle(snap):
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(pe)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(pe))

        while ok:
            if pe.szExeFile.lower() == name.lower():
                return int(pe.th32ProcessID)

            ok = kernel32.Process32NextW(snap, ctypes.byref(pe))

    finally:
        close_handle(snap)

    raise RuntimeError(f"{name} niet gevonden.")


def find_module(pid: int, name: str):
    snap = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        pid,
    )

    if invalid_handle(snap):
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(me)

        ok = kernel32.Module32FirstW(snap, ctypes.byref(me))

        while ok:
            if me.szModule.lower() == name.lower():
                return (
                    int(me.modBaseAddr or 0),
                    int(me.modBaseSize),
                    me.szExePath,
                )

            ok = kernel32.Module32NextW(snap, ctypes.byref(me))

    finally:
        close_handle(snap)

    raise RuntimeError(f"module {name} niet gevonden.")


class Process:
    def __init__(self, pid: int):
        self.pid = pid
        self.h = kernel32.OpenProcess(ACCESS, False, pid)

        if not self.h:
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.h:
            close_handle(self.h)
            self.h = None

    def read(self, address: int, size: int) -> bytes:
        buf = (ctypes.c_ubyte * size)()
        got = ctypes.c_size_t()

        ok = kernel32.ReadProcessMemory(
            self.h,
            ctypes.c_void_p(address),
            buf,
            size,
            ctypes.byref(got),
        )

        if not ok or got.value != size:
            raise RuntimeError(
                f"ReadProcessMemory @0x{address:08X} "
                f"size=0x{size:X} got=0x{got.value:X} "
                f"err={ctypes.get_last_error()}"
            )

        return bytes(buf)

    def safe_read(self, address: int, size: int):
        try:
            return self.read(address, size)
        except Exception:
            return None

    def write(self, address: int, data: bytes):
        buf = ctypes.create_string_buffer(data)
        wrote = ctypes.c_size_t()

        ok = kernel32.WriteProcessMemory(
            self.h,
            ctypes.c_void_p(address),
            buf,
            len(data),
            ctypes.byref(wrote),
        )

        if not ok or wrote.value != len(data):
            raise RuntimeError(
                f"WriteProcessMemory @0x{address:08X} "
                f"size=0x{len(data):X} wrote=0x{wrote.value:X} "
                f"err={ctypes.get_last_error()}"
            )

    def read_u32(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]

    def safe_u32(self, address: int):
        try:
            return self.read_u32(address)
        except Exception:
            return None

    def write_u32(self, address: int, value: int):
        self.write(address, struct.pack("<I", value & 0xFFFFFFFF))

    def alloc(self, size: int) -> int:
        p = kernel32.VirtualAllocEx(
            self.h,
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )

        if not p:
            raise ctypes.WinError(ctypes.get_last_error())

        return int(p)

    def free(self, address: int):
        if address:
            kernel32.VirtualFreeEx(
                self.h,
                ctypes.c_void_p(address),
                0,
                MEM_RELEASE,
            )

    def patch_code(self, address: int, data: bytes):
        old = wt.DWORD()

        if not kernel32.VirtualProtectEx(
            self.h,
            ctypes.c_void_p(address),
            len(data),
            PAGE_EXECUTE_READWRITE,
            ctypes.byref(old),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        try:
            self.write(address, data)
            kernel32.FlushInstructionCache(
                self.h,
                ctypes.c_void_p(address),
                len(data),
            )

        finally:
            ignored = wt.DWORD()
            kernel32.VirtualProtectEx(
                self.h,
                ctypes.c_void_p(address),
                len(data),
                old.value,
                ctypes.byref(ignored),
            )


# ============================================================================
# X86 BUILDING
# ============================================================================

def rel32(src: int, dst: int) -> bytes:
    disp = (dst - (src + 5)) & 0xFFFFFFFF
    return struct.pack("<I", disp)


def jmp_rel32(src: int, dst: int) -> bytes:
    return b"\xE9" + rel32(src, dst)


def decode_existing_e9(site: int, first5: bytes):
    if len(first5) >= 5 and first5[0] == 0xE9:
        disp = struct.unpack("<i", first5[1:5])[0]
        return (site + 5 + disp) & 0xFFFFFFFF
    return None


def simple_prologue_span(code: bytes) -> int:
    """
    Small conservative decoder for common x86 function-entry instructions.
    It is used only when an entry is NOT already an E9.

    Relative CALL/JMP/Jcc in the stolen area are intentionally rejected.
    """

    i = 0

    while i < len(code) and i < 16 and i < 5:
        op = code[i]

        # one-byte pushes/pops, nop, pushfd/pushad
        if (
            0x50 <= op <= 0x5F
            or op in (0x55, 0x90, 0x9C, 0x60)
        ):
            i += 1
            continue

        # mov reg, imm32
        if 0xB8 <= op <= 0xBF:
            i += 5
            continue

        # push imm32 / imm8
        if op == 0x68:
            i += 5
            continue

        if op == 0x6A:
            i += 2
            continue

        # mov ebp,esp = 8B EC or 89 E5
        if code[i:i+2] in (b"\x8B\xEC", b"\x89\xE5"):
            i += 2
            continue

        # sub esp,imm8 = 83 EC xx
        if code[i:i+2] == b"\x83\xEC":
            i += 3
            continue

        # and esp,imm8 = 83 E4 xx
        if code[i:i+2] == b"\x83\xE4":
            i += 3
            continue

        # sub esp,imm32 = 81 EC xxxxxxxx
        if code[i:i+2] == b"\x81\xEC":
            i += 6
            continue

        # absolute mov eax,[imm32] / mov [imm32],eax
        if op in (0xA1, 0xA3):
            i += 5
            continue

        # Any relative flow-control instruction is unsafe to copy verbatim.
        if op in (0xE8, 0xE9, 0xEB) or 0x70 <= op <= 0x7F:
            raise RuntimeError(
                "unsupported relative instruction in first hook bytes"
            )

        if op == 0x0F and i + 1 < len(code) and 0x80 <= code[i+1] <= 0x8F:
            raise RuntimeError(
                "unsupported near conditional jump in first hook bytes"
            )

        raise RuntimeError(
            f"unsupported first instruction byte 0x{op:02X}"
        )

    if i < 5:
        raise RuntimeError("could not obtain >=5 whole entry bytes")

    return i


@dataclass
class Hook:
    site: int
    original: bytes
    patch: bytes
    chain_target: int
    trampoline: int | None


def prepare_chain(
    pm: Process,
    site: int,
    trampoline_addr: int,
) -> tuple[bytes, int, int | None]:
    """
    Returns: original_bytes, chain_target, trampoline_or_none
    """

    head = pm.read(site, 16)
    existing = decode_existing_e9(site, head[:5])

    if existing is not None:
        return head[:5], existing, None

    span = simple_prologue_span(head)
    stolen = head[:span]

    # Copy safe prologue and jump back after it.
    tramp = stolen + jmp_rel32(
        trampoline_addr + len(stolen),
        site + span,
    )

    pm.write(trampoline_addr, tramp)

    return stolen, trampoline_addr, trampoline_addr


def install_hook(
    pm: Process,
    site: int,
    cave_addr: int,
    trampoline_addr: int,
    cave: bytes,
) -> Hook:
    original, chain_target, tramp = prepare_chain(
        pm,
        site,
        trampoline_addr,
    )

    pm.write(cave_addr, cave(chain_target))

    patch = jmp_rel32(site, cave_addr)

    if len(original) > 5:
        patch += b"\x90" * (len(original) - 5)

    pm.patch_code(site, patch)

    return Hook(
        site=site,
        original=original,
        patch=patch,
        chain_target=chain_target,
        trampoline=tramp,
    )


# ============================================================================
# REMOTE CAVES
# ============================================================================

def build_pet_cave(
    cave_addr: int,
    pet_ptr_addr: int,
    chain_target: int,
) -> bytes:
    b = bytearray()

    # mov [abs], ecx
    b += b"\x89\x0D" + struct.pack("<I", pet_ptr_addr)

    # jmp previous target / trampoline
    jmp_site = cave_addr + len(b)
    b += jmp_rel32(jmp_site, chain_target)

    return bytes(b)


class Asm:
    """Tiny label-aware x86 byte builder for the tick cave."""

    def __init__(self, base: int):
        self.base = base
        self.b = bytearray()
        self.labels = {}
        self.fixups = []

    @property
    def va(self):
        return self.base + len(self.b)

    def emit(self, data: bytes):
        self.b += data

    def label(self, name: str):
        self.labels[name] = self.va

    def jcc32(self, cc: int, label: str):
        # 0F 8x rel32, where cc is the low condition nibble:
        #   4 = E/Z, 5 = NE/NZ, etc.
        pos = len(self.b)
        self.b += bytes([0x0F, 0x80 | (cc & 0x0F)]) + b"\x00\x00\x00\x00"
        self.fixups.append(("rel32", pos + 2, label, pos + 6))

    def jmp32_label(self, label: str):
        pos = len(self.b)
        self.b += b"\xE9\x00\x00\x00\x00"
        self.fixups.append(("rel32", pos + 1, label, pos + 5))

    def finish(self):
        for kind, patch_off, label, next_off in self.fixups:
            if label not in self.labels:
                raise RuntimeError(f"missing asm label {label}")

            dst = self.labels[label]
            src_next = self.base + next_off

            disp = (dst - src_next) & 0xFFFFFFFF
            self.b[patch_off:patch_off+4] = struct.pack("<I", disp)

        return bytes(self.b)


def build_tick_cave(
    cave_addr: int,
    chain_target: int,
    enabled_addr: int,
    pet_ptr_addr: int,
    pending_addr: int,
    view_ptr_addr: int,
    oid_addr: int,
    busy_addr: int,
    point_x_addr: int,
    point_y_addr: int,
    call_count_addr: int,
    pool_global_addr: int,
    coord_get_addr: int,
    pickup_addr: int,
) -> bytes:
    a = Asm(cave_addr)

    # Preserve the callback's incoming machine state.
    a.emit(b"\x9C")       # pushfd
    a.emit(b"\x60")       # pushad

    # cmp dword ptr [enabled],0
    a.emit(b"\x83\x3D" + struct.pack("<I", enabled_addr) + b"\x00")
    a.jcc32(0x4, "restore")   # je

    # cmp dword ptr [busy],0
    a.emit(b"\x83\x3D" + struct.pack("<I", busy_addr) + b"\x00")
    a.jcc32(0x5, "restore")   # jne

    # cmp dword ptr [pending],1
    a.emit(b"\x83\x3D" + struct.pack("<I", pending_addr) + b"\x01")
    a.jcc32(0x5, "restore")

    # mov eax,[pet_ptr]
    a.emit(b"\xA1" + struct.pack("<I", pet_ptr_addr))
    a.emit(b"\x85\xC0")       # test eax,eax
    a.jcc32(0x4, "restore")

    # busy = 1
    a.emit(
        b"\xC7\x05"
        + struct.pack("<I", busy_addr)
        + struct.pack("<I", 1)
    )

    # esi = queued view
    a.emit(b"\x8B\x35" + struct.pack("<I", view_ptr_addr))
    a.emit(b"\x85\xF6")
    a.jcc32(0x4, "finish")

    # Require the exact live-drop state still to be 3.
    a.emit(b"\x83\x7E" + bytes([VIEW_STATE_OFF]) + bytes([ACTIVE_DROP_STATE]))
    a.jcc32(0x5, "finish")

    # Verify queued OID still matches [view+0x20].
    a.emit(b"\x8B\x46" + bytes([VIEW_OID_OFF]))  # mov eax,[esi+20]
    a.emit(b"\x3B\x05" + struct.pack("<I", oid_addr))
    a.jcc32(0x5, "finish")

    # x = sign16( SecureGet(view + 0x74) )
    a.emit(b"\x8D\x4E" + bytes([VIEW_X_SECURE_OFF]))
    a.emit(b"\xB8" + struct.pack("<I", coord_get_addr))
    a.emit(b"\xFF\xD0")       # call eax
    a.emit(b"\x0F\xBF\xC0")   # movsx eax,ax
    a.emit(b"\xA3" + struct.pack("<I", point_x_addr))

    # y = sign16( SecureGet(view + 0x68) )
    a.emit(b"\x8D\x4E" + bytes([VIEW_Y_SECURE_OFF]))
    a.emit(b"\xB8" + struct.pack("<I", coord_get_addr))
    a.emit(b"\xFF\xD0")
    a.emit(b"\x0F\xBF\xC0")
    a.emit(b"\xA3" + struct.pack("<I", point_y_addr))

    # ecx = *CDropPoolGlobal
    a.emit(b"\x8B\x0D" + struct.pack("<I", pool_global_addr))
    a.emit(b"\x85\xC9")
    a.jcc32(0x4, "finish")

    # thiscall:
    #   ECX = CDropPool*
    #   [ESP+4] = pet*
    #   [ESP+8] = POINT*
    #
    # push POINT*
    a.emit(b"\x68" + struct.pack("<I", point_x_addr))

    # push pet*
    a.emit(b"\xA1" + struct.pack("<I", pet_ptr_addr))
    a.emit(b"\x50")

    # call pet-aware pickup
    a.emit(b"\xB8" + struct.pack("<I", pickup_addr))
    a.emit(b"\xFF\xD0")

    # inc call counter
    a.emit(b"\xFF\x05" + struct.pack("<I", call_count_addr))

    a.label("finish")

    # pending = 0
    a.emit(
        b"\xC7\x05"
        + struct.pack("<I", pending_addr)
        + struct.pack("<I", 0)
    )

    # busy = 0
    a.emit(
        b"\xC7\x05"
        + struct.pack("<I", busy_addr)
        + struct.pack("<I", 0)
    )

    a.label("restore")

    a.emit(b"\x61")       # popad
    a.emit(b"\x9D")       # popfd

    # Continue the callback exactly where it used to go.
    jmp_site = a.va
    a.emit(jmp_rel32(jmp_site, chain_target))

    return a.finish()


# ============================================================================
# EXACT YUNA ITERATOR
# ============================================================================

@dataclass
class DropEntry:
    current: int
    view: int
    oid: int


def walk_drops(
    pm: Process,
    pool: int,
) -> list[DropEntry]:
    count = pm.safe_u32(pool + POOL_COUNT_OFF)
    root = pm.safe_u32(pool + POOL_ROOT_OFF)

    if count is None or not root:
        return []

    result = []
    seen = set()
    current = root

    max_steps = max(64, count + MAX_ITER_EXTRA)

    for _ in range(max_steps):
        if not current or current in seen:
            break

        seen.add(current)

        view = pm.safe_u32(current + ITER_VIEW_OFF)

        if view:
            state = pm.safe_u32(view + VIEW_STATE_OFF)
            oid = pm.safe_u32(view + VIEW_OID_OFF)

            if (
                state == ACTIVE_DROP_STATE
                and oid not in (None, 0, 0xFFFFFFFF)
            ):
                result.append(
                    DropEntry(
                        current=current,
                        view=view,
                        oid=oid,
                    )
                )

        owner = current - ITER_OWNER_BACK
        next_owner = pm.safe_u32(owner + ITER_NEXT_OWNER_OFF)

        if not next_owner:
            break

        current = (next_owner + ITER_OWNER_BACK) & 0xFFFFFFFF

    return result


# ============================================================================
# MAIN
# ============================================================================

def key_pressed(vk: int, previous: bool):
    now = bool(user32.GetAsyncKeyState(vk) & 0x8000)
    return now, (now and not previous)


def main():
    print("=" * 72)
    print("YunaMS v83 - PET ITEM VAC")
    print("F1 = ON | F2 = OFF | ESC = EXIT + RESTORE")
    print("=" * 72)

    pid = find_pid(PROCESS_NAME)
    base, module_size, module_path = find_module(pid, PROCESS_NAME)

    print(f"[+] PID       : {pid}")
    print(f"[+] Module    : {module_path}")
    print(f"[+] Image base: 0x{base:08X}")

    pm = Process(pid)
    remote = 0
    pet_hook = None
    tick_hook = None

    try:
        # Live addresses.
        pool_global = base + DROP_POOL_GLOBAL_RVA
        pet_update = base + PET_UPDATE_RVA
        game_tick = base + GAME_TICK_RVA
        coord_get = base + SECURE_COORD_GET_RVA
        pickup = base + PET_PICKUP_RVA

        pool = pm.safe_u32(pool_global)

        if not pool:
            raise RuntimeError(
                f"CDropPool is NULL/unreadable at 0x{pool_global:08X}"
            )

        print(f"[+] CDropPool : 0x{pool:08X}")
        print(
            f"[+] Drops now : {pm.safe_u32(pool + POOL_COUNT_OFF)}"
        )

        # Allocate one ordinary executable page.
        remote = pm.alloc(REMOTE_SIZE)
        pm.write(remote, b"\x00" * REMOTE_SIZE)

        print(f"[+] Remote page: 0x{remote:08X}")

        pet_cave = remote + PET_CAVE_OFF
        tick_cave = remote + TICK_CAVE_OFF
        pet_tramp = remote + PET_TRAMP_OFF
        tick_tramp = remote + TICK_TRAMP_OFF

        enabled_addr = remote + ENABLED_OFF
        pet_ptr_addr = remote + PET_PTR_OFF
        pending_addr = remote + PENDING_OFF
        view_ptr_addr = remote + VIEW_PTR_OFF
        oid_addr = remote + OID_OFF
        busy_addr = remote + BUSY_OFF
        point_x_addr = remote + POINT_X_OFF
        point_y_addr = remote + POINT_Y_OFF
        call_count_addr = remote + CALL_COUNT_OFF

        # --------------------------------------------------------------------
        # Preflight both hooks BEFORE installing either one.
        # --------------------------------------------------------------------

        pet_head = pm.read(pet_update, 16)
        tick_head = pm.read(game_tick, 16)

        print(
            "[+] Pet-update bytes:",
            pet_head[:12].hex(" ").upper(),
        )
        print(
            "[+] Game-tick bytes :",
            tick_head[:12].hex(" ").upper(),
        )

        # Determine whether each entry can be chained safely.
        # prepare_chain writes only a trampoline area if needed, not .text.
        pet_original, pet_chain, pet_trampoline_used = prepare_chain(
            pm,
            pet_update,
            pet_tramp,
        )

        tick_original, tick_chain, tick_trampoline_used = prepare_chain(
            pm,
            game_tick,
            tick_tramp,
        )

        print(
            f"[+] Pet chain   : 0x{pet_chain:08X} "
            f"({'existing E9' if pet_trampoline_used is None else 'trampoline'})"
        )

        print(
            f"[+] Tick chain  : 0x{tick_chain:08X} "
            f"({'existing E9' if tick_trampoline_used is None else 'trampoline'})"
        )

        # Build caves now that previous targets are known.
        pet_code = build_pet_cave(
            pet_cave,
            pet_ptr_addr,
            pet_chain,
        )

        tick_code = build_tick_cave(
            tick_cave,
            tick_chain,
            enabled_addr,
            pet_ptr_addr,
            pending_addr,
            view_ptr_addr,
            oid_addr,
            busy_addr,
            point_x_addr,
            point_y_addr,
            call_count_addr,
            pool_global,
            coord_get,
            pickup,
        )

        pm.write(pet_cave, pet_code)
        pm.write(tick_cave, tick_code)

        # Install patches last.
        pet_patch = jmp_rel32(pet_update, pet_cave)
        if len(pet_original) > 5:
            pet_patch += b"\x90" * (len(pet_original) - 5)

        tick_patch = jmp_rel32(game_tick, tick_cave)
        if len(tick_original) > 5:
            tick_patch += b"\x90" * (len(tick_original) - 5)

        pm.patch_code(pet_update, pet_patch)
        pet_hook = Hook(
            site=pet_update,
            original=pet_original,
            patch=pet_patch,
            chain_target=pet_chain,
            trampoline=pet_trampoline_used,
        )

        pm.patch_code(game_tick, tick_patch)
        tick_hook = Hook(
            site=game_tick,
            original=tick_original,
            patch=tick_patch,
            chain_target=tick_chain,
            trampoline=tick_trampoline_used,
        )

        print("[+] Hooks installed; previous chains preserved.")
        print("[*] Summon/move the pet once so its CPet* gets captured.")
        print("[*] F1 ON, F2 OFF, ESC quits and restores hooks.")

        f1_prev = False
        f2_prev = False
        esc_prev = False

        enabled = False
        attempts: dict[int, float] = {}
        last_status = 0.0
        last_calls = 0

        while True:
            f1_prev, f1_edge = key_pressed(VK_F1, f1_prev)
            f2_prev, f2_edge = key_pressed(VK_F2, f2_prev)
            esc_prev, esc_edge = key_pressed(VK_ESCAPE, esc_prev)

            if esc_edge:
                print("[*] ESC -> stopping.")
                break

            if f1_edge:
                enabled = True
                pm.write_u32(enabled_addr, 1)
                print("[ON] Pet Item Vac")

            if f2_edge:
                enabled = False
                pm.write_u32(enabled_addr, 0)
                pm.write_u32(pending_addr, 0)
                print("[OFF] Pet Item Vac")

            if enabled:
                pet_ptr = pm.safe_u32(pet_ptr_addr) or 0
                pending = pm.safe_u32(pending_addr) or 0
                busy = pm.safe_u32(busy_addr) or 0

                # Refresh CDropPool in case the game rebuilt it.
                live_pool = pm.safe_u32(pool_global)

                if live_pool:
                    pool = live_pool

                if pet_ptr and not pending and not busy and pool:
                    drops = walk_drops(pm, pool)

                    now = time.monotonic()
                    chosen = None

                    for drop in drops:
                        last = attempts.get(drop.oid, 0.0)

                        if now - last >= RETRY_SAME_OID_AFTER:
                            chosen = drop
                            break

                    if chosen is not None:
                        # Publish all fields first, pending LAST.
                        pm.write_u32(view_ptr_addr, chosen.view)
                        pm.write_u32(oid_addr, chosen.oid)
                        pm.write_u32(pending_addr, 1)

                        attempts[chosen.oid] = now

                # Prevent the retry dictionary growing forever.
                if len(attempts) > 4096:
                    cutoff = time.monotonic() - 10.0
                    attempts = {
                        oid: when
                        for oid, when in attempts.items()
                        if when >= cutoff
                    }

            now = time.monotonic()

            if now - last_status >= STATUS_EVERY:
                last_status = now

                pet_ptr = pm.safe_u32(pet_ptr_addr) or 0
                calls = pm.safe_u32(call_count_addr) or 0
                live_pool = pm.safe_u32(pool_global)
                drop_count = (
                    pm.safe_u32(live_pool + POOL_COUNT_OFF)
                    if live_pool else None
                )

                mode = "ON " if enabled else "OFF"

                if calls != last_calls or enabled:
                    print(
                        f"[{mode}] pet=0x{pet_ptr:08X} "
                        f"drops={drop_count} pickup_calls={calls}"
                    )

                last_calls = calls

            time.sleep(LOOP_SLEEP)

    except KeyboardInterrupt:
        print("\n[*] Ctrl+C -> stopping.")

    finally:
        # Disable and clear queue first.
        if remote:
            try:
                pm.write_u32(remote + ENABLED_OFF, 0)
                pm.write_u32(remote + PENDING_OFF, 0)
            except Exception:
                pass

        time.sleep(0.05)

        # Restore only if the entry still contains OUR exact patch.
        for name, hook in (
            ("tick", tick_hook),
            ("pet", pet_hook),
        ):
            if hook is None:
                continue

            try:
                current = pm.read(hook.site, len(hook.patch))

                if current == hook.patch:
                    pm.patch_code(
                        hook.site,
                        hook.original,
                    )
                    print(
                        f"[+] Restored {name} hook @ 0x{hook.site:08X}"
                    )
                else:
                    print(
                        f"[!] Did NOT restore {name}: entry changed "
                        "after our installation."
                    )

            except Exception as exc:
                print(f"[!] Restore {name} failed: {exc}")

        time.sleep(0.05)

        if remote:
            try:
                pm.free(remote)
                print("[+] Remote page freed.")
            except Exception as exc:
                print(f"[!] Remote free failed: {exc}")

        pm.close()

        print("[+] Done.")


if __name__ == "__main__":
    main()
