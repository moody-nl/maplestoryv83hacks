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


import tkinter as tk


class PetVacGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Pet Vac")
        self.root.geometry("360x120")
        self.root.resizable(False, False)

        self.enabled = False
        self.closed = False

        self.pid = find_pid(PROCESS_NAME)
        self.base, self.module_size, self.module_path = find_module(
            self.pid,
            PROCESS_NAME,
        )

        self.pm = Process(self.pid)

        self.remote = 0
        self.pet_hook = None
        self.tick_hook = None

        # Live addresses.
        self.pool_global = self.base + DROP_POOL_GLOBAL_RVA
        self.pet_update = self.base + PET_UPDATE_RVA
        self.game_tick = self.base + GAME_TICK_RVA
        self.coord_get = self.base + SECURE_COORD_GET_RVA
        self.pickup = self.base + PET_PICKUP_RVA

        self.pool = self.pm.safe_u32(self.pool_global)

        if not self.pool:
            self.pm.close()
            self.root.destroy()
            raise RuntimeError(
                f"CDropPool is NULL/unreadable at 0x{self.pool_global:08X}"
            )

        # Allocate exactly the same remote block as the original script.
        self.remote = self.pm.alloc(REMOTE_SIZE)
        self.pm.write(self.remote, b"\x00" * REMOTE_SIZE)

        self.pet_cave = self.remote + PET_CAVE_OFF
        self.tick_cave = self.remote + TICK_CAVE_OFF
        self.pet_tramp = self.remote + PET_TRAMP_OFF
        self.tick_tramp = self.remote + TICK_TRAMP_OFF

        self.enabled_addr = self.remote + ENABLED_OFF
        self.pet_ptr_addr = self.remote + PET_PTR_OFF
        self.pending_addr = self.remote + PENDING_OFF
        self.view_ptr_addr = self.remote + VIEW_PTR_OFF
        self.oid_addr = self.remote + OID_OFF
        self.busy_addr = self.remote + BUSY_OFF
        self.point_x_addr = self.remote + POINT_X_OFF
        self.point_y_addr = self.remote + POINT_Y_OFF
        self.call_count_addr = self.remote + CALL_COUNT_OFF

        # Same preflight/chain logic as petvac.py.
        pet_original, pet_chain, pet_trampoline_used = prepare_chain(
            self.pm,
            self.pet_update,
            self.pet_tramp,
        )

        tick_original, tick_chain, tick_trampoline_used = prepare_chain(
            self.pm,
            self.game_tick,
            self.tick_tramp,
        )

        pet_code = build_pet_cave(
            self.pet_cave,
            self.pet_ptr_addr,
            pet_chain,
        )

        tick_code = build_tick_cave(
            self.tick_cave,
            tick_chain,
            self.enabled_addr,
            self.pet_ptr_addr,
            self.pending_addr,
            self.view_ptr_addr,
            self.oid_addr,
            self.busy_addr,
            self.point_x_addr,
            self.point_y_addr,
            self.call_count_addr,
            self.pool_global,
            self.coord_get,
            self.pickup,
        )

        self.pm.write(self.pet_cave, pet_code)
        self.pm.write(self.tick_cave, tick_code)

        # Same hook installation as the original script.
        pet_patch = jmp_rel32(self.pet_update, self.pet_cave)
        if len(pet_original) > 5:
            pet_patch += b"\x90" * (len(pet_original) - 5)

        tick_patch = jmp_rel32(self.game_tick, self.tick_cave)
        if len(tick_original) > 5:
            tick_patch += b"\x90" * (len(tick_original) - 5)

        self.pm.patch_code(self.pet_update, pet_patch)
        self.pet_hook = Hook(
            site=self.pet_update,
            original=pet_original,
            patch=pet_patch,
            chain_target=pet_chain,
            trampoline=pet_trampoline_used,
        )

        self.pm.patch_code(self.game_tick, tick_patch)
        self.tick_hook = Hook(
            site=self.game_tick,
            original=tick_original,
            patch=tick_patch,
            chain_target=tick_chain,
            trampoline=tick_trampoline_used,
        )

        self.attempts: dict[int, float] = {}

        # Global hotkey edge tracking.
        self.f1_prev = False
        self.f2_prev = False

        # Exactly two buttons. Nothing else.
        self.on_button = tk.Button(
            self.root,
            text="F1  AAN",
            command=self.turn_on,
            width=14,
            height=3,
            font=("Segoe UI", 12, "bold"),
        )
        self.on_button.pack(side="left", padx=(20, 10), pady=25)

        self.off_button = tk.Button(
            self.root,
            text="F2  UIT",
            command=self.turn_off,
            width=14,
            height=3,
            font=("Segoe UI", 12, "bold"),
        )
        self.off_button.pack(side="right", padx=(10, 20), pady=25)

        # Local key bindings.
        self.root.bind("<F1>", lambda _event: self.turn_on())
        self.root.bind("<F2>", lambda _event: self.turn_off())

        self.root.protocol("WM_DELETE_WINDOW", self.close)

        # Same logic as the original while-loop, driven by Tk's timer.
        self.root.after(10, self.loop)

    def turn_on(self):
        self.enabled = True
        self.pm.write_u32(self.enabled_addr, 1)

    def turn_off(self):
        self.enabled = False
        self.pm.write_u32(self.enabled_addr, 0)
        self.pm.write_u32(self.pending_addr, 0)

    def loop(self):
        if self.closed:
            return

        # Global F1/F2, so they also work while YunaMS has focus.
        self.f1_prev, f1_edge = key_pressed(VK_F1, self.f1_prev)
        self.f2_prev, f2_edge = key_pressed(VK_F2, self.f2_prev)

        if f1_edge:
            self.turn_on()

        if f2_edge:
            self.turn_off()

        if self.enabled:
            pet_ptr = self.pm.safe_u32(self.pet_ptr_addr) or 0
            pending = self.pm.safe_u32(self.pending_addr) or 0
            busy = self.pm.safe_u32(self.busy_addr) or 0

            # Same CDropPool refresh as the original script.
            live_pool = self.pm.safe_u32(self.pool_global)

            if live_pool:
                self.pool = live_pool

            if pet_ptr and not pending and not busy and self.pool:
                drops = walk_drops(self.pm, self.pool)

                now = time.monotonic()
                chosen = None

                for drop in drops:
                    last = self.attempts.get(drop.oid, 0.0)

                    if now - last >= RETRY_SAME_OID_AFTER:
                        chosen = drop
                        break

                if chosen is not None:
                    # Same publish order as the original:
                    # view/OID first, PENDING last.
                    self.pm.write_u32(
                        self.view_ptr_addr,
                        chosen.view,
                    )
                    self.pm.write_u32(
                        self.oid_addr,
                        chosen.oid,
                    )
                    self.pm.write_u32(
                        self.pending_addr,
                        1,
                    )

                    self.attempts[chosen.oid] = now

            if len(self.attempts) > 4096:
                cutoff = time.monotonic() - 10.0
                self.attempts = {
                    oid: when
                    for oid, when in self.attempts.items()
                    if when >= cutoff
                }

        self.root.after(10, self.loop)

    def close(self):
        if self.closed:
            return

        self.closed = True

        # Same cleanup/restore behavior as petvac.py.
        if self.remote:
            try:
                self.pm.write_u32(self.remote + ENABLED_OFF, 0)
                self.pm.write_u32(self.remote + PENDING_OFF, 0)
            except Exception:
                pass

        time.sleep(0.05)

        for hook in (self.tick_hook, self.pet_hook):
            if hook is None:
                continue

            try:
                current = self.pm.read(
                    hook.site,
                    len(hook.patch),
                )

                if current == hook.patch:
                    self.pm.patch_code(
                        hook.site,
                        hook.original,
                    )

            except Exception:
                pass

        time.sleep(0.05)

        if self.remote:
            try:
                self.pm.free(self.remote)
            except Exception:
                pass

        try:
            self.pm.close()
        except Exception:
            pass

        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main():
    PetVacGUI().run()


if __name__ == "__main__":
    main()
