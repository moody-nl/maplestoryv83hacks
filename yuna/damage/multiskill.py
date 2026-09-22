import atexit
import ctypes
import ctypes.wintypes as wt
import struct
import tkinter as tk
from tkinter import messagebox, ttk

import pymem
import pymem.process


# ============================================================
# YUNAMS v83 - MULTI SKILL PACKET REPLAY GUI
#
# Combines the existing working Magic Claw / Ice Strike logic
# into ONE SendPacket hook.  This is important: two independent
# hooks on the same SendPacket entry would compete with each other.
# ============================================================

PROCESS = "YunaMS.exe"

IMAGE_BASE = 0x00400000

SENDPACKET = 0x0049637B

ATTACK_CALL = 0x0095710A
ATTACK_RETURN = 0x0095710F


# ============================================================
# v83 MAGIC ATTACK FINGERPRINTS
# ============================================================

MAGIC_OPCODE = 0x002E

MAGIC_CLAW_ID = 2001005
MAGIC_CLAW_PACKED = 0x12  # Keep the already-confirmed strict check.

ICE_STRIKE_ID = 2211002
CHAIN_LIGHTNING_ID = 2221006
BLIZZARD_ID = 2221007


# ============================================================
# SKILL MASK
# ============================================================

SKILL_MAGIC_CLAW = 0x01
SKILL_ICE_STRIKE = 0x02
SKILL_CHAIN_LIGHTNING = 0x04
SKILL_BLIZZARD = 0x08

SKILL_INFO = (
    ("Magic Claw", MAGIC_CLAW_ID, SKILL_MAGIC_CLAW),
    ("Ice Strike", ICE_STRIKE_ID, SKILL_ICE_STRIKE),
    ("Chain Lightning", CHAIN_LIGHTNING_ID, SKILL_CHAIN_LIGHTNING),
    ("Blizzard", BLIZZARD_ID, SKILL_BLIZZARD),
)


# ============================================================
# REMOTE MEMORY
# ============================================================

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000

PAGE_EXECUTE_READWRITE = 0x40

ALLOC_SIZE = 0x2000

# Remote control block
CTRL_OFF = 0x1000

# Keep the original first fields/offsets:
#   ctrl + 0x00 = mode: 0=pass-through, 1=x2, 3=x4
#   ctrl + 0x04 = total matching packets intercepted
#   ctrl + 0x08 = last matching COutPacket*
#
# Added for the combined GUI:
#   ctrl + 0x0C = enabled-skill bitmask
#   ctrl + 0x10 = Magic Claw count
#   ctrl + 0x14 = Ice Strike count
#   ctrl + 0x18 = Chain Lightning count
#   ctrl + 0x1C = Blizzard count

C_MODE = 0x00
C_COUNT = 0x04
C_LAST_PACKET = 0x08
C_SKILL_MASK = 0x0C
C_COUNT_MAGIC = 0x10
C_COUNT_ICE = 0x14
C_COUNT_CHAIN = 0x18
C_COUNT_BLIZZARD = 0x1C


kernel32 = ctypes.WinDLL(
    "kernel32",
    use_last_error=True,
)


kernel32.VirtualAllocEx.argtypes = [
    wt.HANDLE,
    wt.LPVOID,
    ctypes.c_size_t,
    wt.DWORD,
    wt.DWORD,
]

kernel32.VirtualAllocEx.restype = wt.LPVOID


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


# ============================================================
# HELPERS
# ============================================================


def p32(value):
    return struct.pack(
        "<I",
        value & 0xFFFFFFFF,
    )


def rel32_bits(source_next, destination):
    """Encode x86 relative CALL/JMP displacement."""
    return p32(
        destination - source_next
    )


def decode_e9_target(address, five_bytes):
    if (
        len(five_bytes) != 5
        or five_bytes[0] != 0xE9
    ):
        return None

    displacement = struct.unpack(
        "<i",
        five_bytes[1:5],
    )[0]

    return (
        address
        + 5
        + displacement
    ) & 0xFFFFFFFF


def decode_e8_target(address, five_bytes):
    if (
        len(five_bytes) != 5
        or five_bytes[0] != 0xE8
    ):
        return None

    displacement = struct.unpack(
        "<i",
        five_bytes[1:5],
    )[0]

    return (
        address
        + 5
        + displacement
    ) & 0xFFFFFFFF


def protect(pm, address, size, protection):
    old = wt.DWORD()

    ok = kernel32.VirtualProtectEx(
        pm.process_handle,
        ctypes.c_void_p(address),
        size,
        protection,
        ctypes.byref(old),
    )

    if not ok:
        raise ctypes.WinError(
            ctypes.get_last_error()
        )

    return old.value


def write_code_verified(
    pm,
    address,
    expected,
    replacement,
):
    actual = pm.read_bytes(
        address,
        len(expected),
    )

    if actual != expected:
        raise RuntimeError(
            f"Write geweigerd @ 0x{address:08X}\n"
            f"found    = {actual.hex(' ').upper()}\n"
            f"expected = {expected.hex(' ').upper()}"
        )

    old = protect(
        pm,
        address,
        len(replacement),
        PAGE_EXECUTE_READWRITE,
    )

    try:
        pm.write_bytes(
            address,
            replacement,
            len(replacement),
        )

        kernel32.FlushInstructionCache(
            pm.process_handle,
            ctypes.c_void_p(address),
            len(replacement),
        )

    finally:
        protect(
            pm,
            address,
            len(replacement),
            old,
        )

    check = pm.read_bytes(
        address,
        len(replacement),
    )

    if check != replacement:
        raise RuntimeError(
            "Code-write verification mislukt."
        )


def make_entry_patch(
    source,
    destination,
):
    return (
        b"\xE9"
        + rel32_bits(
            source + 5,
            destination,
        )
    )


# ============================================================
# TRAMPOLINE
# ============================================================


def build_trampoline(
    code_va,
    ctrl_va,
    downstream_va,
):
    """
    One shared hook for all four skills.

    Entry ABI (kept from the working versions):

        ECX     = CClientSocket*
        [ESP]   = caller return
        [ESP+4] = COutPacket*

    COutPacket:
        +4 = payload pointer
        +8 = payload length

    Common filter:
        caller return = 0x0095710F
        opcode        = 0x002E
        skill ID      = one of the four exact IDs

    Magic Claw additionally keeps its already-confirmed packed=0x12
    requirement.  Ice Strike keeps its dynamic packed-byte behaviour.
    Chain Lightning and Blizzard use opcode + exact skill ID + confirmed
    attack caller, matching the Ice Strike-style classifier.

    mode=1 -> downstream 2 times total
    mode=3 -> downstream 4 times total

    All non-selected / non-matching packets continue unchanged through
    the pre-existing runtime E9 chain.
    """

    b = bytearray()

    # --------------------------------------------------------
    # Save COMPLETE entry state.
    # --------------------------------------------------------

    b += b"\x9C"       # pushfd
    b += b"\x60"       # pushad

    # EBX = ctrl block
    b += b"\xBB" + p32(ctrl_va)

    # EAX = mode
    b += b"\x8B\x03"

    # test eax,eax
    b += b"\x85\xC0"

    jz_mode_off = len(b)
    b += b"\x0F\x84\x00\x00\x00\x00"

    # ONLY the confirmed attack caller.
    # cmp dword ptr [esp+0x24], ATTACK_RETURN
    b += b"\x81\x7C\x24\x24" + p32(ATTACK_RETURN)

    jne_return = len(b)
    b += b"\x0F\x85\x00\x00\x00\x00"

    # ESI = COutPacket*
    b += b"\x8B\x74\x24\x28"

    # test esi,esi
    b += b"\x85\xF6"

    jz_packet = len(b)
    b += b"\x0F\x84\x00\x00\x00\x00"

    # EDX = packet payload pointer
    b += b"\x8B\x56\x04"

    # test edx,edx
    b += b"\x85\xD2"

    jz_payload = len(b)
    b += b"\x0F\x84\x00\x00\x00\x00"

    # ECX = packet length
    b += b"\x8B\x4E\x08"

    # cmp ecx,8
    b += b"\x83\xF9\x08"

    jb_length = len(b)
    b += b"\x0F\x82\x00\x00\x00\x00"

    # cmp word ptr [edx], 002E
    b += (
        b"\x66\x81\x3A"
        + struct.pack("<H", MAGIC_OPCODE)
    )

    jne_opcode = len(b)
    b += b"\x0F\x85\x00\x00\x00\x00"

    # EDI = exact skill ID from payload +4.
    b += b"\x8B\x7A\x04"

    # ========================================================
    # MAGIC CLAW
    # ========================================================

    # cmp edi, MAGIC_CLAW_ID
    b += b"\x81\xFF" + p32(MAGIC_CLAW_ID)

    jne_not_magic = len(b)
    b += b"\x0F\x85\x00\x00\x00\x00"

    # test dword ptr [ebx+C_SKILL_MASK], SKILL_MAGIC_CLAW
    b += b"\xF7\x43" + bytes([C_SKILL_MASK]) + p32(SKILL_MAGIC_CLAW)

    jz_magic_disabled = len(b)
    b += b"\x0F\x84\x00\x00\x00\x00"

    # KEEP the existing exact packed-byte fingerprint.
    # cmp byte ptr [edx+3], 12
    b += b"\x80\x7A\x03" + bytes([MAGIC_CLAW_PACKED])

    jne_magic_packed = len(b)
    b += b"\x0F\x85\x00\x00\x00\x00"

    # inc dword ptr [ebx+C_COUNT_MAGIC]
    b += b"\xFF\x43" + bytes([C_COUNT_MAGIC])

    jmp_magic_selected = len(b)
    b += b"\xE9\x00\x00\x00\x00"

    # ========================================================
    # ICE STRIKE
    # ========================================================

    check_ice = len(b)

    # cmp edi, ICE_STRIKE_ID
    b += b"\x81\xFF" + p32(ICE_STRIKE_ID)

    jne_not_ice = len(b)
    b += b"\x0F\x85\x00\x00\x00\x00"

    # No fixed packed byte: preserve the working Ice Strike logic.
    b += b"\xF7\x43" + bytes([C_SKILL_MASK]) + p32(SKILL_ICE_STRIKE)

    jz_ice_disabled = len(b)
    b += b"\x0F\x84\x00\x00\x00\x00"

    b += b"\xFF\x43" + bytes([C_COUNT_ICE])

    jmp_ice_selected = len(b)
    b += b"\xE9\x00\x00\x00\x00"

    # ========================================================
    # CHAIN LIGHTNING
    # ========================================================

    check_chain = len(b)

    # cmp edi, CHAIN_LIGHTNING_ID
    b += b"\x81\xFF" + p32(CHAIN_LIGHTNING_ID)

    jne_not_chain = len(b)
    b += b"\x0F\x85\x00\x00\x00\x00"

    b += b"\xF7\x43" + bytes([C_SKILL_MASK]) + p32(SKILL_CHAIN_LIGHTNING)

    jz_chain_disabled = len(b)
    b += b"\x0F\x84\x00\x00\x00\x00"

    b += b"\xFF\x43" + bytes([C_COUNT_CHAIN])

    jmp_chain_selected = len(b)
    b += b"\xE9\x00\x00\x00\x00"

    # ========================================================
    # BLIZZARD
    # ========================================================

    check_blizzard = len(b)

    # cmp edi, BLIZZARD_ID
    b += b"\x81\xFF" + p32(BLIZZARD_ID)

    jne_not_blizzard = len(b)
    b += b"\x0F\x85\x00\x00\x00\x00"

    b += b"\xF7\x43" + bytes([C_SKILL_MASK]) + p32(SKILL_BLIZZARD)

    jz_blizzard_disabled = len(b)
    b += b"\x0F\x84\x00\x00\x00\x00"

    b += b"\xFF\x43" + bytes([C_COUNT_BLIZZARD])

    jmp_blizzard_selected = len(b)
    b += b"\xE9\x00\x00\x00\x00"

    # ========================================================
    # SELECTED PACKET TELEMETRY + MODE
    # ========================================================

    selected = len(b)

    # [ctrl+8] = packet
    b += b"\x89\x73\x08"

    # inc dword [ctrl+4]
    b += b"\xFF\x43\x04"

    # EAX has intentionally remained the mode value throughout
    # classification, just like the two working source versions.

    # cmp eax,1
    b += b"\x83\xF8\x01"

    je_x2 = len(b)
    b += b"\x0F\x84\x00\x00\x00\x00"

    # cmp eax,3
    b += b"\x83\xF8\x03"

    je_x4 = len(b)
    b += b"\x0F\x84\x00\x00\x00\x00"

    jmp_normal_unknown = len(b)
    b += b"\xE9\x00\x00\x00\x00"

    # ========================================================
    # X2 - unchanged replay shape
    # ========================================================

    x2 = len(b)

    b += b"\x61"       # popad
    b += b"\x9D"       # popfd

    # Preserve EBX and keep original this/ECX across calls.
    b += b"\x53"
    b += b"\x8B\xD9"

    b += b"\xFF\x74\x24\x08"
    b += b"\x8B\xCB"

    call1_x2 = len(b)
    b += b"\xE8\x00\x00\x00\x00"

    b += b"\xFF\x74\x24\x08"
    b += b"\x8B\xCB"

    call2_x2 = len(b)
    b += b"\xE8\x00\x00\x00\x00"

    b += b"\x5B"
    b += b"\xC2\x04\x00"

    # ========================================================
    # X4 - unchanged replay shape: 4 downstream calls total
    # ========================================================

    x4 = len(b)

    b += b"\x61"
    b += b"\x9D"

    b += b"\x53"
    b += b"\x8B\xD9"

    x4_calls = []

    for _ in range(4):
        b += b"\xFF\x74\x24\x08"
        b += b"\x8B\xCB"

        pos = len(b)
        b += b"\xE8\x00\x00\x00\x00"

        x4_calls.append(pos)

    b += b"\x5B"
    b += b"\xC2\x04\x00"

    # ========================================================
    # NORMAL / PASS-THROUGH
    # ========================================================

    normal = len(b)

    b += b"\x61"
    b += b"\x9D"

    normal_jmp = len(b)
    b += b"\xE9\x00\x00\x00\x00"

    # ========================================================
    # PATCH LOCAL BRANCHES
    # ========================================================

    def patch_jcc(position, destination):
        displacement = destination - (position + 6)
        b[position + 2:position + 6] = struct.pack(
            "<i",
            displacement,
        )

    def patch_local_jmp(position, destination):
        displacement = destination - (position + 5)
        b[position + 1:position + 5] = struct.pack(
            "<i",
            displacement,
        )

    # Common classification failures -> untouched pass-through.
    for pos in (
        jz_mode_off,
        jne_return,
        jz_packet,
        jz_payload,
        jb_length,
        jne_opcode,
        jz_magic_disabled,
        jne_magic_packed,
        jz_ice_disabled,
        jz_chain_disabled,
        jne_not_blizzard,
        jz_blizzard_disabled,
    ):
        patch_jcc(pos, normal)

    # Skill classifier chain.
    patch_jcc(jne_not_magic, check_ice)
    patch_jcc(jne_not_ice, check_chain)
    patch_jcc(jne_not_chain, check_blizzard)

    # Any selected skill -> shared replay mode logic.
    for pos in (
        jmp_magic_selected,
        jmp_ice_selected,
        jmp_chain_selected,
        jmp_blizzard_selected,
    ):
        patch_local_jmp(pos, selected)

    patch_jcc(je_x2, x2)
    patch_jcc(je_x4, x4)
    patch_local_jmp(jmp_normal_unknown, normal)

    # ========================================================
    # PATCH ABSOLUTE DOWNSTREAM CALLS
    # ========================================================

    def patch_absolute_call(position, destination):
        source_next = code_va + position + 5
        b[position + 1:position + 5] = rel32_bits(
            source_next,
            destination,
        )

    patch_absolute_call(call1_x2, downstream_va)
    patch_absolute_call(call2_x2, downstream_va)

    for pos in x4_calls:
        patch_absolute_call(pos, downstream_va)

    # NORMAL absolute tail JMP -> pre-existing runtime E9 target.
    source_next = code_va + normal_jmp + 5
    b[normal_jmp + 1:normal_jmp + 5] = rel32_bits(
        source_next,
        downstream_va,
    )

    return bytes(b)


# ============================================================
# TRAINER
# ============================================================


class MultiSkillReplay:
    def __init__(self):
        self.pm = pymem.Pymem(PROCESS)

        module = (
            pymem.process
            .module_from_name(
                self.pm.process_handle,
                PROCESS,
            )
        )

        if module is None:
            raise RuntimeError(
                "YunaMS.exe module niet gevonden."
            )

        self.base = int(module.lpBaseOfDll)
        self.send = SENDPACKET

        self.alloc = 0
        self.ctrl = 0
        self.patch = None

        self.installed = False
        self.closed = False

        # ----------------------------------------------------
        # Verify the exact already-confirmed attack caller.
        # ----------------------------------------------------

        attack_bytes = self.pm.read_bytes(
            ATTACK_CALL,
            5,
        )

        attack_target = decode_e8_target(
            ATTACK_CALL,
            attack_bytes,
        )

        if attack_target != self.send:
            shown = (
                f"0x{attack_target:08X}"
                if attack_target is not None
                else "INVALID"
            )

            raise RuntimeError(
                "Attack CALL verificatie mislukt.\n"
                f"Bytes: {attack_bytes.hex(' ').upper()}\n"
                f"Target: {shown}\n"
                f"Expected: 0x{self.send:08X}"
            )

        # ----------------------------------------------------
        # Preserve the existing runtime E9 chain EXACTLY.
        # ----------------------------------------------------

        self.original_entry = self.pm.read_bytes(
            self.send,
            5,
        )

        self.downstream = decode_e9_target(
            self.send,
            self.original_entry,
        )

        if self.downstream is None:
            raise RuntimeError(
                "SendPacket heeft niet de verwachte bestaande "
                "E9 runtime-chain.\n"
                "Ik overschrijf daarom niets blind.\n"
                f"Bytes: {self.original_entry.hex(' ').upper()}"
            )

        # ----------------------------------------------------
        # Allocate + write trampoline ONCE.
        # No SendPacket patch yet -> startup remains read-only
        # with respect to the executable code entry.
        # ----------------------------------------------------

        ptr = kernel32.VirtualAllocEx(
            self.pm.process_handle,
            None,
            ALLOC_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )

        if not ptr:
            raise ctypes.WinError(
                ctypes.get_last_error()
            )

        self.alloc = int(
            ctypes.cast(
                ptr,
                ctypes.c_void_p,
            ).value
        )

        self.ctrl = self.alloc + CTRL_OFF

        trampoline = build_trampoline(
            self.alloc,
            self.ctrl,
            self.downstream,
        )

        if len(trampoline) >= CTRL_OFF:
            raise RuntimeError(
                "Trampoline te groot."
            )

        self.pm.write_bytes(
            self.alloc,
            trampoline,
            len(trampoline),
        )

        self.pm.write_bytes(
            self.ctrl,
            b"\x00" * 0x100,
            0x100,
        )

        kernel32.FlushInstructionCache(
            self.pm.process_handle,
            ctypes.c_void_p(self.alloc),
            len(trampoline),
        )

        self.patch = make_entry_patch(
            self.send,
            self.alloc,
        )

    # --------------------------------------------------------
    # CONTROL
    # --------------------------------------------------------

    def set_mode(self, value):
        if value not in (0, 1, 3):
            raise ValueError(
                "mode moet 0, 1 of 3 zijn"
            )

        self.pm.write_uint(
            self.ctrl + C_MODE,
            int(value),
        )

    def set_skill_mask(self, mask):
        self.pm.write_uint(
            self.ctrl + C_SKILL_MASK,
            int(mask) & 0x0F,
        )

    def install(self, mode, skill_mask):
        if mode not in (1, 3):
            raise ValueError(
                "mode moet 1 (x2) of 3 (x4) zijn"
            )

        if not (skill_mask & 0x0F):
            raise ValueError(
                "Vink minimaal één skill aan."
            )

        # Write controls before exposing the hook.
        self.set_skill_mask(skill_mask)
        self.set_mode(mode)

        if self.installed:
            return

        current = self.pm.read_bytes(
            self.send,
            5,
        )

        if current != self.original_entry:
            # Prevent accidental activation if someone else changed
            # the entry after this program started.
            self.set_mode(0)

            raise RuntimeError(
                "SendPacket runtime entry is veranderd sinds startup.\n"
                f"startup = {self.original_entry.hex(' ').upper()}\n"
                f"current = {current.hex(' ').upper()}\n"
                "Ik overschrijf niets."
            )

        write_code_verified(
            self.pm,
            self.send,
            self.original_entry,
            self.patch,
        )

        self.installed = True

    def update_live(self, mode, skill_mask):
        """Update GUI selections while the one shared hook is active."""
        if not self.installed:
            return

        # Set mask first, mode second. If mask is empty, use mode=0 so
        # everything becomes pass-through until a skill is re-selected.
        self.set_skill_mask(skill_mask)

        if skill_mask & 0x0F:
            self.set_mode(mode)
        else:
            self.set_mode(0)

    def disable(self):
        if not self.alloc:
            return

        # First make the trampoline pass-through before restoring entry.
        try:
            self.set_mode(0)
        except Exception:
            pass

        if not self.installed:
            return

        current = self.pm.read_bytes(
            self.send,
            5,
        )

        if current == self.patch:
            write_code_verified(
                self.pm,
                self.send,
                self.patch,
                self.original_entry,
            )

        elif current == self.original_entry:
            pass

        else:
            # Same safety behaviour as the working originals: unknown
            # bytes are NEVER overwritten blindly.
            raise RuntimeError(
                "SendPacket bevat onbekende bytes; "
                "ik overschrijf ze NIET.\n"
                f"current = {current.hex(' ').upper()}"
            )

        self.installed = False

    def stats(self):
        if not self.alloc:
            return {
                "mode": 0,
                "mask": 0,
                "count": 0,
                "last": 0,
                "magic": 0,
                "ice": 0,
                "chain": 0,
                "blizzard": 0,
            }

        return {
            "mode": self.pm.read_uint(self.ctrl + C_MODE),
            "mask": self.pm.read_uint(self.ctrl + C_SKILL_MASK),
            "count": self.pm.read_uint(self.ctrl + C_COUNT),
            "last": self.pm.read_uint(self.ctrl + C_LAST_PACKET),
            "magic": self.pm.read_uint(self.ctrl + C_COUNT_MAGIC),
            "ice": self.pm.read_uint(self.ctrl + C_COUNT_ICE),
            "chain": self.pm.read_uint(self.ctrl + C_COUNT_CHAIN),
            "blizzard": self.pm.read_uint(self.ctrl + C_COUNT_BLIZZARD),
        }

    # --------------------------------------------------------
    # CLEANUP
    # --------------------------------------------------------

    def close(self):
        if self.closed:
            return

        self.closed = True

        restore_error = None

        try:
            self.disable()
        except Exception as exc:
            restore_error = exc

        # Only free our trampoline when the SendPacket entry no longer
        # points at it.  If restore failed because unknown code replaced
        # the entry, freeing is still safe because it no longer points at
        # us.  If our patch somehow remains, keep allocation alive rather
        # than leaving a dangling jump.
        can_free = True

        if self.alloc:
            try:
                current = self.pm.read_bytes(
                    self.send,
                    5,
                )

                if current == self.patch:
                    can_free = False
            except Exception:
                can_free = False

        if self.alloc and can_free:
            try:
                kernel32.VirtualFreeEx(
                    self.pm.process_handle,
                    ctypes.c_void_p(self.alloc),
                    0,
                    MEM_RELEASE,
                )
            except Exception:
                pass

            self.alloc = 0

        try:
            self.pm.close_process()
        except Exception:
            pass

        if restore_error is not None:
            raise restore_error


# ============================================================
# GUI
# ============================================================


class ReplayGUI:
    def __init__(self, root, trainer):
        self.root = root
        self.trainer = trainer
        self.closing = False

        self.root.title("YunaMS v83 - Multi Skill Replay")
        self.root.resizable(False, False)

        # Default multiplier requested by user: x4.
        self.mode_var = tk.IntVar(value=3)

        # Skills are explicit opt-in checkboxes.  Nothing is hooked until
        # the user presses AAN.  "Alles" is available for one-click use.
        self.skill_vars = {
            SKILL_MAGIC_CLAW: tk.BooleanVar(value=False),
            SKILL_ICE_STRIKE: tk.BooleanVar(value=False),
            SKILL_CHAIN_LIGHTNING: tk.BooleanVar(value=False),
            SKILL_BLIZZARD: tk.BooleanVar(value=False),
        }

        self.state_var = tk.StringVar(
            value="Gereed — hook nog niet geplaatst (pass-through)."
        )

        self.stats_var = tk.StringVar(value="Packets: 0")

        self._build()
        self._refresh_status()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.on_close,
        )

    def _build(self):
        outer = ttk.Frame(
            self.root,
            padding=14,
        )
        outer.grid(row=0, column=0, sticky="nsew")

        ttk.Label(
            outer,
            text="YunaMS v83 — Multi Skill Replay",
            font=("Segoe UI", 12, "bold"),
        ).grid(
            row=0,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(0, 8),
        )

        info = (
            f"PID {self.trainer.pm.process_id}   |   "
            f"SendPacket 0x{self.trainer.send:08X}\n"
            f"Existing E9 -> 0x{self.trainer.downstream:08X}"
        )

        ttk.Label(
            outer,
            text=info,
        ).grid(
            row=1,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(0, 10),
        )

        skills = ttk.LabelFrame(
            outer,
            text="Skills",
            padding=10,
        )
        skills.grid(
            row=2,
            column=0,
            columnspan=2,
            sticky="ew",
        )

        for row, (name, skill_id, bit) in enumerate(SKILL_INFO):
            ttk.Checkbutton(
                skills,
                text=f"{name}  ({skill_id})",
                variable=self.skill_vars[bit],
                command=self.on_selection_change,
            ).grid(
                row=row,
                column=0,
                sticky="w",
                pady=2,
            )

        button_row = ttk.Frame(skills)
        button_row.grid(
            row=len(SKILL_INFO),
            column=0,
            sticky="w",
            pady=(7, 0),
        )

        ttk.Button(
            button_row,
            text="Alles",
            command=self.select_all,
        ).grid(row=0, column=0, padx=(0, 6))

        ttk.Button(
            button_row,
            text="Geen",
            command=self.select_none,
        ).grid(row=0, column=1)

        mode = ttk.LabelFrame(
            outer,
            text="Multiplier",
            padding=10,
        )
        mode.grid(
            row=3,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(10, 0),
        )

        ttk.Radiobutton(
            mode,
            text="x2",
            variable=self.mode_var,
            value=1,
            command=self.on_selection_change,
        ).grid(row=0, column=0, padx=(0, 12))

        ttk.Radiobutton(
            mode,
            text="x4 (standaard)",
            variable=self.mode_var,
            value=3,
            command=self.on_selection_change,
        ).grid(row=0, column=1)

        controls = ttk.Frame(outer)
        controls.grid(
            row=4,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(12, 0),
        )

        ttk.Button(
            controls,
            text="AAN / toepassen",
            command=self.enable,
        ).grid(
            row=0,
            column=0,
            sticky="ew",
            padx=(0, 6),
        )

        ttk.Button(
            controls,
            text="UIT / restore",
            command=self.disable,
        ).grid(
            row=0,
            column=1,
            sticky="ew",
        )

        controls.columnconfigure(0, weight=1)
        controls.columnconfigure(1, weight=1)

        ttk.Separator(
            outer,
            orient="horizontal",
        ).grid(
            row=5,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=12,
        )

        ttk.Label(
            outer,
            textvariable=self.state_var,
        ).grid(
            row=6,
            column=0,
            columnspan=2,
            sticky="w",
        )

        ttk.Label(
            outer,
            textvariable=self.stats_var,
        ).grid(
            row=7,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(5, 0),
        )

        ttk.Label(
            outer,
            text=(
                "Magic Claw behoudt packed=0x12.  Ice Strike / "
                "Chain Lightning / Blizzard matchen op opcode + skill-ID."
            ),
            wraplength=470,
        ).grid(
            row=8,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(10, 0),
        )

    def selected_mask(self):
        mask = 0

        for bit, var in self.skill_vars.items():
            if var.get():
                mask |= bit

        return mask

    def selected_names(self):
        mask = self.selected_mask()

        return [
            name
            for name, _skill_id, bit in SKILL_INFO
            if mask & bit
        ]

    def select_all(self):
        for var in self.skill_vars.values():
            var.set(True)

        self.on_selection_change()

    def select_none(self):
        for var in self.skill_vars.values():
            var.set(False)

        self.on_selection_change()

    def on_selection_change(self):
        if not self.trainer.installed:
            return

        try:
            self.trainer.update_live(
                self.mode_var.get(),
                self.selected_mask(),
            )
        except Exception as exc:
            self.state_var.set(
                f"FOUT bij live update: {exc}"
            )

    def enable(self):
        mask = self.selected_mask()

        if not mask:
            messagebox.showwarning(
                "Geen skill geselecteerd",
                "Vink minimaal één skill aan.",
                parent=self.root,
            )
            return

        try:
            self.trainer.install(
                self.mode_var.get(),
                mask,
            )

            mode_text = (
                "x4"
                if self.mode_var.get() == 3
                else "x2"
            )

            self.state_var.set(
                f"AAN — {mode_text}: "
                + ", ".join(self.selected_names())
            )

        except Exception as exc:
            messagebox.showerror(
                "Activeren mislukt",
                str(exc),
                parent=self.root,
            )

            self.state_var.set(
                f"NIET geactiveerd — {exc}"
            )

    def disable(self):
        try:
            self.trainer.disable()
            self.state_var.set(
                "UIT — originele SendPacket E9 hersteld."
            )

        except Exception as exc:
            messagebox.showerror(
                "Restore mislukt",
                str(exc),
                parent=self.root,
            )

            self.state_var.set(
                f"RESTORE FOUT — {exc}"
            )

    def _refresh_status(self):
        if self.closing:
            return

        try:
            s = self.trainer.stats()

            mode_name = {
                0: "OFF",
                1: "x2",
                3: "x4",
            }.get(s["mode"], str(s["mode"]))

            self.stats_var.set(
                f"Mode {mode_name} | totaal {s['count']} | "
                f"MC {s['magic']} | Ice {s['ice']} | "
                f"CL {s['chain']} | Blizzard {s['blizzard']} | "
                f"last 0x{s['last']:08X}"
            )

        except Exception as exc:
            self.stats_var.set(
                f"Status niet leesbaar: {exc}"
            )

        self.root.after(
            500,
            self._refresh_status,
        )

    def on_close(self):
        if self.closing:
            return

        self.closing = True

        try:
            self.trainer.close()
        except Exception as exc:
            messagebox.showerror(
                "Afsluiten / restore",
                str(exc),
                parent=self.root,
            )

        self.root.destroy()


# ============================================================
# MAIN
# ============================================================


def main():
    trainer = None

    root = tk.Tk()
    root.withdraw()

    try:
        trainer = MultiSkillReplay()
        atexit.register(trainer.close)

        ReplayGUI(root, trainer)
        root.deiconify()
        root.mainloop()

    except Exception as exc:
        messagebox.showerror(
            "YunaMS v83 Multi Skill Replay",
            str(exc),
            parent=root,
        )

        if trainer is not None:
            try:
                trainer.close()
            except Exception:
                pass

        try:
            root.destroy()
        except Exception:
            pass


if __name__ == "__main__":
    main()
