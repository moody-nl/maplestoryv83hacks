import atexit
import ctypes
import ctypes.wintypes as wt
import struct
import time

import pymem
import pymem.process


# ============================================================
# YUNAMS v83
# ============================================================

PROCESS = "YunaMS.exe"

IMAGE_BASE = 0x00400000

SENDPACKET = 0x0049637B

ATTACK_CALL = 0x0095710A
ATTACK_RETURN = 0x0095710F


# ============================================================
# ICE STRIKE - v83 MAGIC ATTACK
# ============================================================

ICE_OPCODE = 0x002E
ICE_STRIKE_ID = 2211002


# ============================================================
# HOTKEYS
# ============================================================

VK_F7 = 0x76
VK_F8 = 0x77
VK_F12 = 0x7B


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

# ctrl + 0x00 = mode
#                0 = pass-through
#                3 = x4
#
# ctrl + 0x04 = Ice Strike packets intercepted
# ctrl + 0x08 = last COutPacket*
C_MODE = 0x00
C_COUNT = 0x04
C_LAST_PACKET = 0x08


kernel32 = ctypes.WinDLL(
    "kernel32",
    use_last_error=True,
)

user32 = ctypes.WinDLL(
    "user32",
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


user32.GetAsyncKeyState.argtypes = [
    ctypes.c_int,
]

user32.GetAsyncKeyState.restype = ctypes.c_short


# ============================================================
# HELPERS
# ============================================================

def p32(value):
    return struct.pack(
        "<I",
        value & 0xFFFFFFFF,
    )


def rel32_bits(source_next, destination):
    """
    Encode x86 relative CALL/JMP displacement.
    """
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
    Entry ABI, al eerder vastgesteld:

        ECX     = CClientSocket*
        [ESP]   = caller return
        [ESP+4] = COutPacket*

    COutPacket:
        +4 = payload pointer
        +8 = payload length

    Alleen packet:

        caller return = 0x0095710F
        opcode        = 0x002E
        skill         = 2211002 (Ice Strike)

    wordt herhaald.

    mode=3 -> downstream 4 keer totaal

    Andere packets gaan ongewijzigd naar de bestaande E9-chain.
    """

    b = bytearray()

    # --------------------------------------------------------
    # Save COMPLETE entry state.
    #
    # pushfd = 4 bytes
    # pushad = 32 bytes
    #
    # Daarna:
    #
    # [esp+24] = originele return address
    # [esp+28] = originele COutPacket*
    # [esp+18] = originele ECX
    # --------------------------------------------------------

    b += b"\x9C"       # pushfd
    b += b"\x60"       # pushad

    # EBX = ctrl block
    b += b"\xBB" + p32(
        ctrl_va
    )

    # EAX = mode
    b += b"\x8B\x03"

    # test eax,eax
    b += b"\x85\xC0"

    jz_mode_off = len(b)
    b += b"\x0F\x84\x00\x00\x00\x00"

    # --------------------------------------------------------
    # ONLY the confirmed attack caller.
    #
    # cmp dword ptr [esp+24], ATTACK_RETURN
    # --------------------------------------------------------

    b += (
        b"\x81\x7C\x24\x24"
        + p32(ATTACK_RETURN)
    )

    jne_return = len(b)
    b += b"\x0F\x85\x00\x00\x00\x00"

    # --------------------------------------------------------
    # ESI = COutPacket*
    # --------------------------------------------------------

    b += b"\x8B\x74\x24\x28"

    # test esi,esi
    b += b"\x85\xF6"

    jz_packet = len(b)
    b += b"\x0F\x84\x00\x00\x00\x00"

    # --------------------------------------------------------
    # EDX = packet payload pointer
    # ECX = packet length
    # --------------------------------------------------------

    b += b"\x8B\x56\x04"       # mov edx,[esi+4]

    b += b"\x85\xD2"           # test edx,edx

    jz_payload = len(b)
    b += b"\x0F\x84\x00\x00\x00\x00"

    b += b"\x8B\x4E\x08"       # mov ecx,[esi+8]

    # cmp ecx,8
    b += b"\x83\xF9\x08"

    jb_length = len(b)
    b += b"\x0F\x82\x00\x00\x00\x00"

    # --------------------------------------------------------
    # Ice Strike fingerprint.
    #
    # payload:
    #   +0 WORD  magic attack opcode (0x002E)
    #   +3 BYTE  dynamic target/hit packed value
    #   +4 DWORD skill id (2211002)
    #
    # IMPORTANT:
    # We deliberately do NOT require one exact packed byte here.
    # Ice Strike can legitimately hit fewer than its max target count,
    # so the high nibble changes with the number of mobs actually hit.
    # Opcode + exact skill ID + confirmed magic-attack caller are enough.
    # --------------------------------------------------------

    # cmp word ptr [edx], 002E
    b += (
        b"\x66\x81\x3A"
        + struct.pack(
            "<H",
            ICE_OPCODE,
        )
    )

    jne_opcode = len(b)
    b += b"\x0F\x85\x00\x00\x00\x00"

    # cmp dword ptr [edx+4],2211002
    b += (
        b"\x81\x7A\x04"
        + p32(
            ICE_STRIKE_ID
        )
    )

    jne_skill = len(b)
    b += b"\x0F\x85\x00\x00\x00\x00"

    # --------------------------------------------------------
    # Telemetry
    # --------------------------------------------------------

    # [ctrl+8] = packet
    b += b"\x89\x73\x08"

    # inc dword [ctrl+4]
    b += b"\xFF\x43\x04"

    # --------------------------------------------------------
    # MODE
    # --------------------------------------------------------

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
    # X2
    # ========================================================

    x2 = len(b)

    # Restore genuine SendPacket entry state.
    b += b"\x61"       # popad
    b += b"\x9D"       # popfd

    # Save original EBX.
    #
    # We use EBX to keep the original 'this'/ECX across
    # repeated calls. EBX is callee-saved by x86 thiscall.
    b += b"\x53"       # push ebx
    b += b"\x8B\xD9"   # mov ebx,ecx

    # --------------------------------------------------------
    # SEND #1
    #
    # Current stack:
    #
    # [esp+0] saved EBX
    # [esp+4] original caller return
    # [esp+8] original COutPacket*
    # --------------------------------------------------------

    b += b"\xFF\x74\x24\x08"
    b += b"\x8B\xCB"

    call1_x2 = len(b)
    b += b"\xE8\x00\x00\x00\x00"

    # SEND #2
    b += b"\xFF\x74\x24\x08"
    b += b"\x8B\xCB"

    call2_x2 = len(b)
    b += b"\xE8\x00\x00\x00\x00"

    # Restore original EBX.
    b += b"\x5B"

    # Return to original caller and clean its original
    # COutPacket argument.
    b += b"\xC2\x04\x00"


    # ========================================================
    # X4
    # ========================================================

    x4 = len(b)

    b += b"\x61"
    b += b"\x9D"

    b += b"\x53"
    b += b"\x8B\xD9"

    x4_calls = []

    for _ in range(4):
        # push original packet
        b += b"\xFF\x74\x24\x08"

        # restore socket this pointer
        b += b"\x8B\xCB"

        pos = len(b)
        b += b"\xE8\x00\x00\x00\x00"

        x4_calls.append(
            pos
        )

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

    def patch_jcc(
        position,
        destination,
    ):
        displacement = (
            destination
            - (
                position
                + 6
            )
        )

        b[
            position + 2:
            position + 6
        ] = struct.pack(
            "<i",
            displacement,
        )

    def patch_local_jmp(
        position,
        destination,
    ):
        displacement = (
            destination
            - (
                position
                + 5
            )
        )

        b[
            position + 1:
            position + 5
        ] = struct.pack(
            "<i",
            displacement,
        )

    # All failed classifications -> normal path.
    for pos in (
        jz_mode_off,
        jne_return,
        jz_packet,
        jz_payload,
        jb_length,
        jne_opcode,
        jne_skill,
    ):
        patch_jcc(
            pos,
            normal,
        )

    patch_jcc(
        je_x2,
        x2,
    )

    patch_jcc(
        je_x4,
        x4,
    )

    patch_local_jmp(
        jmp_normal_unknown,
        normal,
    )


    # ========================================================
    # PATCH ABSOLUTE DOWNSTREAM CALLS
    # ========================================================

    def patch_absolute_call(
        position,
        destination,
    ):
        source_next = (
            code_va
            + position
            + 5
        )

        b[
            position + 1:
            position + 5
        ] = rel32_bits(
            source_next,
            destination,
        )

    patch_absolute_call(
        call1_x2,
        downstream_va,
    )

    patch_absolute_call(
        call2_x2,
        downstream_va,
    )

    for pos in x4_calls:
        patch_absolute_call(
            pos,
            downstream_va,
        )


    # ========================================================
    # NORMAL ABSOLUTE TAIL JMP
    # ========================================================

    source_next = (
        code_va
        + normal_jmp
        + 5
    )

    b[
        normal_jmp + 1:
        normal_jmp + 5
    ] = rel32_bits(
        source_next,
        downstream_va,
    )

    return bytes(b)


# ============================================================
# TRAINER
# ============================================================

class IceStrikeReplay:
    def __init__(self):
        self.pm = pymem.Pymem(
            PROCESS
        )

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

        self.base = int(
            module.lpBaseOfDll
        )

        self.send = SENDPACKET

        self.alloc = 0
        self.ctrl = 0

        self.patch = None

        self.installed = False
        self.closed = False

        # ----------------------------------------------------
        # Verify attack caller.
        # ----------------------------------------------------

        attack_bytes = self.pm.read_bytes(
            ATTACK_CALL,
            5,
        )

        attack_target = decode_e8_target(
            ATTACK_CALL,
            attack_bytes,
        )

        print()
        print(
            "Attack CALL bytes:",
            attack_bytes.hex(
                " "
            ).upper(),
        )

        print(
            f"Attack CALL -> "
            f"0x{attack_target:08X}"
            if attack_target is not None
            else
            "Attack CALL -> INVALID"
        )

        if attack_target != self.send:
            raise RuntimeError(
                "0x0095710A wijst niet naar "
                "0x0049637B."
            )

        print(
            "[+] Attack -> SendPacket klopt."
        )

        # ----------------------------------------------------
        # IMPORTANT FIX:
        #
        # Preserve existing runtime E9 chain.
        # ----------------------------------------------------

        self.original_entry = (
            self.pm.read_bytes(
                self.send,
                5,
            )
        )

        print()
        print(
            "=== SendPacket runtime entry ==="
        )

        print(
            "Current:",
            self.original_entry.hex(
                " "
            ).upper(),
        )

        self.downstream = (
            decode_e9_target(
                self.send,
                self.original_entry,
            )
        )

        if self.downstream is None:
            raise RuntimeError(
                "\nSendPacket heeft niet de "
                "verwachte bestaande E9 runtime-chain.\n"
                "Ik overschrijf daarom niets blind.\n"
                f"Bytes: "
                f"{self.original_entry.hex(' ').upper()}"
            )

        print(
            f"[+] Existing E9 target = "
            f"0x{self.downstream:08X}"
        )

        # ----------------------------------------------------
        # Allocate trampoline once.
        # NO SendPacket patch yet.
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

        self.ctrl = (
            self.alloc
            + CTRL_OFF
        )

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
            ctypes.c_void_p(
                self.alloc
            ),
            len(trampoline),
        )

        self.patch = make_entry_patch(
            self.send,
            self.alloc,
        )

        print()
        print(
            f"[+] trampoline = "
            f"0x{self.alloc:08X}"
        )

        print(
            f"[+] ctrl       = "
            f"0x{self.ctrl:08X}"
        )

        print()
        print(
            "Hook is NOG NIET geplaatst."
        )

        print(
            "F7 installeert hem pas."
        )


    # --------------------------------------------------------
    # CONTROL
    # --------------------------------------------------------

    def set_mode(self, value):
        self.pm.write_uint(
            self.ctrl + C_MODE,
            int(value),
        )


    def install(self, mode):
        if mode not in (
            1,
            3,
        ):
            raise ValueError(
                "mode moet 1 of 3 zijn"
            )

        self.set_mode(
            mode
        )

        if self.installed:
            return

        current = self.pm.read_bytes(
            self.send,
            5,
        )

        if current != self.original_entry:
            raise RuntimeError(
                "\nSendPacket runtime entry "
                "is veranderd sinds startup.\n"
                f"startup = "
                f"{self.original_entry.hex(' ').upper()}\n"
                f"current = "
                f"{current.hex(' ').upper()}\n"
                "Ik overschrijf niets."
            )

        write_code_verified(
            self.pm,
            self.send,
            self.original_entry,
            self.patch,
        )

        self.installed = True


    def enable_x2(self):
        self.install(
            1
        )

        print()
        print(
            "=========================================="
        )

        print(
            "Ice Strike x2 AAN"
        )

        print(
            "1 normaal packet + 1 replay"
        )

        print(
            "=========================================="
        )


    def enable_x4(self):
        self.install(
            3
        )

        print()
        print(
            "=========================================="
        )

        print(
            "Ice Strike x4 AAN"
        )

        print(
            "1 normaal packet + 3 replays"
        )

        print(
            "=========================================="
        )


    def disable(self):
        if not self.alloc:
            return

        try:
            self.set_mode(
                0
            )
        except Exception:
            pass

        if not self.installed:
            print()
            print(
                "[+] Al OFF."
            )

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

            print()
            print(
                "[+] Originele runtime E9 "
                "exact hersteld:"
            )

            print(
                "    "
                + self.original_entry.hex(
                    " "
                ).upper()
            )

        elif current == self.original_entry:

            print()
            print(
                "[+] SendPacket was al hersteld."
            )

        else:

            print()
            print(
                "[!] SendPacket bevat onbekende "
                "bytes."
            )

            print(
                "    Ik overschrijf ze NIET."
            )

            print(
                "    current:",
                current.hex(
                    " "
                ).upper(),
            )

        self.installed = False


    def stats(self):
        if not self.alloc:
            return

        try:
            mode = self.pm.read_uint(
                self.ctrl + C_MODE
            )

            count = self.pm.read_uint(
                self.ctrl + C_COUNT
            )

            packet = self.pm.read_uint(
                self.ctrl
                + C_LAST_PACKET
            )

            names = {
                0: "OFF",
                1: "x2",
                3: "x4",
            }

            print(
                f"[status] "
                f"{names.get(mode, mode)} | "
                f"IceStrike packets={count} | "
                f"last=0x{packet:08X}"
            )

        except Exception:
            pass


    # --------------------------------------------------------
    # CLEANUP
    # --------------------------------------------------------

    def close(self):
        if self.closed:
            return

        self.closed = True

        try:
            self.disable()
        except Exception as exc:
            print(
                f"[!] Restore fout: {exc}"
            )

        if self.alloc:

            try:
                kernel32.VirtualFreeEx(
                    self.pm.process_handle,
                    ctypes.c_void_p(
                        self.alloc
                    ),
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


# ============================================================
# HOTKEY
# ============================================================

def key_event(
    vk,
    old_state,
):
    down = bool(
        user32.GetAsyncKeyState(
            vk
        )
        & 0x8000
    )

    pressed = (
        down
        and not old_state
    )

    return (
        down,
        pressed,
    )


# ============================================================
# MAIN
# ============================================================

def main():
    print()
    print(
        "======================================================"
    )

    print(
        " YunaMS v83 Ice Strike x4"
    )

    print(
        " mapleboyx4.dll packet-replay method"
    )

    print(
        "======================================================"
    )

    print()
    print(
        "F7  = Ice Strike x4 AAN (3 extra packets; 4 totaal)"
    )

    print(
        "F8  = OFF / restore original SendPacket E9"
    )

    print(
        "F12 = restore + exit"
    )

    print()

    trainer = IceStrikeReplay()

    atexit.register(
        trainer.close
    )

    print()
    print(
        f"PID         = "
        f"{trainer.pm.process_id}"
    )

    print(
        f"Base        = "
        f"0x{trainer.base:08X}"
    )

    print(
        f"SendPacket  = "
        f"0x{trainer.send:08X}"
    )

    print(
        f"Old E9 ->     "
        f"0x{trainer.downstream:08X}"
    )

    print(
        f"Attack call = "
        f"0x{ATTACK_CALL:08X}"
    )

    print()
    print(
        "Klaar. F7 = AAN, F8 = UIT."
    )

    states = {
        VK_F7: False,
        VK_F8: False,
        VK_F12: False,
    }

    last_stats = time.monotonic()

    try:
        while True:

            for vk in list(
                states
            ):
                (
                    states[vk],
                    pressed,
                ) = key_event(
                    vk,
                    states[vk],
                )

                if not pressed:
                    continue

                try:
                    if vk == VK_F7:
                        trainer.enable_x4()

                    elif vk == VK_F8:
                        trainer.disable()

                    elif vk == VK_F12:
                        print(
                            "\nF12 — restoring..."
                        )

                        trainer.close()

                        return

                except Exception as exc:
                    print()
                    print(
                        "[ERROR]",
                        type(exc).__name__,
                    )

                    print(
                        exc
                    )

            now = time.monotonic()

            if (
                trainer.installed
                and
                now - last_stats >= 2.0
            ):
                trainer.stats()

                last_stats = now

            time.sleep(
                0.02
            )

    except KeyboardInterrupt:

        print(
            "\nCtrl+C — restoring..."
        )

    finally:
        trainer.close()


if __name__ == "__main__":
    main()