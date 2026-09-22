import ctypes
import ctypes.wintypes
import struct
import time
import threading
import tkinter as tk
from tkinter import ttk, simpledialog
import json
import os
import glob
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter

import pymem
import pymem.process

ctypes.windll.kernel32.VirtualAllocEx.restype = ctypes.c_void_p


TARGET = "Kuro.exe"

# Confirmed CMob signature
VT0_RVA = 0x6F8270
VT1_RVA = 0x6F824C
VT2_RVA = 0x6F8248

# Confirmed secure OID
OID_A_OFF = 0x17C
OID_B_OFF = 0x180
OID_CHECK_OFF = 0x184

# Confirmed CMob position
MOB_X_OFF = 0x510
MOB_Y_OFF = 0x514
MOB_PREV_X_OFF = 0x518
MOB_PREV_Y_OFF = 0x51C

# Confirmed character root / position
CHAR_ROOT_RVA = 0x7ED788
CHAR_X_OFF = 0x5D4
CHAR_Y_OFF = 0x5D8

# VIDEO SETTINGS
RUN_SECONDS = 75.0

BODY_PTR_OFF = 0x4C0   # CMob+0x470 subobject + 0x50

BODY_X1_OFF = 0x54
BODY_Y1_OFF = 0x58
BODY_X2_OFF = 0x5C
BODY_Y2_OFF = 0x60

# Put every mob 3 pixels to the right of the character.
# This satisfies your <= 5 pixel requirement.
FRONT_X = -3

# Keep exactly the same Y as the character.
FRONT_Y = 0

# Very aggressive hold.
INTERVAL = 0.001

# Read-only discovery runs beside the proven 1 ms hold loop.  A synchronous
# full-process scan used to pause that loop and only refreshed every 2 seconds.
# A full private-memory scan is expensive.  It runs less often than the 1 ms
# hold loop so discovery cannot starve position maintenance.
RESCAN_SECONDS = 5.0

# Optional read-only-result attack construction telemetry.  Enabling it
# temporarily replaces one validated instruction with a logging trampoline;
# it never changes target limits, packet fields, or server traffic.
IMAGE_BASE = 0x00400000
THUNDER_BOLT_ID = 2201005
PREDISPATCH_RVA = 0x00957103 - IMAGE_BASE
PREDISPATCH_ORIGINAL = bytes.fromhex("8D 85 74 FF FF FF")
TELEMETRY_DATA_OFFSET = 0x180
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000

# Read-only species/type fingerprint candidates. These four CMob fields were
# stable in the earlier probe and split the sampled mobs into repeatable groups.
# They are used only as a local type fingerprint, NOT claimed to be the actual
# Maple mob template ID.
TYPE_FP_OFFSETS = (0x1A0, 0x1C4, 0x1F4, 0x204)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MOB_LABELS_FILE = os.path.join(SCRIPT_DIR, "kuro_mob_labels.json")
ATTACK_TELEMETRY_FILE = os.path.join(SCRIPT_DIR, "kuro_vac_v3_attacks.jsonl")
KURO_WZ_URL = "https://playkuro.com/database/wz-data.json"
KURO_SERVER_URL = "https://playkuro.com/database/server-data.json"
KURO_ITEM_INDEX_URL = "https://playkuro.com/database/item-index.json"
KURO_DB_CACHE = os.path.join(SCRIPT_DIR, "kuro_database_cache.json")
KURO_LOCAL_FILES = {
    "wz": os.path.join(SCRIPT_DIR, "wz-data.json"),
    "server": os.path.join(SCRIPT_DIR, "server-data.json"),
    "items": os.path.join(SCRIPT_DIR, "item-index.json"),
}
# +0x188 was species-grouped in earlier read-only probes (few unique values for many CMobs).
# We treat it as the primary template/species-object candidate and only READ from it.
SPECIES_PTR_OFF = 0x188
SPECIES_SCAN_BYTES = 0x300

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


def _protect(handle, address, size, protection):
    old = ctypes.c_ulong()
    if not ctypes.windll.kernel32.VirtualProtectEx(
            handle, ctypes.c_void_p(address), size, protection, ctypes.byref(old)):
        raise ctypes.WinError()
    return old.value


def _write_code_verified(pm, address, expected, replacement):
    actual = pm.read_bytes(address, len(expected))
    if actual != expected:
        raise RuntimeError(f"byte validation failed at 0x{address:08X}: {actual.hex(' ')}")
    old = _protect(pm.process_handle, address, len(replacement), PAGE_EXECUTE_READWRITE)
    try:
        pm.write_bytes(address, replacement, len(replacement))
        ctypes.windll.kernel32.FlushInstructionCache(
            pm.process_handle, ctypes.c_void_p(address), len(replacement))
    finally:
        _protect(pm.process_handle, address, len(replacement), old)
    if pm.read_bytes(address, len(replacement)) != replacement:
        raise RuntimeError("code write verification failed")


def _rel32(source_after, destination):
    return struct.pack("<i", destination - source_after)


def _build_attack_probe(code_base, return_address):
    """Log sequence, payload length and first 16 payload bytes."""
    data = code_base + TELEMETRY_DATA_OFFSET
    out = bytearray(b"\x9C\x60")                 # pushfd; pushad
    out += b"\x8B\x85\x78\xFF\xFF\xFF"        # eax=[ebp-88], payload
    out += b"\x8B\xC8"                           # ecx=eax
    out += b"\x8B\x85\x7C\xFF\xFF\xFF"        # eax=[ebp-84], length
    out += b"\xA3" + struct.pack("<I", data + 4)
    for displacement, destination in ((0, 8), (4, 12), (8, 16), (12, 20)):
        out += b"\x8B\x41" + bytes([displacement])
        out += b"\xA3" + struct.pack("<I", data + destination)
    out += b"\xFF\x05" + struct.pack("<I", data)  # inc sequence
    out += b"\x61\x9D"                           # popad; popfd
    out += PREDISPATCH_ORIGINAL
    jump_at = code_base + len(out)
    out += b"\xE9" + _rel32(jump_at + 5, return_address)
    if len(out) >= TELEMETRY_DATA_OFFSET:
        raise RuntimeError("attack probe overlaps data")
    return bytes(out)


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


def rol32(v, n):
    v &= 0xFFFFFFFF
    n &= 31

    if not n:
        return v

    return (
        (v << n)
        | (v >> (32 - n))
    ) & 0xFFFFFFFF


def ror32(v, n):
    v &= 0xFFFFFFFF
    n &= 31

    if not n:
        return v

    return (
        (v >> n)
        | (v << (32 - n))
    ) & 0xFFFFFFFF


def secure_checksum(a, b):
    return (
        ror32(
            a ^ 0xBAADF00D,
            5
        )
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


def read_type_fingerprint(pm, mob):
    vals = []
    for off in TYPE_FP_OFFSETS:
        v = read_u32(pm, mob + off)
        if v is None:
            return None
        vals.append(v & 0xFFFFFFFF)
    return tuple(vals)


def fp_key(fp):
    if not fp:
        return "unknown"
    return "-".join(f"{v:X}" for v in fp)




def _json_fetch(url, timeout=12):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 KuroDevRadar/1.0",
            "Accept": "application/json,text/plain,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def _as_int(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, str):
        t = v.strip()
        if t.isdigit():
            try:
                return int(t)
            except Exception:
                pass
    return None


def _pick_name(d):
    for k in ("Name", "name", "MobName", "mobName", "MonsterName", "monsterName", "DisplayName", "displayName", "display_name", "Title", "title"):
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _pick_id(d):
    for k in ("Id", "ID", "id", "MobId", "mobId", "mobID", "MonsterId", "monsterId", "monsterID", "TemplateId", "templateId", "templateID"):
        if k in d:
            n = _as_int(d.get(k))
            if n is not None:
                return n
    return None


def _extract_kuro_mobs(root):
    """Best-effort schema-independent extraction from KuroDB JSON.

    We only accept records that are in a mob/monster-labelled branch, or that use
    an explicit mobId/monsterId field. This avoids treating item/map IDs as mobs.
    """
    out = {}

    def walk(node, path=()):
        if isinstance(node, dict):
            path_l = "/".join(str(x).lower() for x in path)
            explicit_mob_key = any(k in node for k in ("mobId", "mobID", "monsterId", "monsterID"))
            mob_branch = ("mob" in path_l) or ("monster" in path_l)
            if explicit_mob_key or mob_branch:
                mid = _pick_id(node)
                name = _pick_name(node)
                # Maple/Kuro mob template IDs are positive and comfortably below 100m.
                if mid is not None and 1 <= mid < 100_000_000 and name:
                    out[mid] = name
            for k, v in node.items():
                # Common shape: {"210100": {"name": "Slime", ...}}
                if mob_branch:
                    key_id = _as_int(k)
                    if key_id is not None and isinstance(v, dict):
                        name = _pick_name(v)
                        if name and 1 <= key_id < 100_000_000:
                            out[key_id] = name
                walk(v, path + (k,))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, path + (str(i),))

    walk(root)
    return out


def _salvage_array_from_raw(raw, key, next_key=None):
    """Recover one top-level JSON array from a partially downloaded KuroDB file.

    Firefox/Cloudflare downloads can occasionally end early or contain one bad
    encoded description near the end.  The monster array itself is still complete
    in those files, so recover that exact section instead of rejecting everything.
    """
    marker = ('"' + key + '":[').encode('ascii')
    start = raw.find(marker)
    if start < 0:
        return None
    content_start = start + len(marker)

    if next_key:
        end_marker = ('],"' + next_key + '":[').encode('ascii')
        end = raw.find(end_marker, content_start)
        if end >= 0:
            blob = b'[' + raw[content_start:end] + b']'
            try:
                return json.loads(blob.decode('utf-8', errors='replace'))
            except Exception:
                pass

    # Generic bracket matcher, string-aware.
    i = content_start
    depth = 1
    in_string = False
    escaped = False
    while i < len(raw):
        b = raw[i]
        if in_string:
            if escaped:
                escaped = False
            elif b == 0x5C:  # backslash
                escaped = True
            elif b == 0x22:  # quote
                in_string = False
        else:
            if b == 0x22:
                in_string = True
            elif b == 0x5B:  # [
                depth += 1
            elif b == 0x5D:  # ]
                depth -= 1
                if depth == 0:
                    blob = b'[' + raw[content_start:i] + b']'
                    return json.loads(blob.decode('utf-8', errors='replace'))
        i += 1
    return None


def _json_load_file(path):
    """Normal JSON load, with a Kuro WZ salvage path for partial browser saves."""
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f), False
    except Exception as normal_error:
        with open(path, "rb") as f:
            raw = f.read()
        head = raw[:512].lstrip().lower()
        if head.startswith(b'<!doctype html') or b'<html' in head:
            raise ValueError('Cloudflare/HTML response, geen JSON') from normal_error

        monsters = _salvage_array_from_raw(raw, 'monsters', 'maps')
        if isinstance(monsters, list) and monsters:
            # Enough for the current mob resolver. Keep the shape identical to the
            # real KuroDB top-level object so _extract_kuro_mobs can walk it.
            return {"monsters": monsters, "_salvaged": True}, True
        raise normal_error


def _local_candidates(key):
    exact = KURO_LOCAL_FILES[key]
    candidates = []
    if os.path.exists(exact):
        candidates.append(exact)
    stem = {
        "wz": "wz-data*.json",
        "server": "server-data*.json",
        "items": "item-index*.json",
    }[key]
    for p in glob.glob(os.path.join(SCRIPT_DIR, stem)):
        if p not in candidates:
            candidates.append(p)
    # Prefer the largest response: a Cloudflare challenge is only a few KB while
    # the real Kuro WZ response is several MB.
    candidates.sort(key=lambda p: os.path.getsize(p) if os.path.exists(p) else 0, reverse=True)
    return candidates


def load_kuro_db():
    """Load KuroDB, preferring JSON files next to this script.

    Order per dataset: local file -> live URL -> combined cache. This matters when
    the GUI is started elevated from another working directory: files are resolved
    relative to __file__, not the PowerShell current directory.
    """
    cache = {}
    try:
        if os.path.exists(KURO_DB_CACHE):
            cache, _ = _json_load_file(KURO_DB_CACHE)
    except Exception:
        cache = {}

    fetched = {}
    used = []
    errors = []
    for key, url in (("wz", KURO_WZ_URL), ("server", KURO_SERVER_URL), ("items", KURO_ITEM_INDEX_URL)):
        local_loaded = False
        for local_path in _local_candidates(key):
            try:
                payload, salvaged = _json_load_file(local_path)
                fetched[key] = payload
                if salvaged:
                    recovered = len(payload.get("monsters", [])) if isinstance(payload, dict) else 0
                    used.append(f"{key}=local-salvaged({recovered})")
                else:
                    used.append(f"{key}=local")
                local_loaded = True
                break
            except Exception as e:
                errors.append(f"{os.path.basename(local_path)}: {e}")
        if local_loaded:
            continue

        try:
            fetched[key] = _json_fetch(url)
            used.append(f"{key}=live")
            continue
        except Exception as e:
            errors.append(f"{key} live: {e}")

        if isinstance(cache, dict) and key in cache:
            fetched[key] = cache[key]
            used.append(f"{key}=cache")

    if fetched:
        try:
            with open(KURO_DB_CACHE, "w", encoding="utf-8") as f:
                json.dump(fetched, f, ensure_ascii=False)
        except Exception:
            pass

    mobs = {}
    for key in ("wz", "server", "items"):
        if key in fetched:
            mobs.update(_extract_kuro_mobs(fetched[key]))

    if mobs:
        source = ", ".join(used) if used else "KuroDB geladen"
    elif fetched:
        source = "JSON geladen maar 0 mob records herkend"
    else:
        source = "KuroDB niet geladen"
    return mobs, source, errors


# Pointer-like CMob members worth checking read-only for a template/spec object.
# +0x188 is the strongest species-group candidate from the earlier probe; the
# others are fallback object links. We never write through these pointers.
SPECIES_PTR_CANDIDATES = (0x188, 0x120, 0x434, 0x4E0, 0x50C)
CMOB_ID_SCAN_BYTES = 0x548
SPECIES_SCAN_BYTES = 0x500


def _scan_blob_for_mob_ids(blob, mob_db):
    hits = []
    for off in range(0, len(blob) - 3, 4):
        v = struct.unpack_from("<I", blob, off)[0]
        if v in mob_db:
            hits.append((off, v))
    return hits


def resolve_kuro_mob_id(pm, mob, mob_db, template_cache):
    """Read-only Kuro species resolver using the official KuroDB ID set.

    Resolution rules are deliberately conservative: return an ID only when all
    exact matches found in the CMob + candidate child objects agree on one mob ID.
    Otherwise leave it Unknown instead of displaying a wrong monster name.
    """
    if not mob_db:
        return None

    # First inspect the CMob object itself; some builds cache the template ID directly.
    try:
        blob = pm.read_bytes(mob, CMOB_ID_SCAN_BYTES)
    except Exception:
        blob = b""
    hits = _scan_blob_for_mob_ids(blob, mob_db) if blob else []

    for poff in SPECIES_PTR_CANDIDATES:
        ptr = read_u32(pm, mob + poff)
        if not ptr or ptr < 0x10000 or ptr >= 0x7FFFFFFF:
            continue
        cache_key = (poff, ptr)
        if cache_key in template_cache:
            cached = template_cache[cache_key]
            if cached is not None:
                hits.append((0x10000 + poff, cached))
            continue
        try:
            child = pm.read_bytes(ptr, SPECIES_SCAN_BYTES)
        except Exception:
            template_cache[cache_key] = None
            continue
        child_hits = _scan_blob_for_mob_ids(child, mob_db)
        uniq_child = sorted({v for _, v in child_hits})
        child_result = uniq_child[0] if len(uniq_child) == 1 else None
        template_cache[cache_key] = child_result
        if child_result is not None:
            hits.append((0x10000 + poff, child_result))

    uniq = sorted({v for _, v in hits})
    return uniq[0] if len(uniq) == 1 else None

def iter_regions(pm):
    mbi = MBI()
    addr = 0

    while addr < 0x7FFFFFFF:
        result = ctypes.windll.kernel32.VirtualQueryEx(
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
            and mbi.Type == MEM_PRIVATE
            and protect in WRITABLE
            and 0 < size <= 32 * 1024 * 1024
        ):
            yield base, size

        if size <= 0:
            break

        addr = base + size


def scan_sig(pm, sig):
    hits = []

    for base, size in iter_regions(pm):
        try:
            data = pm.read_bytes(
                base,
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

            address = base + pos

            if address % 4 == 0:
                hits.append(address)

            pos += 4

    return hits


def get_character(pm, base):
    ptr = read_u32(
        pm,
        base + CHAR_ROOT_RVA
    )

    if not ptr:
        return None

    x = read_i32(
        pm,
        ptr + CHAR_X_OFF
    )

    y = read_i32(
        pm,
        ptr + CHAR_Y_OFF
    )

    if x is None or y is None:
        return None

    return ptr, x, y


def scan_mobs(pm, base):
    sig = struct.pack(
        "<III",
        base + VT0_RVA,
        base + VT1_RVA,
        base + VT2_RVA,
    )

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

        x = read_i32(
            pm,
            mob + MOB_X_OFF
        )

        y = read_i32(
            pm,
            mob + MOB_Y_OFF
        )

        if x is None or y is None:
            continue

        if not (
            -30000 <= x <= 30000
            and
            -30000 <= y <= 30000
        ):
            continue

        result[oid] = mob

    return result


def set_hi16(value32, new16):
    return (
        (value32 & 0x0000FFFF)
        | ((new16 & 0xFFFF) << 16)
    )


def set_lo16(value32, new16):
    return (
        (value32 & 0xFFFF0000)
        | (new16 & 0xFFFF)
    )


def write_position(pm, mob, x, y):
    #
    # 1. CMob current + previous position
    #
    pm.write_int(
        mob + MOB_X_OFF,
        x
    )

    pm.write_int(
        mob + MOB_Y_OFF,
        y
    )

    pm.write_int(
        mob + MOB_PREV_X_OFF,
        x
    )

    pm.write_int(
        mob + MOB_PREV_Y_OFF,
        y
    )

    #
    # 2. Internal child position object.
    #
    # CMob + 0x470 is the embedded physical/interface
    # object; +0x50 from there gives the child pointer:
    #
    # CMob + 0x4C0
    #
    body = read_u32(
        pm,
        mob + 0x4C0
    )

    if not body:
        return False

    #
    # Earlier runtime captures showed these as
    # P1 and P2, normally separated by only a
    # few pixels while the mob moves.
    #
    # Do NOT treat them as rectangle corners.
    #
    pm.write_int(
        body + 0x54,
        x
    )

    pm.write_int(
        body + 0x58,
        y
    )

    pm.write_int(
        body + 0x5C,
        x
    )

    pm.write_int(
        body + 0x60,
        y
    )

    #
    # The same position pair is mirrored again
    # later in this object:
    #
    # +84/+88 and +8C/+90 contained the same
    # coordinate values in the captured object.
    #
    pm.write_int(
        body + 0x84,
        x
    )

    pm.write_int(
        body + 0x88,
        y
    )

    pm.write_int(
        body + 0x8C,
        x
    )

    pm.write_int(
        body + 0x90,
        y
    )

    return True



class KuroVacGUI:
    OVERLAY_W = 590
    OVERLAY_H = 320
    RADAR_RADIUS = 1600

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Kuro Control Center")
        self.root.geometry("1040x720")
        self.root.minsize(900, 620)
        self.root.configure(bg="#111827")

        self.pm = None
        self.base = None
        self.mobs = {}
        self.vac_enabled = False
        self.stop_event = threading.Event()
        self.worker = None
        self.scanner = None
        self.rescan_requested = threading.Event()
        self.mob_lock = threading.RLock()
        self.last_scan_count = 0
        self.hotkey_state = {0x74: False, 0x75: False}  # F5 / F6
        self.attack_probe_allocation = None
        self.attack_probe_patch = None
        self.attack_probe_sequence = 0
        self.attack_probe_armed = False
        self.last_tb_targets = None
        self.last_tb_hits = None
        self.attack_stats = {"off": Counter(), "stack": Counter(), "tb6": Counter()}
        self.telemetry_session = f"{int(time.time())}-{os.getpid()}"

        self.overlay = None
        self.overlay_canvas = None
        self.overlay_enabled = False
        self.overlay_clickthrough = True

        self.snapshot_lock = threading.Lock()
        self.snapshot = {
            "player": None,
            "mobs": [],
            "held": 0,
            "body_ok": 0,
        }
        self.seen_oids = set()
        self.current_oids = set()
        self.peak_mobs = 0
        self.spawn_events = 0
        self.despawn_events = 0
        self.type_fp_by_oid = {}
        self.type_name_by_key = {}
        self.mob_db, self.kurodb_source, self.kurodb_errors = load_kuro_db()
        self.vac_offset_x = FRONT_X
        self.mob_id_by_oid = {}
        self.template_id_cache = {}
        self._load_type_labels()

        self.status_var = tk.StringVar(value="Niet verbonden")
        self.mob_var = tk.StringVar(value="Mobs: 0")
        self.pos_var = tk.StringVar(value="Player: --")
        self.body_var = tk.StringVar(value="Body state: --")
        self.history_var = tk.StringVar(value="Current 0 | Peak 0 | Seen 0 | +0 / -0")
        self.near_var = tk.StringVar(value="Near player: 5px=0 | 25px=0 | 100px=0")
        self.overlay_var = tk.StringVar(value="Overlay OFF")
        self.db_var = tk.StringVar(value=f"KuroDB: {len(self.mob_db)} monster names — {self.kurodb_source}")
        self.offset_var = tk.IntVar(value=self.vac_offset_x)
        self.offset_text_var = tk.StringVar(value=self._offset_label(self.vac_offset_x))
        self.verified_var = tk.StringVar(value="Verified stack: --")
        self.attack_var = tk.StringVar(value="Laatste Thunder Bolt: --")
        self.probe_var = tk.StringVar(value="Attack telemetry UIT")
        self.comparison_var = tk.StringVar(value="Verdeling: nog geen Thunder Bolt casts")
        self.layout_var = tk.StringVar(value="stack")
        self.layout_mode = "stack"

        self._build_ui_modern()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.connect()
        self.root.after(100, self.render_overlay)
        self.root.after(60, self.poll_hotkeys)
        self.root.after(100, self.poll_attack_probe)

    def _build_ui(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("App.TFrame", background="#111827")
        style.configure("Card.TLabelframe", background="#182235", foreground="#e5e7eb")
        style.configure("Card.TLabelframe.Label", background="#111827", foreground="#93c5fd", font=("Segoe UI", 10, "bold"))
        style.configure("App.TLabel", background="#111827", foreground="#d1d5db")
        style.configure("Title.TLabel", background="#111827", foreground="#f9fafb", font=("Segoe UI Semibold", 22))
        style.configure("Sub.TLabel", background="#111827", foreground="#9ca3af")
        style.configure("Treeview", rowheight=26, background="#f8fafc", fieldbackground="#f8fafc")
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

        shell = ttk.Frame(self.root, style="App.TFrame")
        shell.pack(fill="both", expand=True)
        canvas = tk.Canvas(shell, bg="#111827", highlightthickness=0)
        scrollbar = ttk.Scrollbar(shell, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        frame = ttk.Frame(canvas, padding=22, style="App.TFrame")
        frame_window = canvas.create_window((0, 0), window=frame, anchor="nw")

        def sync_scrollregion(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def sync_width(event):
            canvas.itemconfigure(frame_window, width=event.width)

        frame.bind("<Configure>", sync_scrollregion)
        canvas.bind("<Configure>", sync_width)
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-e.delta / 120), "units"))

        ttk.Label(
            frame,
            text="KuroStory VAC Lab",
            style="Title.TLabel"
        ).pack(pady=(0, 4))

        ttk.Label(
            frame,
            text="Client-side mob position experiment • F5 aan • F6 uit",
            style="Sub.TLabel"
        ).pack(pady=(0, 14))

        for variable in (self.status_var, self.mob_var, self.body_var, self.pos_var,
                         self.history_var, self.near_var, self.overlay_var, self.db_var):
            ttk.Label(frame, textvariable=variable, style="App.TLabel").pack(pady=2)

        offset_box = ttk.LabelFrame(frame, text="VAC-positie", padding=12, style="Card.TLabelframe")
        offset_box.pack(fill="x", pady=(4, 8))
        ttk.Label(offset_box, textvariable=self.offset_text_var).pack(pady=(0, 3))
        self.offset_scale = ttk.Scale(
            offset_box, from_=-350, to=350, orient="horizontal",
            command=self._on_offset_scale
        )
        self.offset_scale.set(self.vac_offset_x)
        self.offset_scale.pack(fill="x", padx=8)
        quick = ttk.Frame(offset_box)
        quick.pack(pady=(5, 0))
        for i, (label, val) in enumerate((("Pirate -3", -3), ("Mage -80", -80), ("Mage -120", -120), ("+80", 80))):
            ttk.Button(quick, text=label, command=lambda v=val: self._set_offset(v)).grid(row=0, column=i, padx=3)

        buttons = ttk.Frame(frame, style="App.TFrame")
        buttons.pack(pady=8)

        self.on_btn = tk.Button(buttons, text="VAC AAN  [F5]", command=self.start_vac,
                                bg="#16a34a", fg="white", activebackground="#15803d",
                                relief="flat", font=("Segoe UI Semibold", 11), padx=24, pady=10)
        self.on_btn.grid(row=0, column=0, padx=6)
        self.off_btn = tk.Button(buttons, text="VAC UIT  [F6]", command=self.stop_vac,
                                 bg="#dc2626", fg="white", activebackground="#b91c1c",
                                 relief="flat", font=("Segoe UI Semibold", 11), padx=24, pady=10)
        self.off_btn.grid(row=0, column=1, padx=6)
        # Existing worker/error paths use this common status control.
        self.toggle_btn = self.on_btn

        self.overlay_btn = ttk.Button(
            buttons,
            text="OVERLAY ON",
            command=self.toggle_overlay
        )
        self.overlay_btn.grid(row=0, column=2, padx=6, ipadx=12, ipady=8)

        conn_buttons = ttk.Frame(frame)
        conn_buttons.pack(pady=6)
        self.reconnect_btn = ttk.Button(
            conn_buttons,
            text="Reconnect Kuro.exe",
            command=self.connect
        )
        self.reconnect_btn.grid(row=0, column=0, padx=5, ipadx=14, ipady=5)
        self.reload_db_btn = ttk.Button(
            conn_buttons,
            text="Reload KuroDB JSON",
            command=self.reload_kuro_db
        )
        self.reload_db_btn.grid(row=0, column=1, padx=5, ipadx=10, ipady=5)

        type_box = ttk.LabelFrame(frame, text="Monsters", padding=10, style="Card.TLabelframe")
        type_box.pack(fill="x", pady=(10, 4))
        self.type_tree = ttk.Treeview(type_box, columns=("name", "count", "fp"), show="headings", height=6)
        self.type_tree.heading("name", text="Name")
        self.type_tree.heading("count", text="Count")
        self.type_tree.heading("fp", text="Mob ID / fingerprint")
        self.type_tree.column("name", width=180, anchor="w")
        self.type_tree.column("count", width=70, anchor="center")
        self.type_tree.column("fp", width=300, anchor="w")
        self.type_tree.pack(fill="x")
        type_buttons = ttk.Frame(type_box)
        type_buttons.pack(pady=(7, 0))
        ttk.Button(type_buttons, text="Naam instellen voor onbekend type", command=self.rename_selected_type).grid(row=0, column=0, padx=5)
        ttk.Button(type_buttons, text="Reset counters", command=self.reset_counters).grid(row=0, column=1, padx=5)

        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=12)

        ttk.Label(
            frame,
            text=(
                "Overlay = transparante client-side radar boven Kuro.exe.\n"
                "Midden = speler; stippen = live CMob-objecten.\n"
                "De radar verandert geen extra game-state; alleen VAC ON schrijft geheugen.\n\n"
                "VAC-afstand is live instelbaar met de schuif; overlay toont target-afstand.\n"
                "Lokale wz-data.json/server-data.json/item-index.json naast dit script krijgen voorrang.\n\n"
                "Mobnamen worden automatisch gekoppeld aan de vaste KuroDB Mob IDs.\n"
                "Onbekend betekent dat er nog geen bewezen Mob ID in de clientstructuur is gevonden.\n"
                "Selecteer zo'n regel en gebruik 'Naam instellen' om een gecontroleerd label op te slaan."
            ),
            justify="center",
            style="Sub.TLabel"
        ).pack()

    def _build_ui_modern(self):
        """New dashboard layout; backend state and VAC writes stay separate."""
        bg, panel, panel2 = "#0b1020", "#121a2d", "#18233b"
        text, muted, cyan = "#f8fafc", "#8ea0bd", "#38bdf8"
        self.root.configure(bg=bg)
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Root.TFrame", background=bg)
        style.configure("Panel.TFrame", background=panel)
        style.configure("TNotebook", background=bg, borderwidth=0)
        style.configure("TNotebook.Tab", background=panel, foreground=muted,
                        padding=(22, 11), font=("Segoe UI Semibold", 10))
        style.map("TNotebook.Tab", background=[("selected", panel2)],
                  foreground=[("selected", text)])
        style.configure("Modern.Treeview", background=panel, fieldbackground=panel,
                        foreground=text, rowheight=30, borderwidth=0)
        style.configure("Modern.Treeview.Heading", background=panel2, foreground=cyan,
                        font=("Segoe UI Semibold", 10), relief="flat")

        root = tk.Frame(self.root, bg=bg)
        root.pack(fill="both", expand=True)

        header = tk.Frame(root, bg=bg, height=78)
        header.pack(fill="x", padx=28, pady=(20, 8))
        tk.Label(header, text="KURO", bg=bg, fg=cyan,
                 font=("Segoe UI Black", 20)).pack(side="left")
        tk.Label(header, text=" / CONTROL CENTER", bg=bg, fg=text,
                 font=("Segoe UI Semibold", 20)).pack(side="left")
        tk.Label(header, text="F5  START    F6  STOP", bg="#172554", fg="#bfdbfe",
                 padx=14, pady=7, font=("Consolas", 10, "bold")).pack(side="right")

        actionbar = tk.Frame(root, bg=panel, padx=18, pady=14)
        actionbar.pack(fill="x", padx=28, pady=(0, 14))
        self.on_btn = tk.Button(actionbar, text="▶  VAC START", command=self.start_vac,
                                bg="#16a34a", fg="white", relief="flat", bd=0,
                                activebackground="#15803d", font=("Segoe UI Semibold", 11), padx=22, pady=9)
        self.on_btn.pack(side="left", padx=(0, 8))
        self.off_btn = tk.Button(actionbar, text="■  VAC STOP", command=self.stop_vac,
                                 bg="#dc2626", fg="white", relief="flat", bd=0,
                                 activebackground="#b91c1c", font=("Segoe UI Semibold", 11), padx=22, pady=9)
        self.off_btn.pack(side="left", padx=8)
        self.toggle_btn = self.on_btn
        self.overlay_btn = tk.Button(actionbar, text="HUD TONEN", command=self.toggle_overlay,
                                     bg="#2563eb", fg="white", relief="flat", bd=0,
                                     font=("Segoe UI Semibold", 10), padx=18, pady=9)
        self.overlay_btn.pack(side="left", padx=8)
        self.probe_btn = tk.Button(actionbar, text="ATTACK METER AAN", command=self.toggle_attack_probe,
                                   bg="#7c3aed", fg="white", relief="flat", bd=0,
                                   font=("Segoe UI Semibold", 10), padx=18, pady=9)
        self.probe_btn.pack(side="left", padx=8)
        tk.Label(actionbar, textvariable=self.status_var, bg=panel, fg="#cbd5e1",
                 font=("Segoe UI", 10)).pack(side="right")

        tabs = ttk.Notebook(root)
        tabs.pack(fill="both", expand=True, padx=28, pady=(0, 24))
        dashboard = tk.Frame(tabs, bg=bg)
        monsters = tk.Frame(tabs, bg=bg)
        settings = tk.Frame(tabs, bg=bg)
        tabs.add(dashboard, text="OVERVIEW")
        tabs.add(monsters, text="MONSTERS")
        tabs.add(settings, text="SETTINGS")

        metrics = tk.Frame(dashboard, bg=bg)
        metrics.pack(fill="x", pady=18)

        def card(parent, title, variable, accent):
            box = tk.Frame(parent, bg=panel, highlightbackground="#24324d",
                           highlightthickness=1, padx=18, pady=15)
            tk.Label(box, text=title.upper(), bg=panel, fg=accent,
                     font=("Segoe UI Semibold", 9)).pack(anchor="w")
            tk.Label(box, textvariable=variable, bg=panel, fg=text,
                     font=("Segoe UI Semibold", 12), wraplength=255,
                     justify="left").pack(anchor="w", pady=(9, 0))
            return box

        card(metrics, "Mob discovery", self.mob_var, cyan).pack(side="left", fill="both", expand=True, padx=(0, 8))
        card(metrics, "Verified position", self.verified_var, "#34d399").pack(side="left", fill="both", expand=True, padx=8)
        card(metrics, "Attack construction", self.attack_var, "#c084fc").pack(side="left", fill="both", expand=True, padx=(8, 0))

        telemetry = tk.Frame(dashboard, bg=panel, padx=22, pady=18)
        telemetry.pack(fill="x", pady=(0, 14))
        tk.Label(telemetry, text="LIVE CLIENT TELEMETRY", bg=panel, fg=text,
                 font=("Segoe UI Semibold", 12)).pack(anchor="w")
        for variable in (self.body_var, self.pos_var, self.near_var,
                         self.history_var, self.probe_var, self.comparison_var):
            tk.Label(telemetry, textvariable=variable, bg=panel, fg=muted,
                     font=("Consolas", 10), anchor="w").pack(fill="x", pady=3)

        hypothesis = tk.Frame(dashboard, bg=panel2, padx=20, pady=16)
        hypothesis.pack(fill="x")
        tk.Label(hypothesis, text="POSITION LAYOUT", bg=panel2, fg=cyan,
                 font=("Segoe UI Semibold", 10)).pack(anchor="w")
        tk.Radiobutton(hypothesis, text="Exact stack — originele werkende methode",
                       variable=self.layout_var, value="stack", bg=panel2, fg=text,
                       command=self._set_layout_mode, selectcolor=bg,
                       activebackground=panel2, activeforeground=text).pack(anchor="w", pady=(8, 2))
        tk.Radiobutton(hypothesis, text="TB spread — zes kleine slots rond de speler",
                       variable=self.layout_var, value="tb6", bg=panel2, fg=text,
                       command=self._set_layout_mode, selectcolor=bg,
                       activebackground=panel2, activeforeground=text).pack(anchor="w", pady=2)

        top = tk.Frame(monsters, bg=bg)
        top.pack(fill="x", pady=(18, 10))
        tk.Label(top, text="Resolved monsters", bg=bg, fg=text,
                 font=("Segoe UI Semibold", 17)).pack(side="left")
        tk.Label(top, textvariable=self.db_var, bg=bg, fg=muted,
                 font=("Segoe UI", 9)).pack(side="right")
        self.type_tree = ttk.Treeview(monsters, columns=("name", "count", "fp"),
                                      show="headings", height=12, style="Modern.Treeview")
        for col, label, width in (("name", "NAME", 330), ("count", "COUNT", 100),
                                  ("fp", "MOB ID / FINGERPRINT", 390)):
            self.type_tree.heading(col, text=label)
            self.type_tree.column(col, width=width, anchor="w" if col != "count" else "center")
        self.type_tree.pack(fill="both", expand=True)
        mob_actions = tk.Frame(monsters, bg=bg)
        mob_actions.pack(fill="x", pady=12)
        ttk.Button(mob_actions, text="Naam instellen voor geselecteerd fingerprint",
                   command=self.rename_selected_type).pack(side="left", padx=(0, 8))
        ttk.Button(mob_actions, text="Counters resetten", command=self.reset_counters).pack(side="left")

        position = tk.Frame(settings, bg=panel, padx=22, pady=20)
        position.pack(fill="x", pady=(18, 12))
        tk.Label(position, text="VAC POSITION", bg=panel, fg=cyan,
                 font=("Segoe UI Semibold", 11)).pack(anchor="w")
        tk.Label(position, textvariable=self.offset_text_var, bg=panel, fg=text,
                 font=("Segoe UI", 11)).pack(anchor="w", pady=(8, 4))
        self.offset_scale = ttk.Scale(position, from_=-350, to=350, orient="horizontal",
                                      command=self._on_offset_scale)
        self.offset_scale.set(self.vac_offset_x)
        self.offset_scale.pack(fill="x", pady=8)
        presets = tk.Frame(position, bg=panel)
        presets.pack(anchor="w")
        for label, val in (("Pirate -3", -3), ("Mage -80", -80), ("Mage -120", -120), ("Right +80", 80)):
            ttk.Button(presets, text=label, command=lambda v=val: self._set_offset(v)).pack(side="left", padx=(0, 7))

        maintenance = tk.Frame(settings, bg=panel, padx=22, pady=20)
        maintenance.pack(fill="x")
        tk.Label(maintenance, text="DATA & CONNECTION", bg=panel, fg=cyan,
                 font=("Segoe UI Semibold", 11)).pack(anchor="w", pady=(0, 10))
        self.reconnect_btn = ttk.Button(maintenance, text="Reconnect Kuro.exe", command=self.connect)
        self.reconnect_btn.pack(side="left", padx=(0, 8))
        ttk.Button(maintenance, text="Rescan CMobs nu", command=self.request_rescan).pack(side="left", padx=(0, 8))
        self.reload_db_btn = ttk.Button(maintenance, text="Reload KuroDB JSON", command=self.reload_kuro_db)
        self.reload_db_btn.pack(side="left")

    def _offset_label(self, value):
        value = int(value)
        side = "op speler" if value == 0 else ("links" if value < 0 else "rechts")
        return f"Mob target X-offset: {value:+d}px  | afstand {abs(value)}px  | {side}"

    def _set_layout_mode(self):
        self.layout_mode = self.layout_var.get()

    def _on_offset_scale(self, raw):
        try:
            value = int(round(float(raw)))
        except Exception:
            return
        self.vac_offset_x = max(-350, min(350, value))
        self.offset_var.set(self.vac_offset_x)
        self.offset_text_var.set(self._offset_label(self.vac_offset_x))

    def _set_offset(self, value):
        self.vac_offset_x = int(value)
        self.offset_scale.set(self.vac_offset_x)
        self.offset_var.set(self.vac_offset_x)
        self.offset_text_var.set(self._offset_label(self.vac_offset_x))

    def reload_kuro_db(self):
        self.db_var.set("KuroDB opnieuw laden...")
        try:
            mobs, source, errors = load_kuro_db()
            self.mob_db = mobs
            self.kurodb_source = source
            self.kurodb_errors = errors
            self.mob_id_by_oid.clear()
            self.template_id_cache.clear()
            suffix = f" | errors: {len(errors)}" if errors else ""
            self.db_var.set(f"KuroDB: {len(mobs)} monster names — {source}{suffix}")
            self.refresh_snapshot(force_scan=True)
        except Exception as e:
            self.db_var.set(f"KuroDB reload fout: {e}")

    def _load_type_labels(self):
        try:
            if os.path.exists(MOB_LABELS_FILE):
                with open(MOB_LABELS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self.type_name_by_key = {str(k): str(v) for k, v in data.items()}
        except Exception:
            self.type_name_by_key = {}

    def _save_type_labels(self):
        try:
            with open(MOB_LABELS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.type_name_by_key, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def _type_name(self, fp):
        key = fp_key(fp)
        if key in self.type_name_by_key:
            return self.type_name_by_key[key]
        return "Onbekend"

    def _type_color(self, fp):
        palette = ("#ff595e", "#ffca3a", "#8ac926", "#1982c4", "#6a4c93", "#00d4aa", "#f72585", "#ff924c")
        key = fp_key(fp)
        return palette[sum(ord(ch) for ch in key) % len(palette)]

    def _mob_color(self, oid, fp=None):
        palette = ("#ff595e", "#ffca3a", "#8ac926", "#1982c4", "#6a4c93", "#00d4aa", "#f72585", "#ff924c")
        mid = self.mob_id_by_oid.get(oid)
        if mid is not None:
            return palette[mid % len(palette)]
        return self._type_color(fp)

    def _ensure_type_fp(self, oid, mob):
        if oid not in self.type_fp_by_oid:
            fp = read_type_fingerprint(self.pm, mob)
            if fp:
                self.type_fp_by_oid[oid] = fp
        return self.type_fp_by_oid.get(oid)

    def _ensure_mob_id(self, oid, mob):
        if oid not in self.mob_id_by_oid:
            mid = resolve_kuro_mob_id(self.pm, mob, self.mob_db, self.template_id_cache)
            if mid is not None:
                self.mob_id_by_oid[oid] = mid
        return self.mob_id_by_oid.get(oid)

    def _mob_display_name(self, oid, fp=None):
        mid = self.mob_id_by_oid.get(oid)
        if mid in self.mob_db:
            return f"{self.mob_db[mid]} [{mid}]"
        return self._type_name(fp)

    def rename_selected_type(self):
        sel = self.type_tree.selection() if hasattr(self, "type_tree") else ()
        if not sel:
            return
        item = self.type_tree.item(sel[0])
        vals = item.get("values", [])
        if len(vals) < 3:
            return
        old_name, _, key = vals
        new_name = simpledialog.askstring("Rename mob type", f"Naam voor {key}:", initialvalue=old_name, parent=self.root)
        if new_name:
            self.type_name_by_key[str(key)] = new_name.strip()
            self._save_type_labels()
            self.update_stats_ui()

    def reset_counters(self):
        self.seen_oids.clear()
        self.current_oids.clear()
        self.peak_mobs = 0
        self.spawn_events = 0
        self.despawn_events = 0
        self.update_stats_ui()

    def _ui(self, fn, *args, **kwargs):
        try:
            if self.root.winfo_exists():
                self.root.after(0, lambda: fn(*args, **kwargs))
        except Exception:
            pass

    def connect(self):
        if self.vac_enabled:
            self.stop_vac()
        if self.attack_probe_armed:
            self.disarm_attack_probe()
            if self.attack_probe_armed:
                self.status_var.set("Reconnect gestopt: attack telemetry is nog niet veilig hersteld")
                return

        try:
            self.pm = pymem.Pymem(TARGET)
            module = pymem.process.module_from_name(
                self.pm.process_handle,
                TARGET
            )
            self.base = int(module.lpBaseOfDll)
            self.mobs = {}
            self.seen_oids.clear()
            self.current_oids.clear()
            self.peak_mobs = 0
            self.spawn_events = 0
            self.despawn_events = 0
            self.type_fp_by_oid.clear()
            self.mob_id_by_oid.clear()
            self.template_id_cache.clear()
            self.status_var.set(f"Connected — PID {self.pm.process_id}")
            self.mob_var.set("Mobs: nog niet gescand")
            self.body_var.set("Body state: --")
            self.refresh_snapshot(force_scan=True)
        except Exception as e:
            self.pm = None
            self.base = None
            self.status_var.set(f"Kuro.exe connect mislukt: {e} — controleer admin/rechten")

    def toggle_vac(self):
        if self.vac_enabled:
            self.stop_vac()
        else:
            self.start_vac()

    def poll_hotkeys(self):
        """Global edge-triggered F5/F6 control without keyboard injection."""
        try:
            user32 = ctypes.windll.user32
            for vk, action in ((0x74, self.start_vac), (0x75, self.stop_vac)):
                down = bool(user32.GetAsyncKeyState(vk) & 0x8000)
                if down and not self.hotkey_state[vk]:
                    action()
                self.hotkey_state[vk] = down
        except Exception:
            pass
        finally:
            try:
                if self.root.winfo_exists():
                    self.root.after(60, self.poll_hotkeys)
            except Exception:
                pass

    def toggle_attack_probe(self):
        if self.attack_probe_armed:
            self.disarm_attack_probe()
        else:
            self.arm_attack_probe()

    def arm_attack_probe(self):
        """Temporarily log constructed attacks; never alters their contents."""
        if self.attack_probe_armed:
            return
        if self.pm is None or self.base is None:
            self.connect()
            if self.pm is None:
                return
        allocation = None
        try:
            hook = self.base + PREDISPATCH_RVA
            allocation = int(ctypes.windll.kernel32.VirtualAllocEx(
                self.pm.process_handle, None, 0x1000,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
            if not allocation:
                raise ctypes.WinError()
            trampoline = _build_attack_probe(allocation, hook + len(PREDISPATCH_ORIGINAL))
            self.pm.write_bytes(allocation, trampoline, len(trampoline))
            self.pm.write_bytes(allocation + TELEMETRY_DATA_OFFSET, b"\x00" * 24, 24)
            patch = b"\xE9" + _rel32(hook + 5, allocation) + b"\x90"
            _write_code_verified(self.pm, hook, PREDISPATCH_ORIGINAL, patch)
            self.attack_probe_allocation = allocation
            self.attack_probe_address = hook
            self.attack_probe_patch = patch
            self.attack_probe_sequence = 0
            self.attack_probe_armed = True
            self.probe_btn.config(text="ATTACK METER UIT", bg="#9333ea")
            self.probe_var.set("Attack telemetry AAN — client construction, geen serverbewijs")
        except Exception as exc:
            if allocation:
                ctypes.windll.kernel32.VirtualFreeEx(
                    self.pm.process_handle, ctypes.c_void_p(allocation), 0, MEM_RELEASE)
            self.probe_var.set(f"Attack telemetry niet gestart: {exc}")

    def disarm_attack_probe(self):
        if not self.attack_probe_armed:
            return
        restored = False
        try:
            actual = self.pm.read_bytes(self.attack_probe_address, len(PREDISPATCH_ORIGINAL))
            if actual == self.attack_probe_patch:
                _write_code_verified(self.pm, self.attack_probe_address,
                                     self.attack_probe_patch, PREDISPATCH_ORIGINAL)
            elif actual != PREDISPATCH_ORIGINAL:
                raise RuntimeError(f"unexpected hook bytes: {actual.hex(' ')}")
            restored = True
            self.probe_var.set("Attack telemetry UIT — originele instructie hersteld")
        except Exception as exc:
            self.probe_var.set(f"KRITIEK: telemetry restore mislukt: {exc}")
        finally:
            if restored and self.attack_probe_allocation:
                ctypes.windll.kernel32.VirtualFreeEx(
                    self.pm.process_handle, ctypes.c_void_p(self.attack_probe_allocation),
                    0, MEM_RELEASE)
                self.attack_probe_allocation = None
                self.attack_probe_armed = False
                self.probe_btn.config(text="ATTACK METER AAN", bg="#7c3aed")

    def poll_attack_probe(self):
        try:
            if self.attack_probe_armed and self.attack_probe_allocation and self.pm:
                raw = self.pm.read_bytes(
                    self.attack_probe_allocation + TELEMETRY_DATA_OFFSET, 24)
                sequence, payload_length = struct.unpack_from("<II", raw, 0)
                if sequence != self.attack_probe_sequence:
                    self.attack_probe_sequence = sequence
                    head = raw[8:24]
                    skill_id = struct.unpack_from("<I", head, 4)[0]
                    packed = head[12]
                    if skill_id == THUNDER_BOLT_ID:
                        self.last_tb_targets = packed >> 4
                        self.last_tb_hits = packed & 0x0F
                        mode = self.layout_mode if self.vac_enabled else "off"
                        self.attack_stats.setdefault(mode, Counter())[self.last_tb_targets] += 1
                        with self.snapshot_lock:
                            snap = dict(self.snapshot)
                        with self.mob_lock:
                            known = len(self.mobs)
                        event = {
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                            "session": self.telemetry_session,
                            "event": "thunder_bolt_client_attack",
                            "layout": mode,
                            "vac_enabled": bool(self.vac_enabled),
                            "declared_targets": self.last_tb_targets,
                            "declared_hits": self.last_tb_hits,
                            "payload_length": payload_length,
                            "verified_stack": int(snap.get("held", 0)),
                            "snapshot_mobs": len(snap.get("mobs", [])),
                            "known_mobs": known,
                        }
                        try:
                            with open(ATTACK_TELEMETRY_FILE, "a", encoding="utf-8") as stream:
                                stream.write(json.dumps(event, sort_keys=True) + "\n")
                        except Exception as exc:
                            self.probe_var.set(f"Telemetry log error: {exc}")
                        self.attack_var.set(
                            f"Thunder Bolt: {self.last_tb_targets} targets × "
                            f"{self.last_tb_hits} hit (client packet)")
                        parts = []
                        for label in ("off", "stack", "tb6"):
                            counts = self.attack_stats.get(label, Counter())
                            total = sum(counts.values())
                            if total:
                                distribution = " ".join(
                                    f"{targets}:{count}" for targets, count in sorted(counts.items()))
                                parts.append(f"{label}[n={total}] {distribution}")
                        self.comparison_var.set("Verdeling targets → " + " | ".join(parts))
        except Exception as exc:
            self.probe_var.set(f"Attack telemetry read error: {exc}")
        finally:
            try:
                if self.root.winfo_exists():
                    self.root.after(100, self.poll_attack_probe)
            except Exception:
                pass

    def _target_for_oid(self, oid, char_x, char_y):
        if self.layout_mode != "tb6":
            return char_x + int(self.vac_offset_x), char_y + FRONT_Y
        slots = ((-54, 0), (-27, 0), (0, 0), (27, 0), (54, 0), (0, -28))
        dx, dy = slots[int(oid) % len(slots)]
        return char_x + dx, char_y + dy

    def start_vac(self):
        if self.pm is None or self.base is None:
            self.connect()
            if self.pm is None:
                return

        if self.worker and self.worker.is_alive():
            return

        self.vac_enabled = True
        self.stop_event.clear()
        self.on_btn.config(text="VAC ACTIEF", state="disabled", bg="#166534")
        self.off_btn.config(state="normal")
        self.status_var.set("VAC start...")

        self.worker = threading.Thread(
            target=self.vac_loop,
            daemon=True
        )
        self.worker.start()
        self.scanner = threading.Thread(target=self.scan_loop, daemon=True)
        self.scanner.start()

    def stop_vac(self):
        if not self.vac_enabled and not (self.worker and self.worker.is_alive()):
            self.on_btn.config(text="VAC AAN  [F5]", state="normal", bg="#16a34a")
            return
        self.vac_enabled = False
        self.stop_event.set()
        self.rescan_requested.clear()
        self.on_btn.config(text="VAC AAN  [F5]", state="normal", bg="#16a34a")
        self.off_btn.config(state="disabled")
        self.status_var.set("VAC OFF — normale physics actief")
        # Keep radar usable after VAC is disabled.
        self.root.after(
            150,
            lambda: None if self.vac_enabled else self.refresh_snapshot(force_scan=True)
        )

    def scan_loop(self):
        """Discover newly created CMobs without pausing the 1 ms hold loop."""
        while self.vac_enabled and not self.stop_event.is_set():
            # Let the proven initial scan in vac_loop finish first; this also
            # spaces every later full-process discovery pass.
            self.rescan_requested.wait(RESCAN_SECONDS)
            if self.stop_event.is_set():
                break
            self.rescan_requested.clear()
            try:
                discovered = scan_mobs(self.pm, self.base)
                with self.mob_lock:
                    self.mobs.update(discovered)
                    self.last_scan_count = len(discovered)
            except Exception as exc:
                self._ui(self.status_var.set, f"VAC actief — scanwaarschuwing: {exc}")

    def request_rescan(self):
        """Request one read-only discovery pass without touching position state."""
        if self.vac_enabled:
            self.rescan_requested.set()
            self.status_var.set("CMob rescan aangevraagd…")
        else:
            self.refresh_snapshot(force_scan=True)

    def _record_oids(self, current):
        current = set(current)
        if not self.current_oids:
            added = current - self.seen_oids
            self.spawn_events += len(added)
        else:
            added = current - self.current_oids
            removed = self.current_oids - current
            self.spawn_events += len(added)
            self.despawn_events += len(removed)

        self.current_oids = current
        self.seen_oids.update(current)
        self.peak_mobs = max(self.peak_mobs, len(current))

    def refresh_snapshot(self, force_scan=False):
        """Read-only snapshot used by GUI/overlay when VAC is off or after reconnect."""
        if self.pm is None or self.base is None:
            return
        try:
            if force_scan or not self.mobs:
                self.mobs = scan_mobs(self.pm, self.base)

            character = get_character(self.pm, self.base)
            if not character:
                return
            _, char_x, char_y = character

            live = []
            stale = []
            for oid, mob in list(self.mobs.items()):
                if get_oid(self.pm, mob) != oid:
                    stale.append(oid)
                    continue
                x = read_i32(self.pm, mob + MOB_X_OFF)
                y = read_i32(self.pm, mob + MOB_Y_OFF)
                if x is None or y is None:
                    continue
                fp = self._ensure_type_fp(oid, mob)
                self._ensure_mob_id(oid, mob)
                live.append((oid, x, y, fp))

            for oid in stale:
                self.mobs.pop(oid, None)

            self._record_oids(oid for oid, _, _, _ in live)
            with self.snapshot_lock:
                self.snapshot = {
                    "player": (char_x, char_y),
                    "mobs": live,
                    "held": 0,
                    "body_ok": 0,
                }
            self.update_stats_ui()
        except Exception:
            pass

    def vac_loop(self):
        try:
            # Preserve the proven initial scan and exact position-write path.
            with self.mob_lock:
                self.mobs = scan_mobs(self.pm, self.base)
            last_gui = 0.0

            while not self.stop_event.is_set():
                character = get_character(self.pm, self.base)
                if not character:
                    self._ui(self.status_var.set, "Character niet gevonden")
                    time.sleep(0.05)
                    continue

                _, char_x, char_y = character
                target_x = char_x + int(self.vac_offset_x)
                target_y = char_y + FRONT_Y
                now = time.perf_counter()

                alive = 0
                body_ok = 0
                dead_oids = []
                live = []

                with self.mob_lock:
                    mob_items = list(self.mobs.items())
                for oid, mob in mob_items:
                    current_oid = get_oid(self.pm, mob)
                    if current_oid != oid:
                        dead_oids.append(oid)
                        continue

                    try:
                        mob_target_x, mob_target_y = self._target_for_oid(
                            oid, char_x, char_y)
                        if write_position(self.pm, mob, mob_target_x, mob_target_y):
                            body_ok += 1
                        alive += 1
                        fp = self._ensure_type_fp(oid, mob)
                        live.append((oid, mob_target_x, mob_target_y, fp))
                    except Exception:
                        dead_oids.append(oid)

                with self.mob_lock:
                    for oid in dead_oids:
                        self.mobs.pop(oid, None)
                    known_count = len(self.mobs)

                # Publish overlay/stats snapshot only 4x/s, not every VAC pass.
                if now - last_gui >= 0.25:
                    # Read back actual CMob coordinates.  "Verified" now means
                    # the values were observed after writing, not merely that
                    # pymem raised no exception.
                    verified_live = []
                    verified = 0
                    for oid, mob in mob_items:
                        if get_oid(self.pm, mob) != oid:
                            continue
                        actual_x = read_i32(self.pm, mob + MOB_X_OFF)
                        actual_y = read_i32(self.pm, mob + MOB_Y_OFF)
                        if actual_x is None or actual_y is None:
                            continue
                        expected_x, expected_y = self._target_for_oid(
                            oid, char_x, char_y)
                        if abs(actual_x - expected_x) <= 4 and abs(actual_y - expected_y) <= 4:
                            verified += 1
                        fp = self._ensure_type_fp(oid, mob)
                        verified_live.append((oid, actual_x, actual_y, fp))

                    self._record_oids(oid for oid, _, _, _ in verified_live)
                    with self.snapshot_lock:
                        self.snapshot = {
                            "player": (char_x, char_y),
                            "mobs": verified_live,
                            "held": verified,
                            "body_ok": body_ok,
                        }

                    self._ui(self.status_var.set, "VAC ACTIVE")
                    self._ui(self.mob_var.set, f"Known {known_count} • write OK {alive} • scan {self.last_scan_count}")
                    self._ui(self.verified_var.set, f"Verified {verified}/{len(verified_live)} op doelpositie")
                    self._ui(self.body_var.set, f"Body state: {body_ok}/{alive}")
                    self._ui(
                        self.pos_var.set,
                        f"Player ({char_x}, {char_y}) • layout {self.layout_mode} • base offset {self.vac_offset_x:+d}px"
                    )
                    self._ui(self.update_stats_ui)
                    last_gui = now

                time.sleep(INTERVAL)

        except Exception as e:
            self.vac_enabled = False
            self.stop_event.set()
            self._ui(self.on_btn.config, text="VAC AAN  [F5]", state="normal", bg="#16a34a")
            self._ui(self.status_var.set, f"VAC error: {e}")
        finally:
            self.vac_enabled = False
            self._ui(self.on_btn.config, text="VAC AAN  [F5]", state="normal", bg="#16a34a")
            self._ui(self.off_btn.config, state="disabled")

    def update_stats_ui(self):
        with self.snapshot_lock:
            snap = dict(self.snapshot)
        player = snap.get("player")
        mobs = snap.get("mobs", [])

        if not player:
            return

        px, py = player
        near5 = near25 = near100 = 0
        distances = []
        species_counts = Counter()
        species_meta = {}

        for oid, x, y, fp in mobs:
            d2 = (x - px) ** 2 + (y - py) ** 2
            d = d2 ** 0.5
            distances.append(d)
            if d2 <= 5 ** 2:
                near5 += 1
            if d2 <= 25 ** 2:
                near25 += 1
            if d2 <= 100 ** 2:
                near100 += 1

            mid = self.mob_id_by_oid.get(oid)
            if mid in self.mob_db:
                key = f"id:{mid}"
                species_meta[key] = (self.mob_db[mid], str(mid), fp)
            else:
                fpk = fp_key(fp)
                key = f"fp:{fpk}"
                species_meta[key] = (self._type_name(fp), fpk, fp)
            species_counts[key] += 1

        self.history_var.set(
            f"Current {len(mobs)} | Peak {self.peak_mobs} | Seen {len(self.seen_oids)} | "
            f"Spawn +{self.spawn_events} / Despawn -{self.despawn_events}"
        )
        maxd = max(distances) if distances else 0.0
        resolved = sum(1 for oid, *_ in mobs if self.mob_id_by_oid.get(oid) in self.mob_db)
        self.near_var.set(
            f"Stack <=5px={near5} | <=25px={near25} | <=100px={near100} | "
            f"Off-stack={len(mobs)-near5} | MaxDist={maxd:.0f}px | Named={resolved}/{len(mobs)}"
        )

        if hasattr(self, "type_tree"):
            for iid in self.type_tree.get_children():
                self.type_tree.delete(iid)
            for key, count in sorted(species_counts.items(), key=lambda kv: (-kv[1], kv[0])):
                name, ident, fp = species_meta[key]
                self.type_tree.insert("", "end", values=(name, count, ident))

    # -------------------- Overlay --------------------

    def toggle_overlay(self):
        if self.overlay_enabled:
            self.hide_overlay()
        else:
            self.show_overlay()

    def show_overlay(self):
        # Use a very distinctive colour key instead of black.  Some Windows/Tk
        # combinations keep a black Tk canvas opaque even though
        # -transparentcolor is accepted without raising an error.
        self.OVERLAY_KEY = "#ff00ff"

        if self.overlay is None or not self.overlay.winfo_exists():
            self.overlay = tk.Toplevel(self.root)
            self.overlay.overrideredirect(True)
            self.overlay.attributes("-topmost", True)
            self.overlay.configure(bg=self.OVERLAY_KEY)

            self.overlay_canvas = tk.Canvas(
                self.overlay,
                width=self.OVERLAY_W,
                height=self.OVERLAY_H,
                bg=self.OVERLAY_KEY,
                highlightthickness=0,
                bd=0,
            )
            self.overlay_canvas.pack()

        self.overlay_enabled = True
        self.overlay_btn.config(text="HUD VERBERGEN")
        self.overlay_var.set("HUD AAN — client telemetry")
        self.position_overlay()
        self.overlay.deiconify()

        # The HWND must be realised before applying layered-window settings.
        self.overlay.update_idletasks()
        self.overlay.update()
        self._make_overlay_clickthrough()

    def hide_overlay(self):
        self.overlay_enabled = False
        self.overlay_btn.config(text="HUD TONEN")
        self.overlay_var.set("HUD UIT")
        if self.overlay is not None:
            try:
                self.overlay.withdraw()
            except Exception:
                pass

    def _make_overlay_clickthrough(self):
        """Make the radar colour-key transparent and mouse click-through on Windows."""
        if self.overlay is None:
            return
        try:
            hwnd = int(self.overlay.winfo_id())
            user32 = ctypes.windll.user32

            GWL_EXSTYLE = -20
            WS_EX_LAYERED = 0x00080000
            WS_EX_TRANSPARENT = 0x00000020
            WS_EX_TOOLWINDOW = 0x00000080
            WS_EX_NOACTIVATE = 0x08000000
            LWA_COLORKEY = 0x00000001

            # 0x00BBGGRR for RGB(255, 0, 255) = magenta.
            MAGENTA_COLORREF = 0x00FF00FF

            style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            user32.SetWindowLongW(
                hwnd,
                GWL_EXSTYLE,
                style
                | WS_EX_LAYERED
                | WS_EX_TRANSPARENT
                | WS_EX_TOOLWINDOW
                | WS_EX_NOACTIVATE,
            )

            # Do not rely only on Tk's -transparentcolor flag: explicitly apply
            # the Win32 layered-window colour key as well.
            user32.SetLayeredWindowAttributes(
                hwnd,
                MAGENTA_COLORREF,
                255,
                LWA_COLORKEY,
            )

            # Also ask Tk to use the same key where supported.
            try:
                self.overlay.wm_attributes(
                    "-transparentcolor",
                    self.OVERLAY_KEY,
                )
            except tk.TclError:
                pass

        except Exception as exc:
            try:
                self.overlay_var.set(f"Overlay transparency error: {exc}")
            except Exception:
                pass

    def _find_kuro_window_rect(self):
        if self.pm is None:
            return None
        try:
            user32 = ctypes.windll.user32
            target_pid = int(self.pm.process_id)
            found = []

            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

            def enum_proc(hwnd, lparam):
                if not user32.IsWindowVisible(hwnd):
                    return True
                pid = ctypes.c_ulong()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value != target_pid:
                    return True
                length = user32.GetWindowTextLengthW(hwnd)
                if length <= 0:
                    return True
                rect = ctypes.wintypes.RECT()
                if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                    w = rect.right - rect.left
                    h = rect.bottom - rect.top
                    if w > 300 and h > 200:
                        found.append((w * h, rect.left, rect.top, rect.right, rect.bottom))
                return True

            user32.EnumWindows(WNDENUMPROC(enum_proc), 0)
            if not found:
                return None
            _, l, t, r, b = max(found)
            return l, t, r, b
        except Exception:
            return None

    def position_overlay(self):
        if not self.overlay_enabled or self.overlay is None:
            return
        rect = self._find_kuro_window_rect()
        if rect:
            l, t, r, b = rect
            x = r - self.OVERLAY_W - 18
            y = t + 42
        else:
            x, y = 40, 40
        try:
            self.overlay.geometry(f"{self.OVERLAY_W}x{self.OVERLAY_H}+{x}+{y}")
        except Exception:
            pass


    def render_overlay(self):
        try:
            if self.overlay_enabled and self.overlay_canvas is not None:
                if not self.vac_enabled:
                    self.refresh_snapshot(force_scan=not bool(self.mobs))

                self.position_overlay()
                c = self.overlay_canvas
                c.delete("all")

                with self.snapshot_lock:
                    snap = dict(self.snapshot)
                player = snap.get("player")
                mobs = snap.get("mobs", [])
                held = snap.get("held", 0)

                c.create_text(12, 8, anchor="nw", text="KURO • LIVE VAC HUD", fill="#38bdf8", font=("Segoe UI Semibold", 12))
                tb = "--" if self.last_tb_targets is None else f"{self.last_tb_targets}×{self.last_tb_hits}"
                c.create_text(12, 29, anchor="nw",
                              text=f"Verified stack {held}/{len(mobs)}   •   Last Thunder Bolt {tb} (client)",
                              fill="white", font=("Consolas", 9, "bold"))

                if player:
                    px, py = player
                    radar_l, radar_t, radar_r, radar_b = 8, 52, 375, self.OVERLAY_H - 10
                    cx = (radar_l + radar_r) // 2
                    cy = (radar_t + radar_b) // 2
                    scale_x = ((radar_r - radar_l) * 0.48) / self.RADAR_RADIUS
                    scale_y = ((radar_b - radar_t) * 0.46) / self.RADAR_RADIUS

                    c.create_rectangle(radar_l, radar_t, radar_r, radar_b, outline="#8a8a8a")
                    c.create_line(cx, radar_t + 4, cx, radar_b - 4, fill="#555555")
                    c.create_line(radar_l + 4, cy, radar_r - 4, cy, fill="#555555")
                    c.create_oval(cx - 5, cy - 5, cx + 5, cy + 5, fill="#ffffff", outline="")
                    # VAC target marker: exactly where the stack will be held relative to player.
                    tx = cx + self.vac_offset_x * scale_x
                    if radar_l + 5 <= tx <= radar_r - 5:
                        c.create_line(cx, cy, tx, cy, fill="#dddddd", dash=(3, 3))
                        c.create_oval(tx - 6, cy - 6, tx + 6, cy + 6, outline="#ffffff", width=2)
                        c.create_text(tx, cy - 12, anchor="s", text=f"{abs(self.vac_offset_x)}px", fill="white", font=("Consolas", 8, "bold"))

                    near5 = near25 = near100 = 0
                    distances = []
                    type_counts = Counter()
                    nearest = []
                    for oid, x, y, fp in mobs:
                        dx = x - px
                        dy = y - py
                        d2 = dx * dx + dy * dy
                        d = d2 ** 0.5
                        distances.append(d)
                        nearest.append((d, oid, x, y, fp))
                        if d2 <= 25:
                            near5 += 1
                        if d2 <= 625:
                            near25 += 1
                        if d2 <= 10000:
                            near100 += 1
                        mid = self.mob_id_by_oid.get(oid)
                        if mid in self.mob_db:
                            type_counts[("id", mid)] += 1
                        else:
                            type_counts[("fp", fp_key(fp))] += 1
                        sx = cx + dx * scale_x
                        sy = cy + dy * scale_y
                        if radar_l + 5 <= sx <= radar_r - 5 and radar_t + 5 <= sy <= radar_b - 5:
                            color = self._mob_color(oid, fp)
                            r = 4 if d2 <= 25 else 3
                            c.create_oval(sx-r, sy-r, sx+r, sy+r, fill=color, outline="")

                    maxd = max(distances) if distances else 0.0
                    c.create_text(radar_l + 7, radar_b - 7, anchor="sw", text=f"Player ({px},{py}) | radius ±{self.RADAR_RADIUS}px", fill="white", font=("Segoe UI", 8))

                    # Right-side information panel
                    x0 = 390
                    c.create_text(x0, 54, anchor="nw", text=f"STACK  target={self.vac_offset_x:+d}px", fill="#ffd166", font=("Segoe UI", 9, "bold"))
                    c.create_text(x0, 72, anchor="nw", text=f"<=5px    {near5:3d}", fill="white", font=("Consolas", 9))
                    c.create_text(x0, 88, anchor="nw", text=f"<=25px   {near25:3d}", fill="white", font=("Consolas", 9))
                    c.create_text(x0, 104, anchor="nw", text=f"<=100px  {near100:3d}", fill="white", font=("Consolas", 9))
                    c.create_text(x0, 120, anchor="nw", text=f"Offstack {len(mobs)-near5:3d}", fill="white", font=("Consolas", 9))
                    c.create_text(x0, 136, anchor="nw", text=f"MaxDist  {maxd:5.0f}px", fill="white", font=("Consolas", 9))
                    c.create_text(x0, 151, anchor="nw", text=f"TB last   {tb}", fill="#c084fc", font=("Consolas", 9, "bold"))

                    c.create_text(x0, 174, anchor="nw", text="MONSTERS", fill="#ffd166", font=("Segoe UI", 9, "bold"))
                    y0 = 193
                    for i, (key, count) in enumerate(sorted(type_counts.items(), key=lambda kv: (-kv[1], str(kv[0])))[:6]):
                        kind, ident = key
                        if kind == "id":
                            name = self.mob_db.get(ident, f"Mob {ident}")
                            label = f"{name[:14]:14s} {count:3d}"
                            color = ("#ff595e", "#ffca3a", "#8ac926", "#1982c4", "#6a4c93", "#00d4aa", "#f72585", "#ff924c")[ident % 8]
                        else:
                            fp = next((v for v in self.type_fp_by_oid.values() if fp_key(v) == ident), None)
                            name = self._type_name(fp) if fp else "Unknown"
                            label = f"{name[:14]:14s} {count:3d}"
                            color = self._type_color(fp)
                        yy = y0 + i * 18
                        c.create_oval(x0, yy+2, x0+8, yy+10, fill=color, outline="")
                        c.create_text(x0+14, yy, anchor="nw", text=label, fill="white", font=("Consolas", 8))

                    nearest.sort(key=lambda v: v[0])
                    if nearest:
                        d, oid, x, y, fp = nearest[0]
                        name = self._mob_display_name(oid, fp)
                        c.create_text(x0, self.OVERLAY_H-28, anchor="nw", text=f"Nearest {name[:18]}  {d:.1f}px", fill="#dddddd", font=("Consolas", 8))
                else:
                    c.create_text(12, 70, anchor="nw", text="Geen player snapshot", fill="white")
        finally:
            self.root.after(100, self.render_overlay)

    def close(self):
        if self.attack_probe_armed:
            self.disarm_attack_probe()
            if self.attack_probe_armed:
                self.status_var.set("Afsluiten gestopt: herstel eerst de attack telemetry")
                return
        self.stop_event.set()
        self.vac_enabled = False
        try:
            if self.overlay is not None:
                self.overlay.destroy()
        except Exception:
            pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    KuroVacGUI().run()
