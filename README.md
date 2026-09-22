# maplestory v83 hacks

MapleStory v83 private-server hacks, tools and reverse-engineering experiments written in Python.

This repository contains the tools I built while researching MapleStory private-server clients, mainly **YunaMS** and **KuroMS**.

> **Important:** these tools are build-specific.  
> Addresses, offsets, structures and code signatures that work on one client build may not work on another.

---

## Contents

### YunaMS

| File | Tool | Controls |
|---|---|---|
| `vac2.py` | Mob VAC | `F5` ON / `F6` OFF |
| `vac.py` | Loot Sweep | `F1` start / `F2` stop / `F3` Y-5 / `F4` Y+5 |
| `petvac.py` | Pet Item Vac | `F1` ON / `F2` OFF / `ESC` restore + exit |
| `petvac_gui_f1_f2.py` | Pet Item Vac GUI | `F1` ON / `F2` OFF |
| `damage.py` | Magic Claw x2/x4 packet replay | `F1` x2 / `F2` x4 / `F3` OFF / `F12` exit |
| `Magicclaw4packets.py` | Magic Claw x2/x4 packet replay variant | `F1` x2 / `F2` x4 / `F3` OFF / `F12` exit |
| `ice.py` | Ice Strike x4 packet replay | `F7` ON / `F8` OFF / `F12` exit |
| `multiskill.py` | Multi Skill Replay GUI | GUI controls |
| `mouse.py` | Mouse target teleport | `F9` calibrate / `F8` save / `F7` teleport |
| `mousefly.py` | Double-middle-click mouse teleport | `F9` calibrate / double middle click teleport |
| `yuna_blink_godmode_f3_f4.py` | Blink Godmode | `F3` ON / `F4` OFF |

### KuroMS

| File | Tool | Controls |
|---|---|---|
| `kuro_vac_gui_v3.py` | Mob VAC / radar / research GUI | `F5` ON / `F6` OFF |
| `kuro_bgm_hotkeys.py` | Blink Godmode | `F1` ON / `F2` OFF / `F3` status / `F12` restore + exit |

---

# YunaMS tools

## Mob VAC

**File:** `vac2.py`

YunaMS mob VAC with a small GUI.

The tool scans live private memory for valid `CMob` objects and validates them using the expected vtables and secure OID fields.

When VAC is enabled it updates these mob position fields:

```text
current X
current Y
previous X
previous Y
```

The GUI also has an adjustable X offset so mobs can be held next to the character instead of directly on top of the character.

### Hotkeys

```text
F5 = VAC ON
F6 = VAC OFF
```

---

## Loot Sweep

**File:** `vac.py`

Older YunaMS loot implementation.

This tool finds active drop objects, matches them to their spatial drop nodes, teleports the player to drop locations and performs repeated `Z` pickup input.

It also groups nearby drops so several items at almost the same coordinates can be handled as one pickup location.

### Hotkeys

```text
F1 = start loot sweep
F2 = stop
F3 = target Y -5
F4 = target Y +5
```

This is separate from Pet Item Vac. Loot Sweep moves the player to loot; Pet Item Vac uses the internal pet pickup path.

---

## Pet Item Vac

**Files:**

```text
petvac.py
petvac_gui_f1_f2.py
```

Pet Item Vac for YunaMS.

The implementation uses the client `CDropPool` iterator and the game's existing pet-aware pickup function.

Important researched YunaMS structures used by the script include:

```text
CDropPool global
CDropPool active count
CDropPool iterator root
drop view/state/OID
pet update path
secure drop coordinate getter
pet-aware pickup function
```

The script installs two normal x86 detours and preserves an existing `E9` chain when one is already present.

### Console version

```text
F1  = Pet Item Vac ON
F2  = Pet Item Vac OFF
ESC = restore hooks and exit
```

### GUI version

```text
F1 = ON
F2 = OFF
```

The GUI version intentionally keeps the same Pet Vac backend and only adds a minimal two-button interface.

---

## Magic Claw x2 / x4

**Files:**

```text
damage.py
Magicclaw4packets.py
```

YunaMS Magic Claw packet-replay trainer.

This does **not** multiply a displayed damage value. It matches the Magic Claw attack packet and sends the same normal attack packet through the existing `SendPacket` route multiple times.

The implementation validates:

```text
attack caller
magic attack opcode
Magic Claw skill ID
Magic Claw packed target/hit byte
```

It also preserves the existing runtime `SendPacket` `E9` chain instead of assuming the function entry is untouched.

### Hotkeys

```text
F1  = x2  (1 extra packet)
F2  = x4  (3 extra packets)
F3  = OFF / restore original SendPacket entry
F12 = restore + exit
```

---

## Ice Strike x4

**File:** `ice.py`

Ice Strike-specific packet replay for YunaMS.

The script identifies Ice Strike using the v83 magic attack opcode and the exact Ice Strike skill ID.

Unlike the strict Magic Claw matcher, it does not require one fixed target/hit packed byte because the number of targets hit by Ice Strike can change.

### Hotkeys

```text
F7  = Ice Strike x4 ON
F8  = OFF / restore original SendPacket entry
F12 = restore + exit
```

---

## Multi Skill Replay

**File:** `multiskill.py`

GUI version that combines several researched magic attacks into one shared `SendPacket` hook.

Supported skill selections in the current script:

```text
Magic Claw
Ice Strike
Chain Lightning
Blizzard
```

Available modes:

```text
x2
x4
```

The GUI lets you:

- select individual skills
- select all / none
- choose x2 or x4
- enable/apply the hook
- disable and restore the original runtime `SendPacket` entry
- view packet counters per supported skill

Magic Claw keeps its strict packed-byte check. The other listed skills are matched by magic attack opcode plus skill ID.

---

## Mouse Teleport

**File:** `mouse.py`

Mouse-to-world teleport tool for YunaMS.

The script first calibrates the player's screen position. A mouse position can then be converted into a world-space target and stored before teleporting.

The target Y position is clamped against the detected bottom map boundary.

### Hotkeys

```text
F9 = calibrate with the mouse placed on the character
F8 = save current mouse position as teleport target
F7 = teleport to saved target
```

---

## Double Middle-Click Teleport

**File:** `mousefly.py`

A faster mouse teleport variant.

After one calibration, double-clicking the middle mouse button teleports toward the current mouse position while YunaMS is the foreground window.

The calculated position is clamped to the detected map bounds.

### Controls

```text
F9 = calibrate
double middle click = teleport to mouse
```

---

## Blink Godmode

**File:** `yuna_blink_godmode_f3_f4.py`

YunaMS Blink Godmode based on the classic v83 instruction pattern.

The relevant instruction changes from:

```asm
sub edi, 0x1E
```

to:

```asm
add edi, 0x1E
```

The Yuna version validates the expected v83 instruction context before applying the patch and restores the original bytes when disabled.

### Hotkeys

```text
F3 = Blink Godmode ON
F4 = Blink Godmode OFF
```

---

# KuroMS tools

## Kuro Mob VAC / Control Center

**File:** `kuro_vac_gui_v3.py`

The larger KuroMS VAC GUI used during earlier research.

The script contains:

- `CMob` discovery
- secure OID validation
- mob position control
- adjustable VAC positioning
- live mob statistics
- spawn/despawn tracking
- mob type fingerprints
- a radar / overlay
- optional mob-name/database research
- optional attack-construction telemetry

### Hotkeys

```text
F5 = VAC ON
F6 = VAC OFF
```

The Kuro implementation is build-specific and should not be assumed to work on YunaMS simply because some structures are similar.

---

## Kuro Blink Godmode

**File:** `kuro_bgm_hotkeys.py`

Earlier Blink Godmode implementation for `Kuro.exe`.

It validates the complete expected Kuro code context before changing the three-byte instruction.

### Hotkeys

```text
F1  = Godmode ON
F2  = Godmode OFF / restore
F3  = show current status
F12 = restore + exit
```

This Kuro script was later used as a reference while creating the YunaMS Blink Godmode version.

---

# Requirements

The Python tools are intended for Windows.

Typical requirements:

```text
Python 3
pymem
tkinter
```

`tkinter` is normally included with the standard Windows Python installer.

Install `pymem` with:

```bash
pip install pymem
```

Some scripts use only `ctypes` for parts of their process/memory access, while others directly depend on `pymem`.

---

# Running

Start the correct private-server client first.

Then run the script you want, for example:

```bash
python vac2.py
```

```bash
python petvac_gui_f1_f2.py
```

```bash
python damage.py
```

```bash
python mousefly.py
```

The process name must match the target expected by that script:

```text
YunaMS.exe
Kuro.exe
```

---

# Build-specific code

These projects contain addresses, RVAs, offsets, object layouts and instruction signatures obtained from specific client builds.

Examples from the YunaMS research include structures related to:

```text
character position
map ID
teleport state
CMob objects
secure mob OIDs
drop objects
CDropPool
pet update
pet pickup
CClientSocket::SendPacket
attack packet construction
```

Do not assume an address from YunaMS is valid for another v83 client.

Even clients based on the same MapleStory version can have different code, injected modules, modified structures or runtime detours.

---

# Reverse-engineering references

During the research, older MapleStory tools and binaries were used as references, including material related to:

```text
Timelapse
mapleboyx4
MapleRoyals
older MapleStory v62/v83 Cheat Engine research
```

These references helped identify historical approaches and client functions.

Third-party binaries or source archives should only be redistributed if their license or author permits it. They are not required for someone to understand the Python tools in this repository.

---

# Repository layout

A simple layout could be:

```text
maplestoryv83hacks/
│
├── README.md
├── requirements.txt
│
├── yuna/
│   ├── mob_vac/
│   │   └── vac2.py
│   ├── loot_sweep/
│   │   └── vac.py
│   ├── pet_vac/
│   │   ├── petvac.py
│   │   └── petvac_gui_f1_f2.py
│   ├── damage/
│   │   ├── damage.py
│   │   ├── Magicclaw4packets.py
│   │   ├── ice.py
│   │   └── multiskill.py
│   ├── movement/
│   │   ├── mouse.py
│   │   └── mousefly.py
│   └── godmode/
│       └── yuna_blink_godmode_f3_f4.py
│
└── kuro/
    ├── kuro_vac_gui_v3.py
    └── kuro_bgm_hotkeys.py
```

---

# Research files

Several temporary probes and reports were created while reverse engineering the Yuna pet-loot path.

Examples include:

```text
yuna_pet_loot_differential_probe.py
yuna_pet_route_readonly_probe.py
yuna_pet_exact_iterator_probe.py
```

and generated report files such as:

```text
yuna_pet_diff_item_*.txt
yuna_pet_diff_meso_*.txt
yuna_pet_route_item_*.txt
yuna_pet_exact_iterator_item_*.txt
```

These are research/debug artifacts rather than normal end-user hacks.

If they are included in the repository, putting them under a separate directory is cleaner:

```text
research/
└── pet_vac/
```

Large raw report files do not need to be in the main release unless you specifically want to preserve the reverse-engineering evidence.

---

# Current project status

Implemented tools currently represented by the scripts above:

```text
YunaMS Mob VAC
YunaMS Loot Sweep
YunaMS Pet Item Vac
YunaMS Magic Claw x2/x4
YunaMS Ice Strike x4
YunaMS Multi Skill Replay
YunaMS Mouse Teleport
YunaMS Double Middle-Click Teleport
YunaMS Blink Godmode

KuroMS Mob VAC / Radar
KuroMS Blink Godmode
```

Future experiments can be documented separately instead of listing them as finished features.

---

# Disclaimer

This repository is intended for reverse-engineering, learning and testing in private-server or otherwise authorized environments.

Client builds differ, and memory modification can crash a client or corrupt its current runtime state if an address or structure is wrong.

No anti-cheat bypass, stealth injection, credential theft or security-system evasion is included in these tools.
