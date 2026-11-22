"""Read-only diagnostic: dumps the live entity list from a running
Spelunky.exe to confirm the entity-list pointer chain (ported from
spelunky-fyi/HD-Toolbox's libs/mem_reader manager.rs get_active_entities/
get_partial_entity, which is itself dead/unverified code in that project)
actually works against this game build, and to find real entity_type
values for things not in HD-Toolbox's own partial EntityType enum
(notably whatever a shop's "Bomb Box" item really is).

Run this while standing in a level with items on the ground (ideally a
shop) and it prints every active entity it can read.
"""

import sys
import pymem

PROCESS_NAME = "Spelunky.exe"

OFFSETS_BY_VERSION = {
    "1.47": {"global_state": 0x15446C, "kali_accepts": 0x112D20},
    "1.4": {"global_state": 0x1384B4, "kali_accepts": 0x108BE4},
}
KALI_ACCEPTS_BYTES = "KALI_ACCEPTS".encode("utf-16-le") + b"\x00\x00"

KNOWN_TYPES = {
    0: "Player", 117: "ShotgunPellet", 157: "TikiSpikes", 252: "Eggplant",
    503: "Spectacles", 504: "ClimbingGloves", 505: "PitchersMitt", 506: "SpringShoes",
    507: "SpikeShoes", 508: "BombPaste", 509: "Compass", 510: "Mattock",
    511: "Boomerang", 512: "Machete", 513: "Crysknife", 514: "WebGun",
    515: "Shotgun", 516: "FreezeRay", 517: "PlasmaCannon", 518: "Camera",
    519: "Teleporter", 520: "Parachute", 521: "Cape", 522: "Jetpack",
    523: "Shield", 524: "RoyalJelly", 525: "Idol", 526: "Kapala",
    527: "UdjatEye", 528: "Ankh", 529: "Hedjet", 530: "Sceptre",
    531: "BookOfTheDead", 532: "VladsCape", 533: "VladsAmulet",
    1055: "Olmec", 1056: "KingYamaHead", 1057: "KingYamaFist",
}
KIND_NAMES = {0: "Floor", 1: "Active", 2: "Player", 3: "Monster", 4: "Item", 5: "Background", 6: "Explosion", -99: "Entity"}


def find_pid():
    for entry in pymem.process.list_processes():
        name = entry.szExeFile.decode(errors="ignore")
        if name.lower() == PROCESS_NAME.lower():
            return entry.th32ProcessID
    return None


def main():
    pid = find_pid()
    if pid is None:
        print("Spelunky.exe not found.")
        sys.exit(1)

    pm = pymem.Pymem()
    pm.open_process_from_id(pid)
    base_addr = pm.process_base.lpBaseOfDll

    offsets = None
    for ver, off in OFFSETS_BY_VERSION.items():
        try:
            data = pm.read_bytes(base_addr + off["kali_accepts"], 26)
        except Exception:
            continue
        if data == KALI_ACCEPTS_BYTES:
            offsets = off
            print(f"Detected version: {ver}")
            break
    if offsets is None:
        print("Unrecognized Spelunky.exe build.")
        sys.exit(1)

    global_state = pm.read_uint(base_addr + offsets["global_state"])
    print(f"global_state = 0x{global_state:X}")

    screen_state = pm.read_int(global_state + 0x58)
    level = pm.read_uint(global_state + 0x4405D4)
    is_black_market = pm.read_uchar(global_state + 0x4405FF)
    print(f"screen_state={screen_state} level={level} is_black_market={is_black_market}")

    entity_struct_offset = pm.read_uint(global_state + 0x30)
    print(f"entity_struct_offset = 0x{entity_struct_offset:X}")
    num_active = pm.read_uint(entity_struct_offset + 0x7810)
    print(f"num_active_entities = {num_active}")

    if num_active == 0 or num_active > 5000:
        print("num_active_entities looks implausible - pointer chain is probably wrong for this build.")
        sys.exit(1)

    ptrs_raw = pm.read_bytes(entity_struct_offset, num_active * 4)
    entities = []
    for i in range(num_active):
        addr = int.from_bytes(ptrs_raw[i * 4:i * 4 + 4], "little")
        if addr == 0:
            continue
        try:
            data = pm.read_bytes(addr + 0x8, 20)
        except Exception as e:
            entities.append((addr, None, None, None, None, None, str(e)))
            continue
        kind = int.from_bytes(data[0:4], "little", signed=True)
        etype = int.from_bytes(data[4:8], "little", signed=True)
        bin_x = int.from_bytes(data[8:12], "little")
        bin_y = int.from_bytes(data[12:16], "little")
        owner = int.from_bytes(data[16:20], "little", signed=True)
        entities.append((addr, kind, etype, bin_x, bin_y, owner, None))

    print(f"\nRead {len(entities)} entities (of {num_active} pointers):\n")
    for addr, kind, etype, bin_x, bin_y, owner, err in entities:
        if err:
            print(f"  0x{addr:X}: READ ERROR {err}")
            continue
        kind_name = KIND_NAMES.get(kind, f"?{kind}")
        type_name = KNOWN_TYPES.get(etype, f"UNKNOWN({etype})")
        print(f"  0x{addr:X}: kind={kind_name:10s} type={type_name:20s} bin=({bin_x},{bin_y}) owner={owner}")

    print("\nItem-kind entities only (kind==4):")
    for addr, kind, etype, bin_x, bin_y, owner, err in entities:
        if kind == 4:
            type_name = KNOWN_TYPES.get(etype, f"UNKNOWN({etype})")
            print(f"  0x{addr:X}: type={type_name:20s} bin=({bin_x},{bin_y}) owner={owner}")


if __name__ == "__main__":
    main()
