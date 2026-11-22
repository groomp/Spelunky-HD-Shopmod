"""Spawns a real, fully-functional item by calling the game's OWN internal
entity-constructor function (SpawnEntity) via a tiny remote-thread stub -
the same technique LunkyBox (ThomasTerp/LunkyBox) uses, just driven from
outside the process instead of an injected DLL. This is why it works where
directly overwriting an existing entity's type field did not: all the real
sprite/animation/behavior setup happens INSIDE that constructor when the
entity is first created, keyed off the class id we pass in - a post-hoc
field poke can't retroactively redo that initialization.

Offsets confirmed against our own build (version 1.47, global_state =
0x15446C matches LunkyBox's own "Steam" table exactly):
  SPAWNENTITY = base + 0x70AB0
  signature (ported from LunkyBox's Spelunky.cpp):
    DWORD __fastcall SpawnEntity(DWORD ecx, void* edx, float x, float y, int entityClassID, bool unknown)
    ecx = *(DWORD*)(base + GLOBAL_STATE)   (same global_state pointer game_reader.py already reads)
    edx = NULL
"""

import struct
import sys
import time

import ctypes
import ctypes.wintypes as w
import pymem

K32 = ctypes.windll.kernel32

PROCESS_NAME = "Spelunky.exe"
GLOBAL_STATE_OFFSET = 0x15446C
KALI_ACCEPTS_OFFSET = 0x112D20
KALI_ACCEPTS_BYTES = "KALI_ACCEPTS".encode("utf-16-le") + b"\x00\x00"
SPAWNENTITY_OFFSET = 0x70AB0

ITEM_CLASS = {
    "ropes": 500, "bomb_bag": 501, "bomb_box": 502, "spectacles": 503,
    "climbing_gloves": 504, "pitchers_mitt": 505, "spring_shoes": 506,
    "spike_shoes": 507, "paste": 508, "compass": 509, "mattock": 510,
    "boomerang": 511, "machete": 512, "web_gun": 514, "shotgun": 515,
    "freeze_ray": 516, "plasma_cannon": 517, "camera": 518, "teleporter": 519,
    "parachute": 520, "cape": 521, "jetpack": 522, "shield": 523,
    "royal_jelly": 524, "idol": 525, "kapala": 526, "udjat_eye": 527,
    "ankh": 528, "hedjet": 529, "sceptre": 530, "book_of_the_dead": 531,
    "vlads_cape": 532, "vlads_amulet": 533,
}

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
MEM_RELEASE = 0x8000

K32.VirtualAllocEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t, w.DWORD, w.DWORD]
K32.VirtualAllocEx.restype = ctypes.c_void_p
K32.VirtualFreeEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t, w.DWORD]
K32.CreateRemoteThread.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, w.DWORD, ctypes.c_void_p]
K32.CreateRemoteThread.restype = w.HANDLE
K32.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]


def find_pid():
    for entry in pymem.process.list_processes():
        if entry.szExeFile.decode(errors="ignore").lower() == PROCESS_NAME.lower():
            return entry.th32ProcessID
    return None


def connect():
    pid = find_pid()
    if pid is None:
        print("Spelunky.exe not found.")
        sys.exit(1)
    pm = pymem.Pymem()
    pm.open_process_from_id(pid)
    base = pm.process_base.lpBaseOfDll
    data = pm.read_bytes(base + KALI_ACCEPTS_OFFSET, 26)
    if data != KALI_ACCEPTS_BYTES:
        print("Unrecognized build (expected version 1.47 / Steam offsets).")
        sys.exit(1)
    return pm, base


def find_player_pos(pm, base):
    global_state = pm.read_uint(base + GLOBAL_STATE_OFFSET)
    entity_struct_offset = pm.read_uint(global_state + 0x30)
    num_active = pm.read_uint(entity_struct_offset + 0x7810)
    ptrs_raw = pm.read_bytes(entity_struct_offset, num_active * 4)
    for i in range(num_active):
        addr = int.from_bytes(ptrs_raw[i * 4:i * 4 + 4], "little")
        if addr == 0:
            continue
        try:
            data = pm.read_bytes(addr + 0x8, 8)
        except Exception:
            continue
        kind = int.from_bytes(data[0:4], "little", signed=True)
        etype = int.from_bytes(data[4:8], "little", signed=True)
        if kind == 2 and etype == 0:  # EntityKind.Player, EntityType.Player
            x, y = struct.unpack("<ff", pm.read_bytes(addr + 0x30, 8))
            return addr, x, y
    return None, None, None


def find_shop_items(pm, base):
    """Any kind==Item entity whose type is one of the known equipment/
    item classes (500-533) - on an early Mines level these are almost
    always real shop-shelf items, not background decoration (which uses
    a completely different, lower id range - see scan_entities.py)."""
    global_state = pm.read_uint(base + GLOBAL_STATE_OFFSET)
    entity_struct_offset = pm.read_uint(global_state + 0x30)
    num_active = pm.read_uint(entity_struct_offset + 0x7810)
    ptrs_raw = pm.read_bytes(entity_struct_offset, num_active * 4)
    known_item_types = set(ITEM_CLASS.values())
    results = []
    for i in range(num_active):
        addr = int.from_bytes(ptrs_raw[i * 4:i * 4 + 4], "little")
        if addr == 0:
            continue
        try:
            data = pm.read_bytes(addr + 0x8, 8)
        except Exception:
            continue
        kind = int.from_bytes(data[0:4], "little", signed=True)
        etype = int.from_bytes(data[4:8], "little", signed=True)
        if kind == 4 and etype in known_item_types:
            x, y = struct.unpack("<ff", pm.read_bytes(addr + 0x30, 8))
            results.append((addr, etype, x, y))
    return results


def move_entity(pm, addr, x, y):
    pm.write_bytes(addr + 0x30, struct.pack("<ff", x, y), 8)


def spawn_entity(pm, base, x, y, class_id, purchasable=True):
    global_state_ptr_addr = base + GLOBAL_STATE_OFFSET
    ecx_value = pm.read_uint(global_state_ptr_addr)
    spawn_addr = base + SPAWNENTITY_OFFSET

    x_bits = struct.unpack("<I", struct.pack("<f", x))[0]
    y_bits = struct.unpack("<I", struct.pack("<f", y))[0]

    code = b""
    code += b"\xB9" + struct.pack("<I", ecx_value)        # mov ecx, ecx_value
    code += b"\x31\xD2"                                     # xor edx, edx
    code += b"\x6A" + bytes([1 if purchasable else 0])      # push unknown (testing: purchasable flag?)
    code += b"\x68" + struct.pack("<I", class_id)           # push class_id
    code += b"\x68" + struct.pack("<I", y_bits)             # push y
    code += b"\x68" + struct.pack("<I", x_bits)             # push x
    code += b"\xB8" + struct.pack("<I", spawn_addr)         # mov eax, spawn_addr
    code += b"\xFF\xD0"                                     # call eax
    result_slot_rel = len(code) + 5                         # patched below once base alloc addr known
    code += b"\xA3\x00\x00\x00\x00"                          # mov [result_addr], eax (placeholder)
    code += b"\xC3"                                          # ret

    remote_mem = K32.VirtualAllocEx(pm.process_handle, None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not remote_mem:
        raise RuntimeError(f"VirtualAllocEx failed: {ctypes.GetLastError()}")
    result_addr = remote_mem + 0x800

    # patch the mov [result_addr], eax placeholder now that we know result_addr
    patch_off = code.index(b"\xA3\x00\x00\x00\x00")
    code = code[:patch_off] + b"\xA3" + struct.pack("<I", result_addr) + code[patch_off + 5:]

    pm.write_bytes(remote_mem, code, len(code))
    pm.write_bytes(result_addr, struct.pack("<I", 0), 4)

    hthread = K32.CreateRemoteThread(pm.process_handle, None, 0, remote_mem, None, 0, None)
    if not hthread:
        raise RuntimeError(f"CreateRemoteThread failed: {ctypes.GetLastError()}")
    K32.WaitForSingleObject(hthread, 5000)
    K32.CloseHandle(hthread)

    entity_addr = pm.read_uint(result_addr)
    K32.VirtualFreeEx(pm.process_handle, remote_mem, 0, MEM_RELEASE)
    return entity_addr


def main():
    if len(sys.argv) < 2:
        print("usage: spawn_item.py <item_name> [dx] [dy]")
        print("items:", ", ".join(ITEM_CLASS))
        sys.exit(1)
    name = sys.argv[1].lower()
    if name not in ITEM_CLASS:
        print(f"unknown item '{name}'. known: {', '.join(ITEM_CLASS)}")
        sys.exit(1)
    dx = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
    dy = float(sys.argv[3]) if len(sys.argv) > 3 else 0.6

    pm, base = connect()
    player_addr, px, py = find_player_pos(pm, base)
    if player_addr is None:
        print("Couldn't find an active player - make sure you're in a level with a character seated.")
        sys.exit(1)
    print(f"player at 0x{player_addr:X} pos=({px:.2f},{py:.2f})")

    spawn_x, spawn_y = px + dx, py + dy
    class_id = ITEM_CLASS[name]
    entity_addr = spawn_entity(pm, base, spawn_x, spawn_y, class_id)
    if entity_addr:
        print(f"spawned {name} (class {class_id}) at ({spawn_x:.2f},{spawn_y:.2f}) -> entity 0x{entity_addr:X}")
    else:
        print("SpawnEntity returned NULL - spawn failed.")


if __name__ == "__main__":
    main()
