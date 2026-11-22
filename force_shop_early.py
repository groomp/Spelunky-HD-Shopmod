"""Timing experiment: the moment `level` flips to TARGET_LEVEL, immediately
(tight poll loop, no 50ms sleep) scans for item-kind entities in the
plausible shop-item type range and overwrites their type to FORCE_TYPE -
testing whether writing before the room has ever been rendered actually
sticks, unlike writing after standing in the shop for a while (confirmed
NOT to change the visible sprite in the live test just done).

Prints timestamps for every stage so we can see how early the write
actually landed relative to level-change detection.
"""

import sys
import time
import pymem

PROCESS_NAME = "Spelunky.exe"
OFFSETS_BY_VERSION = {
    "1.47": {"global_state": 0x15446C, "kali_accepts": 0x112D20},
    "1.4": {"global_state": 0x1384B4, "kali_accepts": 0x108BE4},
}
KALI_ACCEPTS_BYTES = "KALI_ACCEPTS".encode("utf-16-le") + b"\x00\x00"

TARGET_LEVEL = 2  # 1-2
FORCE_TYPE = 522  # Jetpack - distinctive, easy to eyeball
PLAUSIBLE_RANGE = range(500, 534)  # known equipment (503-533) + shop-fixture-adjacent IDs
ARMED_WINDOW_SECONDS = 3.0


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
    base_addr = pm.process_base.lpBaseOfDll
    offsets = None
    for off in OFFSETS_BY_VERSION.values():
        try:
            if pm.read_bytes(base_addr + off["kali_accepts"], 26) == KALI_ACCEPTS_BYTES:
                offsets = off
                break
        except Exception:
            continue
    if offsets is None:
        print("Unrecognized build.")
        sys.exit(1)
    return pm, base_addr, offsets


def read_items(pm, global_state):
    entity_struct_offset = pm.read_uint(global_state + 0x30)
    num_active = pm.read_uint(entity_struct_offset + 0x7810)
    if num_active == 0 or num_active > 5000:
        return []
    ptrs_raw = pm.read_bytes(entity_struct_offset, num_active * 4)
    results = []
    for i in range(num_active):
        addr = int.from_bytes(ptrs_raw[i * 4:i * 4 + 4], "little")
        if addr == 0:
            continue
        try:
            data = pm.read_bytes(addr + 0x8, 20)
        except Exception:
            continue
        kind = int.from_bytes(data[0:4], "little", signed=True)
        etype = int.from_bytes(data[4:8], "little", signed=True)
        if kind == 4:
            results.append((addr, etype))
    return results


def main():
    pm, base_addr, offsets = connect()
    t0 = time.time()
    print(f"[{time.time()-t0:7.3f}] watching for level -> {TARGET_LEVEL} ...", flush=True)

    prev_level = None
    armed_until = None
    written_addrs = set()

    while True:
        try:
            global_state = pm.read_uint(base_addr + offsets["global_state"])
            level = pm.read_uint(global_state + 0x4405D4)
        except Exception:
            time.sleep(0.5)
            continue

        if prev_level is not None and level != prev_level:
            print(f"[{time.time()-t0:7.3f}] level changed {prev_level} -> {level}")
            if level == TARGET_LEVEL:
                armed_until = time.time() + ARMED_WINDOW_SECONDS
                written_addrs.clear()
                print(f"[{time.time()-t0:7.3f}] ARMED - hunting for shop items for {ARMED_WINDOW_SECONDS}s")
        prev_level = level

        if armed_until is not None and time.time() < armed_until:
            items = read_items(pm, global_state)
            candidates = [(a, t) for a, t in items if t in PLAUSIBLE_RANGE and a not in written_addrs]
            for addr, etype in candidates:
                try:
                    pm.write_int(addr + 0xC, FORCE_TYPE)
                    confirm = pm.read_int(addr + 0xC)
                    written_addrs.add(addr)
                    print(f"[{time.time()-t0:7.3f}] wrote 0x{addr:X}: {etype} -> {FORCE_TYPE} (confirm {confirm})")
                except Exception as e:
                    print(f"[{time.time()-t0:7.3f}] write failed on 0x{addr:X}: {e}")
        elif armed_until is not None and time.time() >= armed_until:
            print(f"[{time.time()-t0:7.3f}] disarmed ({len(written_addrs)} entities written total)")
            armed_until = None

        time.sleep(0.01)


if __name__ == "__main__":
    main()
