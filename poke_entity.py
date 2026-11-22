"""Live test harness: lists item-kind entities near a given bin area, and
can overwrite one entity's type field (addr+0xC) to a chosen value so we
can visually confirm, in-game, which memory address corresponds to which
real shop item, and that writing entity_type actually works."""

import sys
import pymem

PROCESS_NAME = "Spelunky.exe"
OFFSETS_BY_VERSION = {
    "1.47": {"global_state": 0x15446C, "kali_accepts": 0x112D20},
    "1.4": {"global_state": 0x1384B4, "kali_accepts": 0x108BE4},
}
KALI_ACCEPTS_BYTES = "KALI_ACCEPTS".encode("utf-16-le") + b"\x00\x00"


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


def list_items(pm, base_addr, offsets, min_x, max_x, min_y, max_y):
    global_state = pm.read_uint(base_addr + offsets["global_state"])
    entity_struct_offset = pm.read_uint(global_state + 0x30)
    num_active = pm.read_uint(entity_struct_offset + 0x7810)
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
        bin_x = int.from_bytes(data[8:12], "little")
        bin_y = int.from_bytes(data[12:16], "little")
        owner = int.from_bytes(data[16:20], "little", signed=True)
        if kind == 4 and min_x <= bin_x <= max_x and min_y <= bin_y <= max_y:
            results.append((addr, etype, bin_x, bin_y, owner))
    return results


def main():
    pm, base_addr, offsets = connect()
    items = list_items(pm, base_addr, offsets, 5, 8, 16, 19)
    print(f"{len(items)} item entities in bin range x[5-8] y[16-19]:")
    for i, (addr, etype, bin_x, bin_y, owner) in enumerate(items):
        print(f"  [{i}] addr=0x{addr:X} type={etype} bin=({bin_x},{bin_y}) owner={owner}")

    if len(sys.argv) >= 3:
        idx = int(sys.argv[1])
        new_type = int(sys.argv[2])
        addr = items[idx][0]
        old_type = pm.read_int(addr + 0xC)
        pm.write_int(addr + 0xC, new_type)
        confirm = pm.read_int(addr + 0xC)
        print(f"\nWrote index [{idx}] (addr=0x{addr:X}): type {old_type} -> {new_type} (read back: {confirm})")


if __name__ == "__main__":
    main()
