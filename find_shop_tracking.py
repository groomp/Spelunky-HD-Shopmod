"""Finds the shopkeeper entity and searches memory for any structure that
references the shelf items' own addresses - if the shop/shopkeeper tracks
its inventory by entity pointer, this should reveal exactly where, so a
future swap can update that reference instead of leaving it dangling
(which is what's triggering aggro no matter when the swap happens)."""

import struct

import pymem

from spawn_item import GLOBAL_STATE_OFFSET, connect, find_shop_items
from force_shop_now import _largest_cluster

SHOPKEEPER_TYPE = 1006


def find_monsters(pm, base, type_filter=None):
    global_state = pm.read_uint(base + GLOBAL_STATE_OFFSET)
    entity_struct_offset = pm.read_uint(global_state + 0x30)
    num_active = pm.read_uint(entity_struct_offset + 0x7810)
    ptrs_raw = pm.read_bytes(entity_struct_offset, num_active * 4)
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
        if kind == 3 and (type_filter is None or etype == type_filter):
            results.append((addr, etype))
    return results, global_state, entity_struct_offset


def search_region_for_pointers(pm, region_start, region_size, needles, label):
    try:
        blob = pm.read_bytes(region_start, region_size)
    except Exception as e:
        print(f"  (couldn't read {label}: {e})")
        return
    for needle_addr in needles:
        needle_bytes = struct.pack("<I", needle_addr)
        start = 0
        while True:
            i = blob.find(needle_bytes, start)
            if i == -1:
                break
            found_at = region_start + i
            print(f"  FOUND ref to item 0x{needle_addr:X} at {label}+0x{i:X} (absolute 0x{found_at:X})")
            start = i + 1


def main():
    pm, base = connect()
    all_items = find_shop_items(pm, base)
    cluster = _largest_cluster(all_items)
    if len(cluster) < 2:
        print("Couldn't find a shop shelf cluster - stand right in front of the shop items.")
        return
    item_addrs = [addr for addr, etype, x, y in cluster]
    print(f"shelf cluster: {[(hex(a), t) for a, t, x, y in cluster]}")

    monsters, global_state, entity_struct_offset = find_monsters(pm, base)
    shopkeepers = [(a, t) for a, t in monsters if t == SHOPKEEPER_TYPE]
    print(f"all monster types nearby: {sorted(set(t for a, t in monsters))}")
    print(f"shopkeeper candidates (type=={SHOPKEEPER_TYPE}): {[hex(a) for a, t in shopkeepers]}")

    for shopkeeper_addr, _ in shopkeepers:
        print(f"\n--- scanning around shopkeeper 0x{shopkeeper_addr:X} (+/- 0x2000) ---")
        search_region_for_pointers(pm, shopkeeper_addr - 0x1000, 0x2000, item_addrs, "shopkeeper")

    print(f"\n--- scanning global_state struct (0x{global_state:X}, 0x500000 bytes) ---")
    search_region_for_pointers(pm, global_state, 0x500000, item_addrs, "global_state")

    print(f"\n--- scanning entity_struct_offset table area (0x{entity_struct_offset:X}, 0x10000 bytes) ---")
    search_region_for_pointers(pm, entity_struct_offset - 0x4000, 0x10000, item_addrs, "entity_table_area")


if __name__ == "__main__":
    main()
