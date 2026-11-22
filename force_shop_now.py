"""Replaces whatever items a shop actually rolled with the desired set:
moves each existing shop-item entity far out of the way (position write -
already confirmed safe/working, unlike overwriting its type field), then
spawns a correct, fully-functional replacement item at the original spot
via the game's own SpawnEntity (spawn_item.py).

Doing this upsets the shopkeeper (it tracks its own items somehow, not
found via a nearby-pointer search), so right after swapping we also force
its hostility flags back to their calm-baseline values (found by diffing
its own entity memory before/after a real aggro event) for a few seconds,
in case the hostile behavior keeps re-triggering on its own."""

import struct
import sys
import time

from spawn_item import GLOBAL_STATE_OFFSET, connect, find_shop_items, move_entity, spawn_entity, ITEM_CLASS

SHOPKEEPER_TYPE = 1006
CALM_FLAGS = {0x134: 0, 0x204: 1, 0x218: 1}
CALM_HOLD_SECONDS = 5.0
CALM_POLL_SECONDS = 0.05


def find_shopkeepers(pm, base):
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
        if kind == 3 and etype == SHOPKEEPER_TYPE:
            results.append(addr)
    return results


def calm_shopkeepers(pm, base):
    for addr in find_shopkeepers(pm, base):
        for off, val in CALM_FLAGS.items():
            pm.write_bytes(addr + off, struct.pack("<I", val), 4)


def hold_shopkeepers_calm(pm, base, seconds=CALM_HOLD_SECONDS):
    t_end = time.time() + seconds
    while time.time() < t_end:
        try:
            calm_shopkeepers(pm, base)
        except Exception:
            pass
        time.sleep(CALM_POLL_SECONDS)

DEFAULT_DESIRED = ["jetpack", "teleporter", "compass", "bomb_box"]


def _largest_cluster(items, max_gap=3.0):
    """Shop shelves place items in a tight row; a loose equipment item
    sitting on an altar or found elsewhere in the level is far from
    everything else. Groups items by proximity (single-link, max_gap
    between consecutive sorted-by-x members of the same cluster) and
    keeps only the biggest group."""
    if not items:
        return []
    by_x = sorted(items, key=lambda it: it[2])
    clusters = [[by_x[0]]]
    for item in by_x[1:]:
        if item[2] - clusters[-1][-1][2] <= max_gap:
            clusters[-1].append(item)
        else:
            clusters.append([item])
    return max(clusters, key=len)


def force_shop(desired=None):
    desired = desired or DEFAULT_DESIRED
    pm, base = connect()
    all_items = find_shop_items(pm, base)
    items = _largest_cluster(all_items)
    if not items:
        print("No shop items found nearby - stand in/near a shop first.")
        return []
    if len(items) != len(all_items):
        print(f"ignoring {len(all_items) - len(items)} item(s) too far from the shelf cluster to be real shop items")
    print(f"found {len(items)} shop item(s)")
    results = []
    for i, (addr, etype, x, y) in enumerate(items):
        item_name = desired[i % len(desired)]
        # Copy the real generator's post-spawn shop-membership markers
        # (set by FUN_004dd1e0 in the real generator, FUN_004cc0b0) from
        # the original item before replacing it: byte+0x1F4=1 ("belongs
        # to a shop"), int+0x160=<room/slot index>, matching what a
        # genuinely-generated item would have.
        shop_flag = pm.read_bytes(addr + 0x1F4, 1)
        slot_index = pm.read_bytes(addr + 0x160, 4)
        new_addr = spawn_entity(pm, base, x, y, ITEM_CLASS[item_name])
        pm.write_bytes(new_addr + 0x1F4, shop_flag, 1)
        pm.write_bytes(new_addr + 0x160, slot_index, 4)
        move_entity(pm, addr, x, -500.0 - i)
        print(f"  slot {i}: old type={etype} at ({x:.2f},{y:.2f}) -> {item_name} (0x{new_addr:X})")
        results.append((item_name, new_addr))

    calm_shopkeepers(pm, base)
    print(f"holding shopkeeper(s) calm for {CALM_HOLD_SECONDS}s...")
    hold_shopkeepers_calm(pm, base)
    print("done")
    return results


if __name__ == "__main__":
    desired = sys.argv[1:] if len(sys.argv) > 1 else None
    force_shop(desired)
