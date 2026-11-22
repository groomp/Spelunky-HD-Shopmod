"""Live diagnostic: polls all kind==Item/known-class entities and logs
(a) the instant a new one appears, with its type, and (b) if an
already-seen entity's type field ever changes afterward - which would
mean something downstream of FUN_004cc0b0 is mutating the item after
creation, rather than the generator itself picking a vanilla value.

Run this, then go find/enter a shop in-game. Ctrl+C to stop.
"""

import sys
import time

sys.path.insert(0, "..")
from spawn_item import connect, find_shop_items, ITEM_CLASS

NAME_BY_ID = {v: k for k, v in ITEM_CLASS.items()}


def main():
    pm, base = connect()
    print(f"watching (pid base=0x{base:X})... go find a shop. ctrl+c to stop.")
    seen = {}  # addr -> (type, first_seen_ts)
    while True:
        try:
            items = find_shop_items(pm, base)
        except Exception as e:
            print(f"[read error: {e}]")
            time.sleep(0.5)
            continue

        current_addrs = set()
        for addr, etype, x, y in items:
            current_addrs.add(addr)
            name = NAME_BY_ID.get(etype, f"UNKNOWN({etype})")
            if addr not in seen:
                seen[addr] = etype
                print(f"[NEW]     0x{addr:X} type={etype} ({name}) at ({x:.1f},{y:.1f})")
            elif seen[addr] != etype:
                old_name = NAME_BY_ID.get(seen[addr], f"UNKNOWN({seen[addr]})")
                print(f"[CHANGED] 0x{addr:X} type {seen[addr]} ({old_name}) -> {etype} ({name})  <<< MUTATED AFTER CREATION")
                seen[addr] = etype

        gone = set(seen) - current_addrs
        for addr in gone:
            del seen[addr]

        time.sleep(0.1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
