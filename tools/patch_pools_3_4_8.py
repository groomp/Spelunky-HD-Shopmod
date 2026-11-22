"""Extends the shop-item patch to the 3 remaining pools inside
FUN_004cc0b0 that were left untouched earlier (param_4 == 3, 4, 8) -
smaller specialty rooms that still visually present as a normal walk-in
shop (shelf + shopkeeper + price tags), and so still need forcing.

Same two kinds of edits as the main-pool patch:
  1. literal item-id patch for every case body
  2. for any case body that uses the "goto"/fast-path pattern (skips the
     duplicate-check loop - see patch_dedup_fix.py for the full
     writeup), NOP the `MOV BL,0x1` and retarget its `JMP` to the real
     dedup-check entry point instead of jumping past it.

Addresses are Ghidra's preferred-image-base (0x400000) VAs; translated
to the live, relocated process address via `delta` like the other
patch scripts.
"""

import struct

from spawn_item import connect, ITEM_CLASS

GHIDRA_PREFERRED_BASE = 0x400000

COMPASS = ITEM_CLASS["compass"]      # 0x1fd
TELEPORT = ITEM_CLASS["teleporter"]  # 0x207
JETPACK = ITEM_CLASS["jetpack"]      # 0x20a
BOMBBOX = ITEM_CLASS["bomb_box"]     # 0x1f6

# (case_literal_addr, desired_item_id)
LITERAL_PATCHES = [
    # pool 3 (3 cases)
    (0x4CC4F8, COMPASS),   # case1 - bomb_bag, fast-path
    (0x4CC4EF, TELEPORT),  # case2 - bomb_box, fast-path
    (0x4CC4D1, JETPACK),   # case3 - paste, dedup-checked
    # pool 4 (8 cases, 7 bodies - case1&2 share one body)
    (0x4CC533, COMPASS),    # case1&2 - bomb_bag, fast-path
    (0x4CC53C, TELEPORT),   # case3 - web_gun
    (0x4CC543, JETPACK),    # case4 - spike_shoes
    (0x4CC54A, BOMBBOX),    # case5 - machete
    (0x4CC551, COMPASS),    # case6 - shotgun
    (0x4CC558, TELEPORT),   # case7 - boomerang
    (0x4CC55F, JETPACK),    # case8 - freeze_ray
    # pool 8 (2 cases, no dedup mechanism at all - simple value swap)
    (0x4CC5AC, COMPASS),   # case1 - ropes
    (0x4CC5B3, TELEPORT),  # case2 - bomb_bag
]

# (nop_addr, jmp_addr, dedup_check_entry_target) - fast-path fixes
DEDUP_FIXES = [
    (0x4CC4FD, 0x4CC4FF, 0x4CC4D6),  # pool 3 case1
    (0x4CC4F4, 0x4CC4F6, 0x4CC4D6),  # pool 3 case2
    (0x4CC538, 0x4CC53A, 0x4CC564),  # pool 4 case1&2
]


def main():
    pm, base = connect()
    delta = base - GHIDRA_PREFERRED_BASE

    print("--- literal patches ---")
    for lit_off, new_val in LITERAL_PATCHES:
        addr = lit_off + delta + 1  # +1 to skip the 0xBE opcode byte
        before = struct.unpack("<I", pm.read_bytes(addr, 4))[0]
        pm.write_bytes(addr, struct.pack("<I", new_val), 4)
        after = struct.unpack("<I", pm.read_bytes(addr, 4))[0]
        print(f"  0x{lit_off:X}: 0x{before:X} -> 0x{after:X}")

    print("--- dedup fixes ---")
    for nop_off, jmp_off, target_off in DEDUP_FIXES:
        nop_addr = nop_off + delta
        jmp_addr = jmp_off + delta
        target = target_off + delta

        nop_before = pm.read_bytes(nop_addr, 2)
        jmp_before = pm.read_bytes(jmp_addr, 2)
        if nop_before != b"\xB3\x01":
            print(f"  SKIP 0x{nop_off:X}: unexpected bytes {nop_before.hex()}")
            continue
        if jmp_before[0] != 0xEB:
            print(f"  SKIP 0x{jmp_off:X}: not a short JMP ({jmp_before.hex()})")
            continue

        new_disp = (target - (jmp_addr + 2)) & 0xFF
        pm.write_bytes(nop_addr, b"\x90\x90", 2)
        pm.write_bytes(jmp_addr + 1, bytes([new_disp]), 1)

        nop_after = pm.read_bytes(nop_addr, 2)
        jmp_after = pm.read_bytes(jmp_addr, 2)
        print(f"  0x{nop_off:X}: {nop_before.hex()} -> {nop_after.hex()}   "
              f"0x{jmp_off:X}: {jmp_before.hex()} -> {jmp_after.hex()} (now jumps to 0x{target_off:X})")

    print("pools 3/4/8 patched.")


if __name__ == "__main__":
    main()
