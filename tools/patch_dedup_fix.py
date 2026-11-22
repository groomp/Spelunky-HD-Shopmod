"""Fixes a duplicate-item bug left over from the shop-pool patch (see
shop_gen_real.txt / disasm_cc0b0.txt): FUN_004cc0b0 has a handful of
"fast path" switch-cases (originally the stackable consumables - ropes/
bomb_bag/bomb_box for the general store, bomb_box for the weapon shop,
bomb_bag for the clothing shop) that set bVar2=true and `goto` straight
past the duplicate-check loop. Our earlier patch (patch_shop_items.py-
style inline edit) overwrote every case's item-id literal with one of
our 4 desired items, including these fast-path cases - so a fast-path
case can now hand out an item that's ALSO being produced (and properly
deduped) by a normal case, giving a shop with a repeated item.

Fix: for each fast-path case, NOP out its `MOV BL,0x1` (so it stops
forcing bVar2=true) and retarget its `JMP` to land on the same dedup-
check entry point the normal ("break") cases already use, instead of
jumping past it. This makes every case - fast-path or not - go through
the real duplicate check.

Each entry: (nop_addr, jmp_addr, new_jmp_target).
"""

import struct

from spawn_item import connect

PATCHES = [
    # general store (param_4 == 0): cases 1,2,3 (ropes/bomb_bag/bomb_box)
    (0x4CC324, 0x4CC326, 0x4CC34D),
    (0x4CC32D, 0x4CC32F, 0x4CC34D),
    (0x4CC336, 0x4CC338, 0x4CC34D),
    # weapon shop (param_4 == 1): case 1 (bomb_box)
    (0x4CC3B4, 0x4CC3B6, 0x4CC3F5),
    # clothing shop (param_4 == 2): case 1 (bomb_bag)
    (0x4CC44B, 0x4CC44D, 0x4CC477),
]


GHIDRA_PREFERRED_BASE = 0x400000


def main():
    pm, base = connect()
    delta = base - GHIDRA_PREFERRED_BASE
    for nop_addr_off, jmp_addr_off, target_off in PATCHES:
        nop_addr = nop_addr_off + delta
        jmp_addr = jmp_addr_off + delta
        target = target_off + delta

        nop_before = pm.read_bytes(nop_addr, 2)
        jmp_before = pm.read_bytes(jmp_addr, 2)
        if nop_before != b"\xB3\x01":
            print(f"  SKIP 0x{nop_addr_off:X}: unexpected bytes {nop_before.hex()} (already patched?)")
            continue
        if jmp_before[0] != 0xEB:
            print(f"  SKIP 0x{jmp_addr_off:X}: not a short JMP ({jmp_before.hex()})")
            continue

        new_disp = (target - (jmp_addr + 2)) & 0xFF
        pm.write_bytes(nop_addr, b"\x90\x90", 2)
        pm.write_bytes(jmp_addr + 1, bytes([new_disp]), 1)

        nop_after = pm.read_bytes(nop_addr, 2)
        jmp_after = pm.read_bytes(jmp_addr, 2)
        print(f"  0x{nop_addr_off:X}: {nop_before.hex()} -> {nop_after.hex()}   "
              f"0x{jmp_addr_off:X}: {jmp_before.hex()} -> {jmp_after.hex()} (now jumps to 0x{target_off:X})")

    print("dedup fix applied.")


if __name__ == "__main__":
    main()
