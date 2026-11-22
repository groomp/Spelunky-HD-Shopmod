"""Shared memory-patch logic for FUN_004cc0b0 (Spelunky.exe's shop item
pool generator) - consolidates everything applied manually over the
course of this session into one reapplyable module:

  1. ensure_structural_fixes(): one-time, idempotent control-flow edits
     - closes the "fast path" duplicate-item bug (a handful of switch
       cases skip the dedup-check loop entirely - see the NOP+JMP
       retargets below) and disables the 1-in-20 "mystery box" branch.
  2. apply_item_order(): cheap, repeatable - just rewrites the 4-byte
     item-id literal for every case in every pool, cycling through
     whatever 4-item order is given. Safe to call every time the user
     reorders items or switches variant in the GUI.

All addresses are Ghidra-preferred-image-base (0x400000) VAs; translated
to the live, relocated process address via `delta`.
"""

import ctypes
import ctypes.wintypes as w
import struct

import pefile

from spawn_item import (
    connect, ITEM_CLASS, GLOBAL_STATE_OFFSET,
    K32, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
)

GHIDRA_PREFERRED_BASE = 0x400000

LEVEL_OFFSET = 0x4405D4  # same raw whole-game level counter pb_tracker's game_reader.py reads
# Simple 1-indexed current-level number, matching "1-N" notation
# directly: raw=1 is 1-1, raw=2 is 1-2, raw=3 is 1-3, etc - confirmed
# live and directly, twice (raw read 2 while standing in 1-2, with no
# ambiguity about timing). An earlier "fix" here briefly changed this
# to 1, based on a misread (a stale/mistimed live check made it look
# like raw=2 corresponded to 1-3 instead) - that undercounted by one
# level, stopping forcing a level too early (1-2 itself went vanilla).
# Reverted. FORCE_UPTO_LEVEL=2 correctly means "force through 1-2,
# vanilla from 1-3 on".
FORCE_UPTO_LEVEL = 2

VARIANTS = {
    "Any% Shop": ["jetpack", "teleporter", "compass", "bomb_box"],
    "No TP Any% Shop": ["jetpack", "bomb_box", "mattock", "compass"],
}

# pool name -> ordered list of case-literal VA offsets (one per switch case)
POOL_GROUPS = {
    "general_store": [0x4CC31F, 0x4CC328, 0x4CC331, 0x4CC33A, 0x4CC341, 0x4CC348],
    "weapon_shop": [0x4CC3AF, 0x4CC3B8, 0x4CC3BF, 0x4CC3C6, 0x4CC3CD,
                    0x4CC3D4, 0x4CC3DB, 0x4CC3E2, 0x4CC3E9, 0x4CC3F0],
    "clothing_shop": [0x4CC446, 0x4CC44F, 0x4CC456, 0x4CC45D, 0x4CC464, 0x4CC46B, 0x4CC472],
    "pool3": [0x4CC4F8, 0x4CC4EF, 0x4CC4D1],
    "pool4": [0x4CC533, 0x4CC53C, 0x4CC543, 0x4CC54A, 0x4CC551, 0x4CC558, 0x4CC55F],
    # pool8 deliberately absent here - its 2 native case literals
    # (0x4CC5AC, 0x4CC5B3) now live inside the overwritten/NOP'd
    # jmp-in region below and are no longer valid independent targets.
    # Its 4 (extended) case literals live in the code cave instead -
    # see _cave_literals.
}

# (nop_addr, jmp_addr, dedup_check_entry_target) - fast-path/skip-dedup fixes
DEDUP_FIXES = [
    (0x4CC324, 0x4CC326, 0x4CC34D),  # general store case1 (ropes)
    (0x4CC32D, 0x4CC32F, 0x4CC34D),  # general store case2 (bomb_bag)
    (0x4CC336, 0x4CC338, 0x4CC34D),  # general store case3 (bomb_box)
    (0x4CC3B4, 0x4CC3B6, 0x4CC3F5),  # weapon shop case1 (bomb_box)
    (0x4CC44B, 0x4CC44D, 0x4CC477),  # clothing shop case1 (bomb_bag)
    (0x4CC4FD, 0x4CC4FF, 0x4CC4D6),  # pool3 case1 (bomb_bag)
    (0x4CC4F4, 0x4CC4F6, 0x4CC4D6),  # pool3 case2 (bomb_box)
    (0x4CC538, 0x4CC53A, 0x4CC564),  # pool4 case1&2 (bomb_bag)
]

MYSTERY_BOX_JNZ_OFFSET = 0x4CC5E6

# --- pool3/pool4/pool8 history: re-enabled 2026-11-21 after an earlier
# bisection test had them disabled over a crash that turned out to be
# unrelated (see git history for that investigation). That re-enable
# then surfaced two real, structural bugs, both now fixed for good
# below instead of worked around:
#
#   1. pool3's switch only has 3 case branches, pool8's only 2 - but
#      every shop (any pool) always fills exactly 4 shelf slots. Once
#      forced to a custom item set, neither pool could ever produce a
#      4th distinct item: pool3, with its dedup-check fast-path fix
#      enabled, span forever on the unreachable 4th slot (confirmed via
#      cdb attach to a frozen Spelunky - main thread spinning at VA
#      0x4CC4E9); pool8, which has ZERO duplicate protection in vanilla
#      (confirmed via Ghidra decompile), just silently duplicated one
#      of its 2 reachable items across all 4 slots instead ("4
#      teleporters" in one observed shop).
#   2. Forgetting to also clear _DISABLED_DEDUP_NOP_OFFSETS (below)
#      alongside DISABLED_POOLS left pool4's duplicate-prevention
#      fast-path fix reverted to vanilla, producing a duplicate forced
#      item (two jetpacks in one pool4 shop).
#
# The real fix for (1): pool3 and pool8 are extended with a small code
# cave (see _build_pool3_stub/_build_pool8_stub below) adding the
# missing case(s) so both pools have exactly 4 reachable, dedup-checked
# case values for their 4 shelf slots - genuinely reachable now, not
# cosmetically patched over. With that in place, both DISABLED_POOLS
# and _DISABLED_DEDUP_NOP_OFFSETS can stay empty permanently: every
# pool (general_store/weapon_shop/clothing_shop/pool3/pool4/pool8) now
# has >=4 distinct dedup-checked case values for its 4 slots, so none
# of them can hang (pigeonhole: by the 4th slot exactly one distinct
# value is left unused, and cycling is guaranteed to find it) and none
# of them can show an off-list or duplicated item.
DISABLED_POOLS = set()
_DISABLED_DEDUP_NOP_OFFSETS = set()


def _delta(base):
    return base - GHIDRA_PREFERRED_BASE


def _active_pool_groups():
    return {name: group for name, group in POOL_GROUPS.items() if name not in DISABLED_POOLS}


def _active_dedup_fixes():
    return [fix for fix in DEDUP_FIXES if fix[0] not in _DISABLED_DEDUP_NOP_OFFSETS]


# --- pool3/pool8 case-extension cave -----------------------------------
#
# Hand-assembled x86 stubs, verified instruction-by-instruction against
# a live disassembly of the real Spelunky HD exe (D:\Steam\...\Spelunky.exe,
# not the Spelunky Classic freeware exe some other drives have lying
# around - confirm with `u <addr>` in cdb against the actual running
# build before ever touching these again).
#
# Shared register convention (same enclosing function, FUN_004cc0b0,
# for every pool branch): esi = candidate item id, bl = accept(1)/
# reject(0), ebp = count of items already placed this shop (local_18),
# [esp + idx*4 + 0x1C] = local_10[idx] (the already-placed item ids) -
# all confirmed consistent across branches since none of them push/pop
# anything unbalanced before reaching their own dispatch.

CAVE_SIZE = 256

POOL3_JMP_IN = 0x4CC4CC          # 'sub eax,1; jne 0x4CC4D6' (5 bytes)
POOL3_JMP_IN_VANILLA = b"\x83\xE8\x01\x75\x05"
POOL3_CASE3_FALLBACK = 0x4CC4D1  # existing 'mov esi,0x1FCh', falls through to...
POOL3_DEDUP_ENTRY = 0x4CC4D6     # ...the shared dedup-check entry (eax-as-scratch safe: pool3's own cycle var is edx)
POOL3_MOD_ADDR = 0x4CC4B2        # immediate byte of 'mov ecx,3' (case-count/cycle-wrap modulus)

POOL8_JMP_IN = 0x4CC5A0          # 'mov ecx,eax ... mov bl,1' (26 bytes, native 2-case/zero-dedup dispatch)
POOL8_JMP_IN_VANILLA_PREFIX = b"\x8B\xC8"
POOL8_JMP_IN_LEN = 26
POOL8_CONTINUE = 0x4CC5BA        # original 'inc eax' - resumes pool8's own 1..4 cycle/wrap
# POOL8_MOD_A_ADDR (0x4CC59C, "and eax,1"'s mask immediate) used to be
# patched 1->3 here, as part of reaching 4 cases. That address is now
# INSIDE the ORDER_PRELUDES pool8 region below - the deterministic-
# order patch replaces that whole RNG-pick prelude outright, making
# the old 1-byte mask tweak moot (it never runs once this is patched).
POOL8_MOD_B_ADDR = 0x4CC5BD      # immediate byte of 'cmp eax,6' (cycle-wrap bound) - still needed, outside ORDER_PRELUDES' range


def _asm_jmp32(from_addr, to_addr):
    return b"\xE9" + struct.pack("<i", to_addr - (from_addr + 5))


def _asm_call32(from_addr, to_addr):
    return b"\xE8" + struct.pack("<i", to_addr - (from_addr + 5))


def _build_pool3_stub(cave_addr, delta):
    """20 bytes. Replaces POOL3_JMP_IN. Entry state: eax = edx-2 (edx is
    pool3's own case-cycle var, now cycling 1..4 - see POOL3_MOD_ADDR).
    eax==1 -> original case3 (edx==3): jmp the EXISTING 0x4CC4D1 'mov
    esi,0x1FCh', which itself falls through to POOL3_DEDUP_ENTRY.
    eax==2 -> new case4 (edx==4): set esi to our 4th forced item (the
    literal this returns the address of) and jump straight into the
    same shared dedup entry.

    delta relocates the two jump TARGETS below back into the exe
    (POOL3_CASE3_FALLBACK/POOL3_DEDUP_ENTRY are Ghidra-preferred-base
    constants) - cave_addr itself is already an absolute live address
    and needs no relocation. Missing this the first time around sent
    the jump to literal offset 0xCC4D6 regardless of where the exe
    actually loaded, landing in unrelated code on any run where the
    exe's ASLR base differs from the preferred 0x400000 - confirmed via
    a live crash dump (eip ended up executing garbage at that raw
    offset, reading through an unrelated ebp and faulting)."""
    code = bytearray(20)
    code[0:3] = b"\x83\xF8\x01"                                              # cmp eax,1
    code[3:5] = b"\x75\x05"                                                  # jne +5 -> offset 10
    code[5:10] = _asm_jmp32(cave_addr + 5, POOL3_CASE3_FALLBACK + delta)     # jmp 0x4CC4D1
    code[10:15] = b"\xBE" + struct.pack("<I", 0)                            # mov esi, <case4 id>
    code[15:20] = _asm_jmp32(cave_addr + 15, POOL3_DEDUP_ENTRY + delta)     # jmp 0x4CC4D6
    lit_addr = cave_addr + 11
    return bytes(code), lit_addr


def _build_pool8_stub(cave_addr, delta):
    """71 bytes. Replaces POOL8_JMP_IN entirely with a fresh 4-case
    lookup (eax = pool8's own case-cycle var, now cycling 1..4 - see
    POOL8_MOD_A_ADDR/POOL8_MOD_B_ADDR) plus a self-contained dedup
    check (pool8 has none natively, unlike pool3/pool4 - eax is
    preserved across it via push/pop since, unlike pool3's shared
    dedup block, pool8 itself needs eax to survive), then resumes
    pool8's native cycle at POOL8_CONTINUE. delta relocates that last
    jump target back into the exe - see _build_pool3_stub's docstring
    for why this matters."""
    code = bytearray(71)

    def case_block(off, cmp_val, next_off):
        code[off:off + 3] = bytes([0x83, 0xF8, cmp_val])             # cmp eax,cmp_val
        code[off + 3:off + 5] = bytes([0x75, (next_off - (off + 5)) & 0xFF])  # jne next_off
        code[off + 5:off + 10] = b"\xBE" + struct.pack("<I", 0)      # mov esi, <id>
        code[off + 10:off + 12] = bytes([0xEB, (41 - (off + 12)) & 0xFF])  # jmp DEDUP(41)
        return off + 6  # literal address (skip the BE opcode byte)

    lit_offsets = [
        case_block(0, 1, 12),
        case_block(12, 2, 24),
        case_block(24, 3, 36),
    ]
    code[36:41] = b"\xBE" + struct.pack("<I", 0)                     # case4: mov esi, <id> (falls into DEDUP)
    lit_offsets.append(37)

    # DEDUP block @41
    code[41:42] = b"\x50"                                           # push eax
    code[42:44] = b"\x33\xC0"                                       # xor eax,eax
    code[44:46] = b"\xB3\x01"                                       # mov bl,1
    code[46:48] = b"\x85\xED"                                       # test ebp,ebp
    code[48:50] = bytes([0x7E, 65 - 50])                            # jle DONE(65)
    code[50:54] = b"\x39\x74\x84\x20"                                # cmp [esp+eax*4+0x20],esi (0x1C+4 for our push eax)
    code[54:56] = bytes([0x74, 63 - 56])                            # je REJECT(63)
    code[56:57] = b"\x40"                                           # inc eax
    code[57:59] = b"\x3B\xC5"                                       # cmp eax,ebp
    code[59:61] = bytes([0x7C, (50 - 61) & 0xFF])                   # jl LOOP(50)
    code[61:63] = bytes([0xEB, 65 - 63])                            # jmp DONE(65)
    code[63:65] = b"\x32\xDB"                                       # xor bl,bl  (REJECT@63)
    code[65:66] = b"\x58"                                           # pop eax    (DONE@65)
    code[66:71] = _asm_jmp32(cave_addr + 66, POOL8_CONTINUE + delta)  # jmp 0x4CC5BA

    lit_addrs = [cave_addr + o for o in lit_offsets]
    return bytes(code), lit_addrs


# --- deterministic shelf-position ordering -----------------------------
#
# Every pool's item pick for a given shelf slot was, until now, chosen
# by RNG (dedup only prevented repeats within one shop) - so while a
# shop only ever offered the chosen 4 items, WHICH of those 4 landed on
# WHICH shelf position (left to right) was still random per shop.
#
# The shelf-slot index (0,1,2,3, incrementing left-to-right, one fill
# per outer-loop iteration) is EBP itself, as a plain integer register
# - NOT a float, and NOT "[ebp-0x18]" (that first version crashed live:
# this function never establishes a true EBP stack frame - no 'push
# ebp; mov ebp,esp' prologue - EBP is just a repurposed scratch
# register here, confirmed to be holding something else entirely, like
# 0, at the point an earlier version of this tried to dereference it as
# an address). Confirmed for real this time by finding the loop's own
# back-edge in the disassembly: 'inc ebp; cmp ebp,4; jl <loop top>' -
# an unambiguous, direct register increment-and-bound-check, no memory
# or FPU involved. This also matches (and explains) the existing,
# already-tested pool3/pool8 dedup code above, which already treats
# ebp as "count of items placed so far" (test ebp,ebp /
# [esp+idx*4+0x1C] bound) - same register, same meaning, the whole
# time; Ghidra's decompiled "float local_18/fVar4" was decompiler noise
# from this register's value also feeding into unrelated FPU coordinate
# math elsewhere, not a sign it's ever genuinely a float itself.
#
# Replacing each pool's "call RNG; mod N" prelude with a call to this
# shared cave routine makes the very first case tried for shelf slot N
# always be case N+1. Since apply_item_order (above) already assigns
# the player's order[0..3] to cases 1..4 for every pool (pools with
# more than 4 cases just never reach the extra ones now - harmless,
# they're simply never picked), shelf slot 0 always ends up with the
# player's first chosen item, slot 1 the second, etc. - the drag-order
# from the panel, left to right, every shop, every pool.
READ_SLOT_PLUS1_STUB = bytes([
    0x8B, 0xC5,                   # mov eax, ebp                     (the slot index, already a plain int)
    0x40,                         # inc eax                          (1-indexed, matching case numbering)
    0xC3,                         # ret
])

RNG_FUNC_ADDR = 0x00407d10

# (prelude_addr, byte_length, output_in_edx) - each region is the
# pool's own "call RNG; <mask-or-div-by-N>; <result ends up in eax or
# edx>" prelude, replaced wholesale with 'call cave_routine' (+
# 'mov edx,eax' when the pool's own dispatch reads its case number
# from edx rather than eax) + NOP padding to fill the rest.
ORDER_PRELUDES = [
    (0x4CC2FB, 15, True),   # general_store: call; xor edx,edx; mov ecx,6; div eax,ecx; inc edx
    (0x4CC38B, 15, True),   # weapon_shop:   call; xor edx,edx; mov ecx,0Ah; div eax,ecx; inc edx
    (0x4CC428, 15, True),   # clothing_shop: call; xor edx,edx; mov ecx,7; div eax,ecx; inc edx
    (0x4CC4AA, 15, True),   # pool3:         call; xor edx,edx; mov ecx,3; div eax,ecx; inc edx
    (0x4CC51B, 9, False),   # pool4:         call; and eax,7; inc eax
    (0x4CC595, 9, False),   # pool8:         call; and eax,1 (or ,3 from the old case-extension fix); inc eax
]


def _prelude_still_calls_rng(pm, live_addr, delta):
    """True if this prelude's first 5 bytes are still a CALL into the
    RNG function - true for genuinely vanilla bytes AND for pool8's
    earlier one-byte mask tweak (still calls the RNG, just with a wider
    mask after it) - both cases this patch hasn't been applied yet.
    live_addr must already be relocated (delta added) - only the
    comparison target (a Ghidra-preferred-base constant) needs delta
    applied here."""
    live = pm.read_bytes(live_addr, 5)
    if live[0] != 0xE8:
        return False
    rel = struct.unpack("<i", live[1:5])[0]
    target = live_addr + 5 + rel
    return target == RNG_FUNC_ADDR + delta


ENABLE_DETERMINISTIC_ORDER = True  # re-enabled - see READ_SLOT_PLUS1_STUB's docstring for the corrected mechanism (ebp is the plain slot counter itself, confirmed via the loop's own back-edge disassembly)


def _ensure_order_prelude_patches(pm, base):
    if not ENABLE_DETERMINISTIC_ORDER:
        return
    _ensure_cave_allocated(pm, base)
    delta = _delta(base)
    order_routine = _cave_state["order_routine_addr"]
    for addr, length, output_in_edx in ORDER_PRELUDES:
        live_addr = addr + delta
        if not _prelude_still_calls_rng(pm, live_addr, delta):
            continue  # already patched
        call_bytes = _asm_call32(live_addr, order_routine)
        if output_in_edx:
            patch = call_bytes + b"\x89\xC2" + b"\x90" * (length - 7)  # + mov edx,eax
        else:
            patch = call_bytes + b"\x90" * (length - 5)
        pm.write_bytes(live_addr, patch, length)


def _alloc_cave(pm):
    addr = K32.VirtualAllocEx(pm.process_handle, None, CAVE_SIZE,
                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not addr:
        raise OSError(f"VirtualAllocEx failed for pool-extension cave: {ctypes.GetLastError()}")
    return addr


_cave_state = {"base": None, "pid": None, "addr": None, "p8_addr": None, "order_routine_addr": None}
_cave_literals = {}


def _ensure_cave_allocated(pm, base):
    if _cave_state["base"] == base and _cave_state["pid"] == pm.process_id:
        return
    delta = _delta(base)
    cave_addr = _alloc_cave(pm)

    p3_stub, p3_lit = _build_pool3_stub(cave_addr, delta)
    pm.write_bytes(cave_addr, p3_stub, len(p3_stub))

    p8_addr = cave_addr + len(p3_stub)
    p8_stub, p8_lits = _build_pool8_stub(p8_addr, delta)
    pm.write_bytes(p8_addr, p8_stub, len(p8_stub))

    order_routine_addr = p8_addr + len(p8_stub)
    pm.write_bytes(order_routine_addr, READ_SLOT_PLUS1_STUB, len(READ_SLOT_PLUS1_STUB))

    _cave_state.update(base=base, pid=pm.process_id, addr=cave_addr, p8_addr=p8_addr,
                        order_routine_addr=order_routine_addr)

    global _cave_literals
    _cave_literals = {
        "pool3": [(3, p3_lit)],
        "pool8": [(0, p8_lits[0]), (1, p8_lits[1]), (2, p8_lits[2]), (3, p8_lits[3])],
    }


def _ensure_pool_extension_patches(pm, base):
    """One-time (per process) extension of pool3 (3->4 cases) and
    pool8 (2->4 cases). Idempotent via live-byte checks, like the
    dedup fixes above, so it correctly re-applies after restore_vanilla
    reverts it past FORCE_UPTO_LEVEL and the level range is re-entered."""
    _ensure_cave_allocated(pm, base)
    delta = _delta(base)
    cave_addr = _cave_state["addr"]
    p8_addr = _cave_state["p8_addr"]

    p3_addr = POOL3_JMP_IN + delta
    if pm.read_bytes(p3_addr, 5) == POOL3_JMP_IN_VANILLA:
        pm.write_bytes(p3_addr, _asm_jmp32(p3_addr, cave_addr), 5)

    p8_jmp_addr = POOL8_JMP_IN + delta
    if pm.read_bytes(p8_jmp_addr, 2) == POOL8_JMP_IN_VANILLA_PREFIX:
        patch = _asm_jmp32(p8_jmp_addr, p8_addr) + b"\x90" * (POOL8_JMP_IN_LEN - 5)
        pm.write_bytes(p8_jmp_addr, patch, POOL8_JMP_IN_LEN)

    mod_p3 = POOL3_MOD_ADDR + delta
    if pm.read_bytes(mod_p3, 1) == b"\x03":
        pm.write_bytes(mod_p3, b"\x04", 1)

    mod_p8b = POOL8_MOD_B_ADDR + delta
    if pm.read_bytes(mod_p8b, 1) == b"\x06":
        pm.write_bytes(mod_p8b, b"\x04", 1)


def ensure_structural_fixes(pm, base):
    """Idempotent - safe to call every reconnect. Skips any fix whose
    bytes no longer look like the original (already patched)."""
    delta = _delta(base)

    # Must run before the dedup fixes below: pool3's case1/case2 fixes
    # are only hang-safe once pool3 actually has a 4th reachable case.
    _ensure_pool_extension_patches(pm, base)
    _ensure_order_prelude_patches(pm, base)

    for nop_off, jmp_off, target_off in _active_dedup_fixes():
        nop_addr = nop_off + delta
        jmp_addr = jmp_off + delta
        target = target_off + delta
        if pm.read_bytes(nop_addr, 2) != b"\xB3\x01":
            continue  # already patched (or unexpected - don't touch)
        new_disp = (target - (jmp_addr + 2)) & 0xFF
        pm.write_bytes(nop_addr, b"\x90\x90", 2)
        pm.write_bytes(jmp_addr + 1, bytes([new_disp]), 1)

    jnz_addr = MYSTERY_BOX_JNZ_OFFSET + delta
    if pm.read_bytes(jnz_addr, 1) == b"\x75":
        pm.write_bytes(jnz_addr, b"\xEB", 1)


def apply_item_order(pm, base, order):
    """order: list of 1-4 item-name strings (from ITEM_CLASS). Cycles
    across every active pool's case slots so every shop variant only
    ever offers these, in this priority order. Pools in DISABLED_POOLS
    are left out (see bisection-test note above)."""
    delta = _delta(base)
    ids = [ITEM_CLASS[name] for name in order]
    for group in _active_pool_groups().values():
        for i, off in enumerate(group):
            addr = off + delta + 1  # +1 to skip the MOV ESI opcode byte
            pm.write_bytes(addr, struct.pack("<I", ids[i % len(ids)]), 4)
    for name, entries in _cave_literals.items():
        if name in DISABLED_POOLS:
            continue
        for idx, lit_addr in entries:  # lit_addr is already an absolute live address
            pm.write_bytes(lit_addr, struct.pack("<I", ids[idx % len(ids)]), 4)


def connect_and_patch(order):
    """Convenience: connect, apply structural fixes, apply the given
    item order. Returns (pm, base)."""
    pm, base = connect()
    ensure_structural_fixes(pm, base)
    apply_item_order(pm, base, order)
    return pm, base


def read_level(pm, base):
    """Raw whole-game level counter (1-indexed, +1 per level including
    bonus ones - same offset pb_tracker's game_reader.py uses). Returns
    0 outside any level (menu/camp), or None on a transient read failure
    (e.g. mid level-load)."""
    try:
        global_state = pm.read_uint(base + GLOBAL_STATE_OFFSET)
        return pm.read_uint(global_state + LEVEL_OFFSET)
    except Exception:
        return None


def should_force(level):
    """level=0 (camp/menu, nothing generated yet) and level=None (a
    transient read failure) both count as "force" so the patch is
    already live and correct the instant the next level loads, instead
    of racing the level-load screen to catch the transition."""
    return level is None or level == 0 or level <= FORCE_UPTO_LEVEL


# --- vanilla (unpatched) byte snapshot, read straight from Spelunky.exe
# on disk - lets us fully undo every edit below (both the item literals
# and the structural fixes) regardless of whatever the live, already-
# patched process currently holds in memory, so shops past the forced
# level range run completely unmodified original code.

_vanilla_snapshot = None


def _get_exe_path(pm):
    K32 = ctypes.windll.kernel32
    buf = ctypes.create_unicode_buffer(260)
    size = w.DWORD(260)
    if not K32.QueryFullProcessImageNameW(pm.process_handle, 0, buf, ctypes.byref(size)):
        raise OSError("couldn't resolve Spelunky.exe's own path on disk")
    return buf.value


def _read_disk_bytes(pe, image_base, va_offset, length):
    rva = va_offset - image_base
    file_off = pe.get_offset_from_rva(rva)
    return pe.__data__[file_off:file_off + length]


_CAVE_PATCH_REGIONS = [
    (POOL3_JMP_IN, 5),
    (POOL8_JMP_IN, POOL8_JMP_IN_LEN),
    (POOL3_MOD_ADDR, 1),
    (POOL8_MOD_B_ADDR, 1),
] + [(addr, length) for addr, length, _ in ORDER_PRELUDES]


def _build_vanilla_snapshot(pm):
    pe = pefile.PE(_get_exe_path(pm), fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    literals = {
        off: _read_disk_bytes(pe, image_base, off + 1, 4)
        for group in POOL_GROUPS.values() for off in group
    }
    nops = {off: _read_disk_bytes(pe, image_base, off, 2) for off, _, _ in DEDUP_FIXES}
    jmps = {off: _read_disk_bytes(pe, image_base, off, 2) for _, off, _ in DEDUP_FIXES}
    jnz = _read_disk_bytes(pe, image_base, MYSTERY_BOX_JNZ_OFFSET, 1)
    cave_regions = {
        off: _read_disk_bytes(pe, image_base, off, length) for off, length in _CAVE_PATCH_REGIONS
    }
    return {"literals": literals, "nops": nops, "jmps": jmps, "jnz": jnz, "cave_regions": cave_regions}


def _get_vanilla_snapshot(pm):
    global _vanilla_snapshot
    if _vanilla_snapshot is None:
        _vanilla_snapshot = _build_vanilla_snapshot(pm)
    return _vanilla_snapshot


def restore_vanilla(pm, base):
    """Undoes every edit ensure_structural_fixes/apply_item_order make,
    writing back the pristine bytes read from disk. Safe to call
    whether or not this live process was ever patched."""
    snap = _get_vanilla_snapshot(pm)
    delta = _delta(base)
    for off, data in snap["literals"].items():
        pm.write_bytes(off + 1 + delta, data, len(data))
    for off, data in snap["nops"].items():
        pm.write_bytes(off + delta, data, len(data))
    for off, data in snap["jmps"].items():
        pm.write_bytes(off + delta, data, len(data))
    pm.write_bytes(MYSTERY_BOX_JNZ_OFFSET + delta, snap["jnz"], len(snap["jnz"]))
    for off, data in snap["cave_regions"].items():
        pm.write_bytes(off + delta, data, len(data))


def _revert_disabled_pools(pm, base):
    """Keeps DISABLED_POOLS genuinely vanilla even while the rest is
    being forced (see bisection-test note above) - undoes any leftover
    forced bytes those pools picked up in earlier sessions tonight."""
    snap = _get_vanilla_snapshot(pm)
    delta = _delta(base)
    for pool in DISABLED_POOLS:
        for off in POOL_GROUPS[pool]:
            data = snap["literals"][off]
            pm.write_bytes(off + 1 + delta, data, len(data))
    for nop_off, jmp_off, _ in DEDUP_FIXES:
        if nop_off not in _DISABLED_DEDUP_NOP_OFFSETS:
            continue
        pm.write_bytes(nop_off + delta, snap["nops"][nop_off], len(snap["nops"][nop_off]))
        pm.write_bytes(jmp_off + delta, snap["jmps"][jmp_off], len(snap["jmps"][jmp_off]))


def sync_to_level(pm, base, order):
    """Call every poll: forces the given order while within the allowed
    level range, fully reverts to vanilla otherwise."""
    level = read_level(pm, base)
    if should_force(level):
        ensure_structural_fixes(pm, base)
        apply_item_order(pm, base, order)
        _revert_disabled_pools(pm, base)
    else:
        restore_vanilla(pm, base)
