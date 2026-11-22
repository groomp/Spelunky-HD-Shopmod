# Ghidra headless post-script (Jython). For every CALL to SpawnEntity,
# looks at the instructions in the few bytes right before the call for a
# PUSH/MOV of an immediate value in the item-class range [500,534) - this
# is much more precise than scanning all instructions for the value
# anywhere (which hits tons of unrelated memory-offset false positives),
# since it specifically targets what becomes SpawnEntity's class-id
# argument at an actual call site.

from ghidra.program.model.scalar import Scalar

SPAWNENTITY_VA_STR = "00470ab0"
ITEM_MIN, ITEM_MAX = 500, 534
LOOKBACK_BYTES = 40

def run():
    target_addr = currentProgram.getAddressFactory().getAddress(SPAWNENTITY_VA_STR)
    fm = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()

    refs = ref_mgr.getReferencesTo(target_addr)
    call_sites = [ref.getFromAddress() for ref in refs if ref.getReferenceType().isCall()]
    print("total call sites: %d" % len(call_sites))

    hits = []
    for call_addr in call_sites:
        start = call_addr.subtract(LOOKBACK_BYTES)
        instrs = listing.getInstructions(start, True)
        found_val = None
        for ins in instrs:
            if ins.getAddress().compareTo(call_addr) > 0:
                break
            mnem = ins.getMnemonicString()
            if mnem not in ("PUSH", "MOV"):
                continue
            n = ins.getNumOperands()
            for i in range(n):
                for obj in ins.getOpObjects(i):
                    if isinstance(obj, Scalar):
                        val = obj.getSignedValue()
                        if ITEM_MIN <= val < ITEM_MAX:
                            found_val = (val, ins.getAddress(), ins.toString())
        if found_val:
            fn = fm.getFunctionContaining(call_addr)
            hits.append((fn.getEntryPoint() if fn else None, fn.getName() if fn else "???", call_addr, found_val))

    print("call sites with a nearby item-class immediate: %d" % len(hits))
    by_fn = {}
    for entry, name, call_addr, found_val in hits:
        by_fn.setdefault((entry, name), []).append((call_addr, found_val))

    for (entry, name), items in sorted(by_fn.items(), key=lambda kv: -len(kv[1])):
        print("\n%s @ %s - %d matching call(s):" % (name, entry, len(items)))
        for call_addr, (val, ins_addr, ins_text) in items:
            print("    call@%s  imm=%d (0x%x) from %s: %s" % (call_addr, val, val, ins_addr, ins_text))

run()
