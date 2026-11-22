# Ghidra headless post-script (Jython). Scans every instruction in .text
# for scalar immediate operands in the known item-class range [500,534),
# then groups hits by containing function and reports functions with
# several such immediates close together (a real "build this shop's
# possible item list" sequence would show several MOV/PUSH imm32 in this
# narrow, specific range within a short span - unlike a coincidental
# single hit elsewhere, e.g. a frame count or pixel offset that happens
# to fall in range).

from ghidra.program.model.scalar import Scalar

ITEM_MIN, ITEM_MAX = 500, 534

def run():
    listing = currentProgram.getListing()
    fm = currentProgram.getFunctionManager()
    instrs = listing.getInstructions(True)

    by_function = {}
    for ins in instrs:
        n = ins.getNumOperands()
        for i in range(n):
            objs = ins.getOpObjects(i)
            for obj in objs:
                if isinstance(obj, Scalar):
                    val = obj.getSignedValue()
                    if ITEM_MIN <= val < ITEM_MAX:
                        fn = fm.getFunctionContaining(ins.getAddress())
                        key = fn.getEntryPoint() if fn else None
                        name = fn.getName() if fn else "???"
                        by_function.setdefault((key, name), []).append((ins.getAddress(), val, ins.toString()))

    # keep only functions with >= 3 such immediates (real candidates)
    candidates = [(k, v) for k, v in by_function.items() if len(v) >= 3]
    candidates.sort(key=lambda kv: -len(kv[1]))
    print("FUNCTIONS WITH >=3 item-range immediates: %d" % len(candidates))
    for (entry, name), hits in candidates:
        print("\n%s @ %s - %d hits:" % (name, entry, len(hits)))
        for addr, val, text in hits:
            print("    %s: %s   (imm=%d)" % (addr, text, val))

run()
