# Ghidra headless post-script (Jython). Finds the unique FUNCTIONS that
# call SpawnEntity (at image VA 0x470AB0, confirmed via LunkyBox), and
# prints each caller's name/address plus how many times it calls
# SpawnEntity - so we can shortlist which few (of ~700 raw call sites)
# are worth decompiling in full.

from ghidra.program.model.symbol import RefType

SPAWNENTITY_VA = 0x00470ab0

def run():
    addr = currentProgram.getAddressFactory().getAddress(hex(SPAWNENTITY_VA))
    fm = currentProgram.getFunctionManager()
    target_fn = fm.getFunctionAt(addr)
    if target_fn is None:
        print("NO FUNCTION AT TARGET ADDRESS 0x%x" % SPAWNENTITY_VA)
        return
    print("target function: %s @ %s" % (target_fn.getName(), target_fn.getEntryPoint()))

    ref_mgr = currentProgram.getReferenceManager()
    refs = ref_mgr.getReferencesTo(addr)

    caller_counts = {}
    for ref in refs:
        if ref.getReferenceType().isCall():
            from_addr = ref.getFromAddress()
            caller_fn = fm.getFunctionContaining(from_addr)
            key = caller_fn.getEntryPoint() if caller_fn else from_addr
            name = caller_fn.getName() if caller_fn else "???"
            if key not in caller_counts:
                caller_counts[key] = [name, 0]
            caller_counts[key][1] += 1

    print("UNIQUE CALLER FUNCTIONS: %d" % len(caller_counts))
    items = sorted(caller_counts.items(), key=lambda kv: -kv[1][1])
    for entry_addr, (name, count) in items:
        print("  %s @ %s  (calls SpawnEntity %d times)" % (name, entry_addr, count))

run()
