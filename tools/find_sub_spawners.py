# Ghidra headless post-script (Jython). Finds every function CALLED BY
# FUN_004d6690 (the main content-placement function, 127 direct
# SpawnEntity calls), then cross-references against the full list of
# functions that themselves call SpawnEntity - looking for a
# room-type-specific sub-handler (e.g. a dedicated shop populator) that
# the main dispatcher delegates to, rather than spawning everything
# directly itself.

SPAWNENTITY_VA_STR = "00470ab0"
MAIN_FN_STR = "004d6690"

def get_callees(fn, fm, ref_mgr):
    body = fn.getBody()
    callees = {}
    listing = currentProgram.getListing()
    instrs = listing.getInstructions(body, True)
    for ins in instrs:
        if ins.getFlowType().isCall():
            for ref in ins.getReferencesFrom():
                if ref.getReferenceType().isCall():
                    to_addr = ref.getToAddress()
                    target_fn = fm.getFunctionAt(to_addr)
                    name = target_fn.getName() if target_fn else "???"
                    callees[to_addr] = name
    return callees

def run():
    fm = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()

    main_fn = fm.getFunctionAt(currentProgram.getAddressFactory().getAddress(MAIN_FN_STR))
    callees = get_callees(main_fn, fm, ref_mgr)
    print("FUN_%s calls %d distinct functions" % (MAIN_FN_STR, len(callees)))

    spawnentity_addr = currentProgram.getAddressFactory().getAddress(SPAWNENTITY_VA_STR)
    spawn_refs = ref_mgr.getReferencesTo(spawnentity_addr)
    spawner_callers = set()
    for ref in spawn_refs:
        if ref.getReferenceType().isCall():
            caller_fn = fm.getFunctionContaining(ref.getFromAddress())
            if caller_fn:
                spawner_callers.add(caller_fn.getEntryPoint())

    print("\nCallees of the main function that ALSO call SpawnEntity themselves:")
    count = 0
    for addr, name in callees.items():
        if addr in spawner_callers and addr != main_fn.getEntryPoint():
            count += 1
            fn = fm.getFunctionAt(addr)
            size = fn.getBody().getNumAddresses() if fn else 0
            print("  %s @ %s  (function size: %d bytes)" % (name, addr, size))
    print("total: %d" % count)

run()
