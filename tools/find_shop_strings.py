# Ghidra headless post-script (Jython). Finds defined strings containing
# "shop" (any case) and prints every place in code that references them -
# a much more reliable anchor into the shop-generation logic than
# guessing from SpawnEntity's 120 caller functions by call count alone.

def run():
    listing = currentProgram.getListing()
    data_iter = listing.getDefinedData(True)
    fm = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()

    hits = 0
    for data in data_iter:
        dt = data.getDataType()
        if dt is None:
            continue
        type_name = dt.getName().lower()
        if "string" not in type_name and "char" not in type_name:
            continue
        try:
            val = data.getValue()
        except Exception:
            continue
        if val is None:
            continue
        s = str(val)
        if "shop" not in s.lower():
            continue
        hits += 1
        addr = data.getAddress()
        print("STRING @ %s: %r" % (addr, s))
        refs = ref_mgr.getReferencesTo(addr)
        for ref in refs:
            from_addr = ref.getFromAddress()
            caller_fn = fm.getFunctionContaining(from_addr)
            name = caller_fn.getName() if caller_fn else "???"
            entry = caller_fn.getEntryPoint() if caller_fn else from_addr
            print("    referenced from %s in function %s @ %s" % (from_addr, name, entry))

    print("TOTAL SHOP-RELATED STRINGS: %d" % hits)

run()
