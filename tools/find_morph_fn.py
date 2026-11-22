# Ghidra headless post-script (Jython). Looks for a possible "change an
# existing entity's type in place" function in Spelunky.exe - distinct
# from SpawnEntity (which allocates a NEW entity). Heuristic: find
# functions that write a NON-constant (register/parameter-derived) value
# to [reg + 0xC] (the known type-field offset), which would indicate
# "set this entity's type to whatever value you pass me" rather than a
# hardcoded construction-time immediate.

def run():
    listing = currentProgram.getListing()
    fm = currentProgram.getFunctionManager()
    instrs = listing.getInstructions(True)

    by_fn = {}
    for ins in instrs:
        mnem = ins.getMnemonicString()
        if mnem != "MOV":
            continue
        if ins.getNumOperands() < 2:
            continue
        dest_repr = ins.getDefaultOperandRepresentation(0)
        src_repr = ins.getDefaultOperandRepresentation(1)
        # destination must be [reg + 0xc] (any register, the entity's own type field)
        if "0xc]" not in dest_repr.lower() and "+ 0xc" not in dest_repr.lower():
            continue
        if "[" not in dest_repr:
            continue
        # source must be a REGISTER (not an immediate constant) - i.e. no literal digits-only operand
        src_clean = src_repr.strip()
        is_register_src = src_clean.isalpha() and len(src_clean) <= 3
        if not is_register_src:
            continue
        fn = fm.getFunctionContaining(ins.getAddress())
        key = fn.getEntryPoint() if fn else None
        name = fn.getName() if fn else "???"
        by_fn.setdefault((key, name), []).append((ins.getAddress(), dest_repr, src_repr))

    print("functions writing a REGISTER value to [.. + 0xc]: %d" % len(by_fn))
    for (entry, name), hits in sorted(by_fn.items(), key=lambda kv: -len(kv[1])):
        print("\n%s @ %s - %d hit(s):" % (name, entry, len(hits)))
        for addr, dest, src in hits:
            print("    %s: MOV %s, %s" % (addr, dest, src))

run()
