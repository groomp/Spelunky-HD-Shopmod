def run():
    args = getScriptArgs()
    target_addr = currentProgram.getAddressFactory().getAddress(args[0])
    fm = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()
    refs = list(ref_mgr.getReferencesTo(target_addr))
    print("total refs to %s: %d" % (args[0], len(refs)))
    for ref in refs:
        frm = ref.getFromAddress()
        fn = fm.getFunctionContaining(frm)
        print("  %s  type=%s  in function %s @ %s" % (
            frm, ref.getReferenceType(), fn.getName() if fn else "???", fn.getEntryPoint() if fn else "?"))

run()
