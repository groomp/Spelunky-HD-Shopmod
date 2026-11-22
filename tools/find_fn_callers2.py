def run():
    args = getScriptArgs()
    target_addr = currentProgram.getAddressFactory().getAddress(args[0])
    fm = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()
    refs = ref_mgr.getReferencesTo(target_addr)
    for ref in refs:
        if ref.getReferenceType().isCall():
            frm = ref.getFromAddress()
            fn = fm.getFunctionContaining(frm)
            print("call site %s in function %s @ %s" % (frm, fn.getName() if fn else "???", fn.getEntryPoint() if fn else "?"))

run()
