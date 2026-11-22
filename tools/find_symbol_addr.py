# Ghidra headless post-script (Jython). Finds the address(es) of a named
# symbol (e.g. an imported function's IAT thunk) - useful when you need
# the address find_fn_callers.py expects but only know the name.

def run():
    args = getScriptArgs()
    name = args[0]
    st = currentProgram.getSymbolTable()
    symbols = st.getSymbols(name)
    found = False
    for sym in symbols:
        found = True
        print("%s -> %s (type=%s, namespace=%s)" % (
            name, sym.getAddress(), sym.getSymbolType(), sym.getParentNamespace()))
    if not found:
        print("no symbol named %s found" % name)

run()
