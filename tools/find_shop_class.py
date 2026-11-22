# Ghidra headless post-script (Jython). Searches the symbol table for
# anything related to ShopContentsPatch (Ghidra's RTTI analyzer should
# have identified its vtable/class structure even without a PDB), and
# dumps the vtable's function pointers if found.

def run():
    st = currentProgram.getSymbolTable()
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()

    matches = []
    for sym in st.getAllSymbols(True):
        name = sym.getName()
        if "ShopContentsPatch" in name or "Shop" in name:
            matches.append(sym)

    print("MATCHING SYMBOLS: %d" % len(matches))
    for sym in matches:
        print("  %s @ %s (type=%s, namespace=%s)" % (
            sym.getName(), sym.getAddress(), sym.getSymbolType(), sym.getParentNamespace()))

    # Also check data types for a ShopContentsPatch class/vtable structure
    dtm = currentProgram.getDataTypeManager()
    iterator = dtm.getAllDataTypes()
    dt_matches = []
    for dt in iterator:
        if "ShopContentsPatch" in dt.getName():
            dt_matches.append(dt)
    print("\nMATCHING DATA TYPES: %d" % len(dt_matches))
    for dt in dt_matches:
        print("  %s (category=%s)" % (dt.getName(), dt.getCategoryPath()))

run()
