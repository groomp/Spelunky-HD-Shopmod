# Ghidra headless post-script (Jython). Finds references to the
# ShopContentsPatch vtable address (where it gets assigned into an
# object, i.e. the constructor) and decompiles the containing function.

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

VTABLE_VA_STR = "0068c454"

def run():
    vtable_addr = currentProgram.getAddressFactory().getAddress(VTABLE_VA_STR)
    ref_mgr = currentProgram.getReferenceManager()
    fm = currentProgram.getFunctionManager()

    refs = list(ref_mgr.getReferencesTo(vtable_addr))
    print("refs to vtable %s: %d" % (VTABLE_VA_STR, len(refs)))
    seen = set()
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    for ref in refs:
        frm = ref.getFromAddress()
        fn = fm.getFunctionContaining(frm)
        key = fn.getEntryPoint() if fn else frm
        print("  ref from %s (function %s @ %s)" % (frm, fn.getName() if fn else "???", key))
        if key not in seen and fn is not None:
            seen.add(key)
            print("\n" + "=" * 20 + (" %s @ %s " % (fn.getName(), fn.getEntryPoint())) + "=" * 20)
            results = decomp.decompileFunction(fn, 60, monitor)
            if results.decompileCompleted():
                print(results.getDecompiledFunction().getC())
            else:
                print("DECOMPILE FAILED: %s" % results.getErrorMessage())

run()
