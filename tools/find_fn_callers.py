# Ghidra headless post-script (Jython). Finds callers of a given function
# (by entry address, from script args) and prints them, plus decompiles
# the immediate parent if there's just one or a few.

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def run():
    args = getScriptArgs()
    target_addr = currentProgram.getAddressFactory().getAddress(args[0])
    fm = currentProgram.getFunctionManager()
    ref_mgr = currentProgram.getReferenceManager()

    refs = ref_mgr.getReferencesTo(target_addr)
    callers = {}
    for ref in refs:
        if ref.getReferenceType().isCall():
            from_addr = ref.getFromAddress()
            caller_fn = fm.getFunctionContaining(from_addr)
            key = caller_fn.getEntryPoint() if caller_fn else from_addr
            name = caller_fn.getName() if caller_fn else "???"
            callers[key] = name

    print("CALLERS OF %s: %d" % (args[0], len(callers)))
    for entry, name in callers.items():
        print("  %s @ %s" % (name, entry))

    if len(callers) <= 3:
        decomp = DecompInterface()
        decomp.openProgram(currentProgram)
        monitor = ConsoleTaskMonitor()
        for entry, name in callers.items():
            fn = fm.getFunctionAt(entry)
            print("\n" + "=" * 20 + (" %s @ %s " % (name, entry)) + "=" * 20)
            results = decomp.decompileFunction(fn, 60, monitor)
            if results.decompileCompleted():
                print(results.getDecompiledFunction().getC())
            else:
                print("DECOMPILE FAILED: %s" % results.getErrorMessage())

run()
