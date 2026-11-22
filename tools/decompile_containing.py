# Ghidra headless post-script (Jython). Decompiles the function
# CONTAINING a given address (rather than requiring the exact entry
# point), for addresses found via raw disassembly earlier.

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def run():
    args = getScriptArgs()
    fm = currentProgram.getFunctionManager()
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()

    for arg in args:
        addr = currentProgram.getAddressFactory().getAddress(arg)
        fn = fm.getFunctionContaining(addr)
        if fn is None:
            print("NO FUNCTION CONTAINS %s" % arg)
            continue
        print("=" * 20 + (" %s @ %s (contains %s) " % (fn.getName(), fn.getEntryPoint(), arg)) + "=" * 20)
        results = decomp.decompileFunction(fn, 60, monitor)
        if results.decompileCompleted():
            print(results.getDecompiledFunction().getC())
        else:
            print("DECOMPILE FAILED: %s" % results.getErrorMessage())
        print("")

run()
