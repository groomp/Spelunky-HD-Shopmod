# Ghidra headless post-script (Jython). Decompiles one or more functions
# (by entry address, passed as script args) to readable pseudocode.

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
        fn = fm.getFunctionAt(addr)
        if fn is None:
            print("NO FUNCTION AT %s" % arg)
            continue
        print("=" * 20 + (" %s @ %s " % (fn.getName(), addr)) + "=" * 20)
        results = decomp.decompileFunction(fn, 60, monitor)
        if results.decompileCompleted():
            print(results.getDecompiledFunction().getC())
        else:
            print("DECOMPILE FAILED: %s" % results.getErrorMessage())
        print("")

run()
