# Ghidra headless post-script (Jython). Prints the storage (register or
# stack offset) Ghidra's decompiler assigned to each named high-level
# variable in a function, across every address where it's live - avoids
# manually bisecting disassembly to answer "where does this C variable
# actually live".

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def run():
    args = getScriptArgs()
    func_addr_str = args[0]
    var_names = set(args[1:])

    fm = currentProgram.getFunctionManager()
    addr = currentProgram.getAddressFactory().getAddress(func_addr_str)
    fn = fm.getFunctionContaining(addr)
    if fn is None:
        print("NO FUNCTION AT %s" % func_addr_str)
        return

    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    results = decomp.decompileFunction(fn, 120, monitor)
    if not results.decompileCompleted():
        print("DECOMPILE FAILED: %s" % results.getErrorMessage())
        return

    high_func = results.getHighFunction()
    lsm = high_func.getLocalSymbolMap()
    symbols = lsm.getSymbols()
    while symbols.hasNext():
        sym = symbols.next()
        name = sym.getName()
        if var_names and name not in var_names:
            continue
        hv = sym.getHighVariable()
        print("=== %s ===" % name)
        if hv is None:
            print("  (no HighVariable)")
            continue
        for inst in hv.getInstances():
            addr = inst.getAddress()
            pc_addr = inst.getPCAddress()
            kind = "reg" if inst.isRegister() else ("unique" if inst.isUnique() else
                   ("const" if inst.isConstant() else ("stack" if addr is not None and addr.isStackAddress() else "other")))
            reg_name = None
            if inst.isRegister():
                reg = currentProgram.getLanguage().getRegister(addr, inst.getSize())
                reg_name = reg.getName() if reg else None
            print("  kind=%s addr=%s reg=%s pcaddress=%s size=%d" %
                  (kind, addr, reg_name, pc_addr, inst.getSize()))

run()
