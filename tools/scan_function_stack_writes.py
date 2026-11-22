# Ghidra headless post-script (Jython). Within one function, finds MOV
# instructions that write an item-class-range immediate [500,534) into a
# STACK-relative location (ESP/EBP-based), as opposed to a heap/struct
# field access - the signature of building a local array of candidate
# item ids for a random pick, rather than coincidental struct-offset
# numbers matching the range.

from ghidra.program.model.scalar import Scalar
from ghidra.program.model.lang import Register

ITEM_MIN, ITEM_MAX = 500, 534

def run():
    args = getScriptArgs()
    fn_addr = currentProgram.getAddressFactory().getAddress(args[0])
    fm = currentProgram.getFunctionManager()
    fn = fm.getFunctionAt(fn_addr)
    if fn is None:
        print("no function at %s" % args[0])
        return
    body = fn.getBody()
    listing = currentProgram.getListing()
    instrs = listing.getInstructions(body, True)

    for ins in instrs:
        mnem = ins.getMnemonicString()
        if mnem != "MOV":
            continue
        n = ins.getNumOperands()
        if n < 2:
            continue
        # operand 0 is destination; check it references ESP/EBP (stack) and not just a plain register
        dest_repr = ins.getDefaultOperandRepresentation(0)
        if "ESP" not in dest_repr and "EBP" not in dest_repr:
            continue
        if "[" not in dest_repr:
            continue  # must be a memory write, not a register-to-register mov
        for obj in ins.getOpObjects(1):
            if isinstance(obj, Scalar):
                val = obj.getSignedValue()
                if ITEM_MIN <= val < ITEM_MAX:
                    print("%s: %s   (dest=%s, imm=%d)" % (ins.getAddress(), ins.toString(), dest_repr, val))

run()
