# Ghidra headless post-script (Jython). Prints disassembly (with
# addresses) for a range of instructions around a given center address,
# so we can see exactly what sets up a call (e.g. what condition guards
# playing a specific sound), which the decompiled C doesn't show as
# directly mapped addresses.

def run():
    args = getScriptArgs()
    center = currentProgram.getAddressFactory().getAddress(args[0])
    before = int(args[1], 0) if len(args) > 1 else 0x100
    after = int(args[2], 0) if len(args) > 2 else 0x60

    listing = currentProgram.getListing()
    start = center.subtract(before)
    end = center.add(after)

    instr = listing.getInstructions(start, True)
    for ins in instr:
        if ins.getAddress().compareTo(end) > 0:
            break
        marker = "  <== CENTER" if ins.getAddress().equals(center) else ""
        print("%s: %s%s" % (ins.getAddress(), ins.toString(), marker))

run()
