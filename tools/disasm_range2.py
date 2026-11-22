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
        print("%s: %s" % (ins.getAddress(), ins.toString()))

run()
