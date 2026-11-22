# Ghidra headless post-script (Jython). Properly walks MSVC RTTI via
# Ghidra's own reference manager (reliable, handles relocations etc.)
# from the ShopContentsPatch TypeDescriptor -> RTTICompleteObjectLocator
# -> vtable, then lists the vtable's function pointers.

import struct

def run():
    listing = currentProgram.getListing()
    mem = currentProgram.getMemory()
    ref_mgr = currentProgram.getReferenceManager()
    fm = currentProgram.getFunctionManager()

    # find the mangled name string
    needle = ".?AVShopContentsPatch@@"
    target_str_addr = None
    for data in listing.getDefinedData(True):
        try:
            val = data.getValue()
        except Exception:
            continue
        if val is not None and needle in str(val):
            target_str_addr = data.getAddress()
            break
    if target_str_addr is None:
        print("string not found as defined data - scanning raw bytes")
        found = mem.findBytes(currentProgram.getMinAddress(), needle, None, True, None)
        print("raw found at", found)
        return

    print("TypeDescriptor name string at %s" % target_str_addr)
    td_addr = target_str_addr.subtract(8)
    print("TypeDescriptor starts at %s" % td_addr)

    td_refs = list(ref_mgr.getReferencesTo(td_addr))
    print("refs to TypeDescriptor: %d" % len(td_refs))
    for ref in td_refs:
        frm = ref.getFromAddress()
        fn = fm.getFunctionContaining(frm)
        print("  ref from %s (in function %s)" % (frm, fn.getName() if fn else "???"))

        # Is this a data reference (part of a COL struct)? COL layout:
        # [signature, offset, cdOffset, pTypeDescriptor, pClassDescriptor]
        # pTypeDescriptor is at relative offset 0xC within the struct.
        col_addr = frm.subtract(0xC)
        try:
            sig = mem.getInt(col_addr)
        except Exception:
            continue
        if sig == 0:
            print("    plausible COL at %s (sig=0)" % col_addr)
            col_refs = list(ref_mgr.getReferencesTo(col_addr))
            print("    refs to this COL: %d" % len(col_refs))
            for cref in col_refs:
                vtable_minus1 = cref.getFromAddress()
                vtable_addr = vtable_minus1.add(4)
                print("      COL referenced from %s -> vtable candidate at %s" % (vtable_minus1, vtable_addr))
                for i in range(10):
                    try:
                        fptr = mem.getInt(vtable_addr.add(i * 4)) & 0xffffffff
                    except Exception:
                        break
                    name = "???"
                    try:
                        fn_addr = currentProgram.getAddressFactory().getAddress(hex(fptr))
                        if fn_addr is not None and fn_addr.isMemoryAddress():
                            target_fn = fm.getFunctionAt(fn_addr)
                            if target_fn:
                                name = target_fn.getName()
                    except Exception as e:
                        name = "err:%s" % e
                    print("        slot[%d] = 0x%x  (%s)" % (i, fptr, name))

run()
