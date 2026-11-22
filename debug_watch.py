"""Minimal Windows debugger (ctypes, no external debugger libs - the only
one on PyPI, winappdbg, is a broken py2-era port that doesn't import under
py3) that attaches to a running 32-bit process from 64-bit Python and sets
a hardware breakpoint (debug registers, via Wow64GetThreadContext/
Wow64SetThreadContext since the target is WOW64) on one address, to find
out what code actually reads/writes it - the only reliable way to find
the real decision point after plain memory-value patches proved to not
affect either the shop item's sprite or what you actually receive.

Usage: python debug_watch.py <hex_address> <r|w|rw> [max_hits] [timeout_s]
"""

import ctypes
import ctypes.wintypes as w
import sys
import time

import pymem

K32 = ctypes.windll.kernel32

PROCESS_NAME = "Spelunky.exe"

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_BREAKPOINT = 0x80000003

CONTEXT_i386 = 0x00010000
CONTEXT_CONTROL = CONTEXT_i386 | 0x1
CONTEXT_INTEGER = CONTEXT_i386 | 0x2
CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10
WATCH_FLAGS = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS

THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_SUSPEND_RESUME = 0x0002
THREAD_ACCESS = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME

WATCH_ALL_THREADS = False


class EXCEPTION_RECORD(ctypes.Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", w.DWORD),
    ("ExceptionFlags", w.DWORD),
    ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p),
    ("NumberParameters", w.DWORD),
    ("ExceptionInformation", ctypes.c_void_p * 15),
]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", w.DWORD)]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hThread", w.HANDLE), ("lpThreadLocalBase", ctypes.c_void_p), ("lpStartAddress", ctypes.c_void_p)]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", w.HANDLE), ("hProcess", w.HANDLE), ("hThread", w.HANDLE),
        ("lpBaseOfImage", ctypes.c_void_p), ("dwDebugInfoFileOffset", w.DWORD),
        ("nDebugInfoSize", w.DWORD), ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p), ("lpImageName", ctypes.c_void_p),
        ("fUnicode", w.WORD),
    ]


class EXIT_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", w.DWORD)]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("dwDebugInfoFileOffset", w.DWORD),
                ("nDebugInfoSize", w.DWORD), ("lpImageName", ctypes.c_void_p), ("fUnicode", w.WORD)]


class UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p)]


class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = [("lpDebugStringData", ctypes.c_void_p), ("fUnicode", w.WORD), ("nDebugStringLength", w.WORD)]


class RIP_INFO(ctypes.Structure):
    _fields_ = [("dwError", w.DWORD), ("dwType", w.DWORD)]


class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_DEBUG_INFO),
        ("ExitProcess", EXIT_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", w.DWORD), ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD),
                ("u", DEBUG_EVENT_UNION)]


class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [
        ("ControlWord", w.DWORD), ("StatusWord", w.DWORD), ("TagWord", w.DWORD),
        ("ErrorOffset", w.DWORD), ("ErrorSelector", w.DWORD), ("DataOffset", w.DWORD),
        ("DataSelector", w.DWORD), ("RegisterArea", ctypes.c_byte * 80), ("Cr0NpxState", w.DWORD),
    ]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", w.DWORD),
        ("Dr0", w.DWORD), ("Dr1", w.DWORD), ("Dr2", w.DWORD), ("Dr3", w.DWORD), ("Dr6", w.DWORD), ("Dr7", w.DWORD),
        ("FloatSave", WOW64_FLOATING_SAVE_AREA),
        ("SegGs", w.DWORD), ("SegFs", w.DWORD), ("SegEs", w.DWORD), ("SegDs", w.DWORD),
        ("Edi", w.DWORD), ("Esi", w.DWORD), ("Ebx", w.DWORD), ("Edx", w.DWORD), ("Ecx", w.DWORD), ("Eax", w.DWORD),
        ("Ebp", w.DWORD), ("Eip", w.DWORD), ("SegCs", w.DWORD), ("EFlags", w.DWORD),
        ("Esp", w.DWORD), ("SegSs", w.DWORD),
        ("ExtendedRegisters", ctypes.c_byte * 512),
    ]


K32.DebugActiveProcess.argtypes = [w.DWORD]
K32.DebugActiveProcess.restype = w.BOOL
K32.DebugActiveProcessStop.argtypes = [w.DWORD]
K32.DebugActiveProcessStop.restype = w.BOOL
K32.DebugSetProcessKillOnExit.argtypes = [w.BOOL]
K32.DebugSetProcessKillOnExit.restype = w.BOOL
K32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), w.DWORD]
K32.WaitForDebugEvent.restype = w.BOOL
K32.ContinueDebugEvent.argtypes = [w.DWORD, w.DWORD, w.DWORD]
K32.ContinueDebugEvent.restype = w.BOOL
K32.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
K32.OpenThread.restype = w.HANDLE
K32.Wow64GetThreadContext.argtypes = [w.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
K32.Wow64GetThreadContext.restype = w.BOOL
K32.Wow64SetThreadContext.argtypes = [w.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
K32.Wow64SetThreadContext.restype = w.BOOL
K32.CloseHandle.argtypes = [w.HANDLE]


def find_pid():
    for entry in pymem.process.list_processes():
        if entry.szExeFile.decode(errors="ignore").lower() == PROCESS_NAME.lower():
            return entry.th32ProcessID
    return None


def arm_breakpoint(hthread, address, cond_bits, size_bits):
    ctx = WOW64_CONTEXT()
    ctx.ContextFlags = WATCH_FLAGS
    if not K32.Wow64GetThreadContext(hthread, ctypes.byref(ctx)):
        print("Wow64GetThreadContext failed:", ctypes.GetLastError())
        return False
    ctx.Dr0 = address & 0xFFFFFFFF
    ctx.Dr7 = (ctx.Dr7 & ~0x000F0003) | 0x1 | (cond_bits << 16) | (size_bits << 18)
    ctx.ContextFlags = WATCH_FLAGS
    if not K32.Wow64SetThreadContext(hthread, ctypes.byref(ctx)):
        print("Wow64SetThreadContext failed:", ctypes.GetLastError())
        return False
    return True


def disarm_breakpoint(hthread):
    ctx = WOW64_CONTEXT()
    ctx.ContextFlags = WATCH_FLAGS
    K32.Wow64GetThreadContext(hthread, ctypes.byref(ctx))
    ctx.Dr7 = ctx.Dr7 & ~0x1
    ctx.ContextFlags = WATCH_FLAGS
    K32.Wow64SetThreadContext(hthread, ctypes.byref(ctx))


def disassemble_at(pm, eip, count=6):
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        code = pm.read_bytes(eip, 64)
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        lines = []
        for insn in md.disasm(code, eip):
            lines.append(f"    0x{insn.address:X}: {insn.mnemonic} {insn.op_str}")
            if len(lines) >= count:
                break
        return "\n".join(lines)
    except Exception as e:
        return f"    (disasm failed: {e})"


def main():
    if len(sys.argv) < 3:
        print("usage: debug_watch.py <hex_address> <r|w|rw> [max_hits] [timeout_s]")
        sys.exit(1)
    address = int(sys.argv[1], 16)
    mode = sys.argv[2].lower()
    max_hits = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    timeout_s = float(sys.argv[4]) if len(sys.argv) > 4 else 30.0
    global WATCH_ALL_THREADS
    WATCH_ALL_THREADS = len(sys.argv) > 5 and sys.argv[5] == "all"

    cond_bits = {"w": 0b01, "rw": 0b11, "r": 0b11}[mode]  # x86 has no write-exclusive-read distinction beyond this
    size_bits = 0b11  # 4 bytes

    pid = find_pid()
    if pid is None:
        print("Spelunky.exe not found.")
        sys.exit(1)

    pm = pymem.Pymem()
    pm.open_process_from_id(pid)

    if not K32.DebugActiveProcess(pid):
        print("DebugActiveProcess failed:", ctypes.GetLastError())
        sys.exit(1)
    K32.DebugSetProcessKillOnExit(False)
    print(f"Attached as debugger to pid {pid}. Watching 0x{address:X} mode={mode} for up to {max_hits} hits / {timeout_s}s")

    thread_handles = {}  # tid -> HANDLE, tracks every thread we see
    hits = 0
    t_start = time.time()

    def arm_all():
        for tid, h in thread_handles.items():
            arm_breakpoint(h, address, cond_bits, size_bits)
        print(f"  breakpoint armed on {len(thread_handles)} thread(s): {list(thread_handles)}")

    de = DEBUG_EVENT()
    try:
        while time.time() - t_start < timeout_s and hits < max_hits:
            if not K32.WaitForDebugEvent(ctypes.byref(de), 200):
                continue
            code = de.dwDebugEventCode
            tid = de.dwThreadId

            if code == CREATE_PROCESS_DEBUG_EVENT:
                thread_handles[tid] = de.u.CreateProcessInfo.hThread
                print(f"  main thread tid={tid}")
            elif code == CREATE_THREAD_DEBUG_EVENT:
                thread_handles[tid] = de.u.CreateThread.hThread
                if WATCH_ALL_THREADS:
                    arm_breakpoint(de.u.CreateThread.hThread, address, cond_bits, size_bits)
            elif code == EXIT_THREAD_DEBUG_EVENT:
                thread_handles.pop(tid, None)
            elif code == EXCEPTION_DEBUG_EVENT:
                exc = de.u.Exception.ExceptionRecord.ExceptionCode
                if exc == EXCEPTION_BREAKPOINT:
                    # Mandatory attach breakpoint (and any other int3) - must
                    # ack with DBG_CONTINUE or the process can crash/die.
                    K32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE)
                    continue
                if exc == EXCEPTION_SINGLE_STEP and tid in thread_handles:
                    hthread = thread_handles[tid]
                    ctx = WOW64_CONTEXT()
                    ctx.ContextFlags = WATCH_FLAGS
                    K32.Wow64GetThreadContext(hthread, ctypes.byref(ctx))
                    hits += 1
                    print(f"\n--- hit #{hits} (tid={tid}) EIP=0x{ctx.Eip:X} ESP=0x{ctx.Esp:X} EAX=0x{ctx.Eax:X} ---")
                    print(disassemble_at(pm, ctx.Eip))
                    try:
                        stack = pm.read_bytes(ctx.Esp, 32)
                        vals = [int.from_bytes(stack[i:i+4], "little") for i in range(0, 32, 4)]
                        print("    stack:", " ".join(f"0x{v:X}" for v in vals))
                    except Exception:
                        pass
                    K32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE)
                    continue
                K32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_EXCEPTION_NOT_HANDLED)
                continue

            if code == CREATE_PROCESS_DEBUG_EVENT:
                if WATCH_ALL_THREADS:
                    arm_all()
                else:
                    arm_breakpoint(thread_handles[tid], address, cond_bits, size_bits)
                    print(f"  breakpoint armed on main thread only (tid={tid})")

            K32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE)
    finally:
        for h in thread_handles.values():
            disarm_breakpoint(h)
        K32.DebugActiveProcessStop(pid)
        print(f"\nDetached. Total hits: {hits}")


if __name__ == "__main__":
    main()
