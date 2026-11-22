"""Injects overlay/shopmod_overlay.dll (see overlay/overlay.cpp) into
Spelunky.exe via the classic CreateRemoteThread+LoadLibraryA technique -
the same remote-thread approach spawn_item.py already uses to call the
game's own SpawnEntity. The DLL hooks Direct3D9's EndScene inside the
game's own process so the watermark is drawn as part of the actual
rendered frame (see overlay/overlay.cpp for why).

is_injected()/inject() are both safe to call every reconnect - injection
only actually happens once per game process.
"""

import ctypes
import ctypes.wintypes as w
import os
import struct

import pefile

K32 = ctypes.windll.kernel32
K32.OpenProcess.restype = ctypes.c_void_p
K32.VirtualAllocEx.restype = ctypes.c_void_p
K32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, w.DWORD, w.DWORD]
K32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
K32.GetModuleHandleW.restype = ctypes.c_void_p
K32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
K32.GetProcAddress.restype = ctypes.c_void_p
K32.CreateRemoteThread.restype = ctypes.c_void_p
K32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)]
K32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
K32.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
K32.Module32First.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
K32.Module32Next.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
K32.CloseHandle.argtypes = [ctypes.c_void_p]
K32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PROCESS_ALL_ACCESS = 0x1F0FFF
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

DLL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "overlay", "shopmod_overlay.dll")
DLL_BASENAME = os.path.basename(DLL_PATH)


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", w.DWORD), ("th32ModuleID", w.DWORD), ("th32ProcessID", w.DWORD),
        ("GlblcntUsage", w.DWORD), ("ProccntUsage", w.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)), ("modBaseSize", w.DWORD),
        ("hModule", w.HMODULE), ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260),
    ]


def is_injected(pid):
    snap = K32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == INVALID_HANDLE_VALUE:
        return False
    try:
        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)
        if not K32.Module32First(snap, ctypes.byref(entry)):
            return False
        while True:
            if entry.szModule.decode(errors="ignore").lower() == DLL_BASENAME.lower():
                return True
            if not K32.Module32Next(snap, ctypes.byref(entry)):
                return False
    finally:
        K32.CloseHandle(snap)


def _target_kernel32_base(pid):
    """This controller runs as 64-bit Python, but Spelunky.exe is a
    32-bit (WOW64) process - its own kernel32.dll is a completely
    separate, differently-based module from ours, so we have to look
    it up in ITS module list (TH32CS_SNAPMODULE32 is what makes a
    64-bit snapshotter able to see a WOW64 target's 32-bit modules)."""
    snap = K32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == INVALID_HANDLE_VALUE:
        return None
    try:
        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)
        if not K32.Module32First(snap, ctypes.byref(entry)):
            return None
        while True:
            if entry.szModule.decode(errors="ignore").lower() == "kernel32.dll":
                return ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value
            if not K32.Module32Next(snap, ctypes.byref(entry)):
                return None
    finally:
        K32.CloseHandle(snap)


def _find_dll_module(pid):
    """(hModule, base) of our DLL in the target process, or (None, None)."""
    snap = K32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == INVALID_HANDLE_VALUE:
        return None, None
    try:
        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)
        if not K32.Module32First(snap, ctypes.byref(entry)):
            return None, None
        while True:
            if entry.szModule.decode(errors="ignore").lower() == DLL_BASENAME.lower():
                return entry.hModule, ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value
            if not K32.Module32Next(snap, ctypes.byref(entry)):
                return None, None
    finally:
        K32.CloseHandle(snap)


def _kernel32_export_rva(name):
    """A kernel32.dll export's offset within the module - identical for
    every 32-bit process on this machine regardless of ASLR base, so
    reading it once from the on-disk SysWOW64 copy (no need to load it)
    gives an offset we can add to the target's own base from
    _target_kernel32_base()."""
    path = os.path.join(os.environ["WINDIR"], "SysWOW64", "kernel32.dll")
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    name_bytes = name.encode()
    for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if sym.name == name_bytes:
            return sym.address
    raise RuntimeError(f"{name} not found in SysWOW64 kernel32.dll exports")


def _target_proc_addr(pid, name):
    base = _target_kernel32_base(pid)
    if base is None:
        raise OSError("couldn't find kernel32.dll in the target process")
    return base + _kernel32_export_rva(name)


def _dll_export_rva(dll_path, name):
    """A DLL export's offset within its own module, read straight from
    the on-disk file - same trick as _kernel32_export_rva. DO NOT use
    this for our OWN overlay DLL in unload() - see _dll_export_rva_live
    for why; this is only safe for a file that's guaranteed identical
    to whatever's actually loaded (e.g. the never-recompiled-mid-session
    SysWOW64 kernel32.dll)."""
    pe = pefile.PE(dll_path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    name_bytes = name.encode()
    for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if sym.name == name_bytes:
            return sym.address
    raise RuntimeError(f"{name} not found in {dll_path} exports")


def _read_process_memory(h_process, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if not K32.ReadProcessMemory(h_process, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)):
        raise OSError(f"ReadProcessMemory failed: {ctypes.GetLastError()}")
    return buf.raw[:n.value]


def _dll_export_rva_live(h_process, module_base, name):
    """Same job as _dll_export_rva, but parses the PE export table out
    of the TARGET PROCESS's own memory instead of a file on disk.

    unload() used to resolve RestoreHook's address via _dll_export_rva
    against shopmod_overlay.dll on disk - correct only as long as that
    file is byte-for-byte what's actually loaded in the target process.
    The very first time this session's workflow recompiled the DLL
    (picking up unrelated, substantial code changes) BEFORE unloading
    the OLD build still injected in a live game, that assumption broke:
    the NEW file's RestoreHook RVA no longer matched the OLD, still-
    loaded image's layout, so module_base + (new) rva landed partway
    into a completely unrelated function - confirmed via a live crash
    dump (the remote thread's very first frame was already deep inside
    "RestoreHook+0xf8c", nowhere near its real ~100-byte body). Reading
    the export table live removes the whole hazard: it reflects
    whatever's ACTUALLY mapped, regardless of what's since changed on
    disk or in what order this module's own recompile/unload calls
    happen to run."""
    dos_header = _read_process_memory(h_process, module_base, 0x40)
    e_lfanew = struct.unpack_from("<I", dos_header, 0x3C)[0]

    nt_header = _read_process_memory(h_process, module_base + e_lfanew, 0x18 + 0x60 + 8)
    magic = struct.unpack_from("<H", nt_header, 24)[0]
    if magic != 0x10B:
        raise OSError("target module is not a PE32 (32-bit) image")
    export_dir_rva, _export_dir_size = struct.unpack_from("<II", nt_header, 24 + 96)

    export_dir = _read_process_memory(h_process, module_base + export_dir_rva, 40)
    num_names = struct.unpack_from("<I", export_dir, 24)[0]
    addr_of_functions = struct.unpack_from("<I", export_dir, 28)[0]
    addr_of_names = struct.unpack_from("<I", export_dir, 32)[0]
    addr_of_name_ordinals = struct.unpack_from("<I", export_dir, 36)[0]

    name_bytes = name.encode()
    names_table = _read_process_memory(h_process, module_base + addr_of_names, 4 * num_names)
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", names_table, 4 * i)[0]
        candidate = _read_process_memory(h_process, module_base + name_rva, len(name_bytes) + 1)
        if candidate == name_bytes + b"\x00":
            ordinals_table = _read_process_memory(h_process, module_base + addr_of_name_ordinals, 2 * num_names)
            ordinal = struct.unpack_from("<H", ordinals_table, 2 * i)[0]
            functions_table = _read_process_memory(h_process, module_base + addr_of_functions, 4 * (ordinal + 1))
            return struct.unpack_from("<I", functions_table, 4 * ordinal)[0]
    raise OSError(f"{name} not found in the live module's export table")


def unload(pid):
    """Remotely FreeLibrary()s our DLL out of the target process, if
    loaded - lets us recompile and reinject without closing the game
    between iterations (a loaded DLL's file can't be overwritten)."""
    h_module, module_base = _find_dll_module(pid)
    if h_module is None:
        return True

    h_process = K32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise OSError(f"OpenProcess failed: {ctypes.GetLastError()}")
    try:
        # Restore the game's own D3D vtable slot BEFORE freeing the DLL -
        # see overlay.cpp's RestoreHook for why: without this, the slot
        # is left pointing into memory that's about to be unmapped, and
        # the very next rendered frame crashes the game. Best-effort:
        # still try to unload even if this fails (e.g. older DLL build
        # without the export, or path mismatch).
        #
        # Resolved from the LIVE module's own export table (see
        # _dll_export_rva_live's docstring) - NOT from dll_path on disk,
        # which may have since been recompiled with a different layout
        # than whatever's actually still loaded in this process.
        try:
            restore_rva = _dll_export_rva_live(h_process, module_base, "RestoreHook")
            restore_addr = module_base + restore_rva
            thread_id = w.DWORD(0)
            h_thread = K32.CreateRemoteThread(h_process, None, 0, restore_addr,
                                               None, 0, ctypes.byref(thread_id))
            if h_thread:
                K32.WaitForSingleObject(h_thread, 5000)
                K32.CloseHandle(h_thread)
        except Exception:
            pass

        free_library_addr = _target_proc_addr(pid, "FreeLibrary")
        thread_id = w.DWORD(0)
        h_thread = K32.CreateRemoteThread(h_process, None, 0, free_library_addr,
                                           h_module, 0, ctypes.byref(thread_id))
        if not h_thread:
            raise OSError(f"CreateRemoteThread failed: {ctypes.GetLastError()}")
        K32.WaitForSingleObject(h_thread, 5000)
        K32.CloseHandle(h_thread)
    finally:
        K32.CloseHandle(h_process)

    return not is_injected(pid)


def inject(pid, dll_path=None):
    """Loads shopmod_overlay.dll into the target process, unless it's
    already loaded there. Returns True if the DLL ends up loaded.

    dll_path overrides the module-level default - callers running from
    a frozen (PyInstaller) build should pass their own resolved path,
    since this module's own __file__ isn't reliable once bundled."""
    if is_injected(pid):
        return True
    dll_path = dll_path or DLL_PATH
    if not os.path.isfile(dll_path):
        raise FileNotFoundError(f"overlay DLL not built: {dll_path}")

    h_process = K32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        raise OSError(f"OpenProcess failed: {ctypes.GetLastError()}")

    try:
        path_bytes = dll_path.encode("mbcs") + b"\x00"
        remote_mem = K32.VirtualAllocEx(h_process, None, len(path_bytes),
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote_mem:
            raise OSError(f"VirtualAllocEx failed: {ctypes.GetLastError()}")

        written = ctypes.c_size_t(0)
        if not K32.WriteProcessMemory(h_process, remote_mem, path_bytes,
                                       len(path_bytes), ctypes.byref(written)):
            raise OSError(f"WriteProcessMemory failed: {ctypes.GetLastError()}")

        load_library_addr = _target_proc_addr(pid, "LoadLibraryA")

        thread_id = w.DWORD(0)
        h_thread = K32.CreateRemoteThread(h_process, None, 0, load_library_addr,
                                           remote_mem, 0, ctypes.byref(thread_id))
        if not h_thread:
            raise OSError(f"CreateRemoteThread failed: {ctypes.GetLastError()}")

        K32.WaitForSingleObject(h_thread, 5000)
        K32.CloseHandle(h_thread)
    finally:
        K32.CloseHandle(h_process)

    return is_injected(pid)
