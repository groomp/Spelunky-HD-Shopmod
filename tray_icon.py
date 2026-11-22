"""Minimal Win32 system tray icon, so Shopmod is visible somewhere
other than Task Manager and has an obvious way to close it (right-click
-> Exit, or just double-click the icon) instead of hunting it down in
Task Manager. Pure ctypes - no extra dependency (pystray etc.), kept in
the same style as the rest of this project's Win32 calls.

Runs its own hidden window + message loop on a dedicated thread (started
by run_in_background below); the window is what actually receives the
tray icon's mouse-click callback message, Windows requires a window for
that regardless of whether anything is ever shown on screen.
"""

import ctypes
import ctypes.wintypes as w
import threading

K32 = ctypes.windll.kernel32
U32 = ctypes.windll.user32
Shell32 = ctypes.windll.shell32

LRESULT = ctypes.c_longlong
ULONG_PTR = ctypes.c_uint64

# Explicit argtypes/restype for everything that carries a WPARAM/LPARAM/
# pointer-sized value - without these, ctypes falls back to marshalling
# plain Python ints as 32-bit C int and raises OverflowError the first
# time a real (64-bit-range) value comes through (confirmed via a
# smoke test: DefWindowProcW blew up on the very first routine message).
U32.DefWindowProcW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
U32.DefWindowProcW.restype = LRESULT
U32.RegisterClassW.argtypes = [ctypes.c_void_p]
U32.RegisterClassW.restype = w.ATOM
U32.CreateWindowExW.argtypes = [w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD, ctypes.c_int, ctypes.c_int,
                                 ctypes.c_int, ctypes.c_int, w.HWND, w.HMENU, w.HINSTANCE, ctypes.c_void_p]
U32.CreateWindowExW.restype = w.HWND
U32.DestroyWindow.argtypes = [w.HWND]
U32.PostMessageW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
U32.PostQuitMessage.argtypes = [ctypes.c_int]
U32.GetMessageW.argtypes = [ctypes.c_void_p, w.HWND, w.UINT, w.UINT]
U32.TranslateMessage.argtypes = [ctypes.c_void_p]
U32.DispatchMessageW.argtypes = [ctypes.c_void_p]
U32.LoadImageW.argtypes = [w.HINSTANCE, w.LPCWSTR, w.UINT, ctypes.c_int, ctypes.c_int, w.UINT]
U32.LoadImageW.restype = w.HANDLE
U32.DestroyIcon.argtypes = [w.HICON]
U32.GetCursorPos.argtypes = [ctypes.c_void_p]
U32.SetForegroundWindow.argtypes = [w.HWND]
U32.CreatePopupMenu.restype = w.HMENU
U32.AppendMenuW.argtypes = [w.HMENU, w.UINT, ctypes.c_void_p, w.LPCWSTR]
U32.TrackPopupMenuEx.argtypes = [w.HMENU, w.UINT, ctypes.c_int, ctypes.c_int, w.HWND, ctypes.c_void_p]
U32.DestroyMenu.argtypes = [w.HMENU]
U32.ShowWindow.argtypes = [w.HWND, ctypes.c_int]
U32.SendMessageW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
U32.SendMessageW.restype = LRESULT
Shell32.Shell_NotifyIconW.argtypes = [w.DWORD, ctypes.c_void_p]

WS_OVERLAPPEDWINDOW = 0x00CF0000
SW_SHOWMINNOACTIVE = 7  # minimized, without stealing focus from the game

WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_COMMAND = 0x0111
WM_APP = 0x8000
WM_TRAYICON = WM_APP + 1
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_LBUTTONUP = 0x0202

NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002
NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004

IMAGE_ICON = 1
LR_LOADFROMFILE = 0x00000010
LR_DEFAULTSIZE = 0x00000040

MF_STRING = 0x00000000
TPM_RIGHTBUTTON = 0x0002
TPM_RETURNCMD = 0x0100

IDM_EXIT = 1001
GWLP_WNDPROC = -4

WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_long, w.HWND, w.UINT, w.WPARAM, w.LPARAM)


class WNDCLASS(ctypes.Structure):
    _fields_ = [
        ("style", w.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int), ("hInstance", w.HINSTANCE), ("hIcon", w.HICON),
        ("hCursor", w.HANDLE), ("hbrBackground", w.HBRUSH),
        ("lpszMenuName", w.LPCWSTR), ("lpszClassName", w.LPCWSTR),
    ]


class NOTIFYICONDATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", w.DWORD), ("hWnd", w.HWND), ("uID", w.UINT), ("uFlags", w.UINT),
        ("uCallbackMessage", w.UINT), ("hIcon", w.HICON), ("szTip", ctypes.c_wchar * 128),
    ]


def run(icon_path, tooltip, on_exit):
    """Blocks running the tray icon's message loop - call this on its
    own thread. on_exit() is called once (right-click Exit, or
    double-click the icon); this function returns after cleanup."""
    hinstance = K32.GetModuleHandleW(None)
    class_name = "ShopmodTrayWnd"

    def wndproc(hwnd, msg, wparam, lparam):
        if msg == WM_TRAYICON:
            event = lparam & 0xFFFF
            if event == WM_RBUTTONUP:
                menu = U32.CreatePopupMenu()
                U32.AppendMenuW(menu, MF_STRING, IDM_EXIT, "Exit Shopmod")
                pt = w.POINT()
                U32.GetCursorPos(ctypes.byref(pt))
                U32.SetForegroundWindow(hwnd)
                cmd = U32.TrackPopupMenuEx(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD,
                                           pt.x, pt.y, hwnd, None)
                U32.DestroyMenu(menu)
                if cmd == IDM_EXIT:
                    U32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            elif event == WM_LBUTTONDBLCLK:
                U32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            return 0
        if msg == WM_COMMAND and (wparam & 0xFFFF) == IDM_EXIT:
            U32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            return 0
        if msg == WM_CLOSE:
            U32.DestroyWindow(hwnd)
            return 0
        if msg == WM_DESTROY:
            U32.PostQuitMessage(0)
            return 0
        return U32.DefWindowProcW(hwnd, msg, wparam, lparam)

    wndproc_ref = WNDPROC(wndproc)  # keep alive - ctypes doesn't pin callbacks on its own

    wc = WNDCLASS()
    wc.lpfnWndProc = wndproc_ref
    wc.hInstance = hinstance
    wc.lpszClassName = class_name
    U32.RegisterClassW(ctypes.byref(wc))

    # WS_OVERLAPPEDWINDOW (not the invisible style=0 this started with) so
    # the window also shows up as a taskbar button - minimized via
    # ShowWindow below, so it's reachable to close (right-click -> Close
    # window / Alt+F4 once focused) without ever popping up on screen or
    # stealing focus, in addition to the tray icon's own right-click Exit.
    hwnd = U32.CreateWindowExW(0, class_name, "Shopmod", WS_OVERLAPPEDWINDOW,
                                0, 0, 1, 1, None, None, hinstance, None)
    U32.ShowWindow(hwnd, SW_SHOWMINNOACTIVE)

    hicon = U32.LoadImageW(None, icon_path, IMAGE_ICON, 0, 0,
                            LR_LOADFROMFILE | LR_DEFAULTSIZE)
    if hicon:
        WM_SETICON = 0x0080
        ICON_BIG = 1
        ICON_SMALL = 0
        U32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, hicon)
        U32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hicon)

    nid = NOTIFYICONDATA()
    nid.cbSize = ctypes.sizeof(NOTIFYICONDATA)
    nid.hWnd = hwnd
    nid.uID = 1
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP
    nid.uCallbackMessage = WM_TRAYICON
    nid.hIcon = hicon
    nid.szTip = tooltip
    Shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))

    msg = w.MSG()
    while U32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        U32.TranslateMessage(ctypes.byref(msg))
        U32.DispatchMessageW(ctypes.byref(msg))

    Shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
    if hicon:
        U32.DestroyIcon(hicon)
    on_exit()


def run_in_background(icon_path, tooltip, on_exit):
    """Starts run() on a daemon thread and returns immediately."""
    t = threading.Thread(target=run, args=(icon_path, tooltip, on_exit), daemon=True)
    t.start()
    return t
