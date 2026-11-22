"""Standalone practice tool (separate from PB Tracker): live-patches
Spelunky's own shop item-pool generator (see shop_patch.py for how/why)
so every shop in the game only ever offers a chosen 4-item set.

Both the "SHOPMOD" watermark and the item-order panel are rendered
in-process via a Direct3D9 hook (see overlay/overlay.cpp, injected via
overlay_inject.py) instead of as separate Tkinter windows. An earlier
version embedded a Tk panel as a Win32 child window of Spelunky's own
window (SetParent) - that turned out to be fundamentally fragile: Tk
wasn't designed to live inside a foreign process's window tree, and it
would silently stop rendering on focus changes in every display mode
(fullscreen, borderless, and genuine windowed alike), not just the
expected exclusive-fullscreen DWM limitation. Rendering everything
through the same D3D hook as the watermark sidesteps that whole class
of bug, and also means the panel is visible under every capture method
just like the watermark is.

The DLL owns live UI state (which variant/order the player has chosen,
driven by mouse input on the in-game panel) and publishes it through
shared memory (see overlay_state.py); this process only ever reads that
and applies it to the game's own memory via shop_patch - the reverse of
how the old Tk panel worked, where this process owned the UI directly.

Single-instance: launching the exe while it's already running signals
the running copy to quit instead of starting a second one, so the exe
itself acts as an on/off toggle (see main()).
"""

import ctypes
import os
import sys
import threading
import time

from spawn_item import find_pid
import overlay_inject
import overlay_state
import shop_patch
import tray_icon

OVERLAY_DLL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "overlay", "shopmod_overlay.dll")
ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
ICON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")

# A shop's items get picked once, at level-load time, from whatever is
# in memory at that exact instant - sync_to_level has to win a race
# against that, not just eventually catch up. At the old 0.5s interval,
# a level transition landing early in a poll gap let the next level's
# shop get generated (and permanently baked in - reverting afterwards
# doesn't un-bake it) before we'd caught up and reverted - confirmed
# live: a 1-3 shop still forced minutes after the raw level counter
# had already read 3 and the underlying bytes had already reverted.
# 0.05s matches pb_tracker's own POLL_INTERVAL_SECONDS, already proven
# safe for reading this same game's memory this often.
POLL_SECONDS = 0.05
# find_pid()/is_injected() each do a full process/module enumeration -
# not worth doing 20x/second just to catch a pid change or a missing
# overlay DLL, neither of which is a race against level-load timing -
# so only sync_to_level (the one actually racing that) runs every fast
# tick; these two run every Nth tick, same real-world cadence as the
# old flat 0.5s poll.
PROCESS_CHECK_EVERY_N_TICKS = 10

MUTEX_NAME = "ShopmodSingleInstanceMutex"
QUIT_EVENT_NAME = "ShopmodQuitEvent"
ERROR_ALREADY_EXISTS = 183

PROCESS_TERMINATE = 0x0001
MISSING_GAME_TICKS_TO_QUIT = 2  # 1s debounce (at the throttled process-check cadence) against a one-off find_pid() miss


def _kill_process(pid):
    if pid is None:
        return
    k32 = ctypes.windll.kernel32
    h = k32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if h:
        k32.TerminateProcess(h, 0)
        k32.CloseHandle(h)


class App:
    def __init__(self, request_quit):
        self.pm = None
        self.base = None
        self.last_pid = None
        self.order = list(shop_patch.VARIANTS["Any% Shop"])

        # Lets the watchdog trigger the exact same shutdown path as the
        # tray icon/taskbar close/relaunch-toggle (see main()) when it
        # notices Spelunky itself has closed - the two processes'
        # lifetimes are linked both ways: this one for "game closed ->
        # close Shopmod too", shutdown() below for the reverse
        # ("Shopmod closed -> kill the game too").
        self._request_quit = request_quit
        self._game_present = False
        self._missing_game_ticks = 0

        self.panel_state = overlay_state.PanelStateReader()
        self.panel_state.set_assets_dir(ASSETS_DIR)

        self._stop = threading.Event()
        self._reconnect_and_apply()
        self._watchdog_thread = threading.Thread(target=self._watchdog_loop, daemon=True)
        self._watchdog_thread.start()

    def _apply_current_order(self):
        if self.pm is None:
            return
        try:
            shop_patch.sync_to_level(self.pm, self.base, self.order)
        except Exception:
            self.pm = None

    def _reconnect_and_apply(self):
        try:
            self.pm, self.base = shop_patch.connect()
            shop_patch.sync_to_level(self.pm, self.base, self.order)
            self.last_pid = find_pid()
            try:
                overlay_inject.inject(self.last_pid, OVERLAY_DLL_PATH)
            except Exception:
                pass  # watermark/panel are best-effort - never block shop forcing on them
        except SystemExit:
            self.pm = None
        except Exception:
            self.pm = None

    def _watchdog_loop(self):
        tick = 0
        while not self._stop.is_set():
            time.sleep(POLL_SECONDS)
            tick += 1

            new_order = self.panel_state.poll_order()
            if new_order and all(new_order):
                self.order = new_order

            # The timing-critical part - runs every fast tick, using
            # whatever connection the last (throttled) process check
            # established. See sync_to_level/shop_patch for why this is
            # the part that actually needs to win a race.
            if self.pm is not None:
                try:
                    shop_patch.sync_to_level(self.pm, self.base, self.order)
                except Exception:
                    self.pm = None

            if tick % PROCESS_CHECK_EVERY_N_TICKS != 0:
                continue

            pid = find_pid()
            if pid is None:
                if self._game_present:
                    self._missing_game_ticks += 1
                    if self._missing_game_ticks >= MISSING_GAME_TICKS_TO_QUIT:
                        # Spelunky closed or crashed on its own - close
                        # Shopmod too instead of idling with nothing
                        # to attach to.
                        self._game_present = False
                        self.pm = None
                        self.last_pid = None
                        self._request_quit()
                        return
                else:
                    self.pm = None
                    self.last_pid = None
                continue
            self._missing_game_ticks = 0
            self._game_present = True
            if self.pm is None or pid != self.last_pid:
                self._reconnect_and_apply()
                continue
            try:
                # Covers the overlay DLL going missing without the game
                # process itself restarting (e.g. an external unload).
                if not overlay_inject.is_injected(pid):
                    overlay_inject.inject(pid, OVERLAY_DLL_PATH)
            except Exception:
                pass

    def shutdown(self):
        self._stop.set()
        pid_to_kill = self.last_pid
        if self.pm is not None:
            try:
                shop_patch.restore_vanilla(self.pm, self.base)
            except Exception:
                pass
        if self.last_pid is not None:
            try:
                # Unload the overlay DLL so a later toggle-on re-injects
                # fresh and re-hooks whatever device is live then -
                # otherwise is_injected() would see the (possibly
                # stale/orphaned) DLL still loaded and skip reinjecting.
                overlay_inject.unload(self.last_pid)
            except Exception:
                pass
        # The two processes' lifetimes are linked both ways (see
        # __init__'s _request_quit note) - this is a no-op if Spelunky
        # already closed on its own and triggered this same shutdown
        # (pid_to_kill is already None by then).
        _kill_process(pid_to_kill)

    def run(self):
        self._watchdog_thread.join()


def main():
    k32 = ctypes.windll.kernel32
    k32.CreateMutexW(None, False, MUTEX_NAME)
    already_running = k32.GetLastError() == ERROR_ALREADY_EXISTS

    if already_running:
        # EVENT_MODIFY_STATE = 0x2
        quit_event = k32.OpenEventW(0x2, False, QUIT_EVENT_NAME)
        if quit_event:
            k32.SetEvent(quit_event)
            k32.CloseHandle(quit_event)
        sys.exit(0)

    quit_event = k32.CreateEventW(None, True, False, QUIT_EVENT_NAME)
    app = App(request_quit=lambda: k32.SetEvent(quit_event))

    def watch_quit():
        k32.WaitForSingleObject(quit_event, 0xFFFFFFFF)
        app.shutdown()

    threading.Thread(target=watch_quit, daemon=True).start()

    try:
        # Gives the exe a visible presence outside Task Manager and an
        # obvious way to close it (right-click -> Exit, or double-click
        # the icon) - routed through the same quit_event as launching
        # the exe a second time, so it's the exact same shutdown path.
        tray_icon.run_in_background(
            ICON_PATH, "Shopmod - right-click to exit",
            on_exit=lambda: k32.SetEvent(quit_event),
        )
    except Exception:
        pass  # best-effort - never block shop forcing on the tray icon

    app.run()


if __name__ == "__main__":
    main()
