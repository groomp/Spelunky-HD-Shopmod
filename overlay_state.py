"""Python mirror of overlay/overlay_state.h - the shared-memory protocol
between the injected overlay DLL (owns live UI state: the player's
chosen variant/item order, driven by mouse input on the in-game panel -
see overlay/overlay.cpp) and this controller (owns actual game-memory
patching - see shop_patch.py). One-directional: the DLL writes, we only
ever read and react.

Keep this struct layout byte-for-byte in sync with overlay_state.h.
"""

import ctypes
import mmap

PANEL_SHM_NAME = "ShopmodPanelSHM"
PANEL_MAGIC = 0x53484D31

VARIANT_COUNT = 2
ITEMS_PER_VARIANT = 4
ITEM_NAME_LEN = 16


class PanelState(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("generation", ctypes.c_uint32),
        ("assets_dir", ctypes.c_char * 260),
        ("variant_name", ctypes.c_char * 32),
        ("item_ids", (ctypes.c_char * ITEM_NAME_LEN) * ITEMS_PER_VARIANT),
    ]


class PanelStateReader:
    """Opens (creating if needed) the named shared-memory block and lets
    the controller seed assets_dir and poll for DLL-published updates."""

    def __init__(self):
        self._mm = mmap.mmap(-1, ctypes.sizeof(PanelState), tagname=PANEL_SHM_NAME)
        self._state = PanelState.from_buffer(self._mm)
        self._last_generation = None

    def set_assets_dir(self, path):
        self._state.assets_dir = path.encode("mbcs")[:259]

    def poll_order(self):
        """Returns a list of item-name strings if the DLL published a new
        order/variant since the last call, else None."""
        if self._state.magic != PANEL_MAGIC:
            return None
        if self._state.generation == self._last_generation:
            return None
        self._last_generation = self._state.generation
        return [self._state.item_ids[i].value.decode("ascii", errors="ignore")
                for i in range(ITEMS_PER_VARIANT)]
