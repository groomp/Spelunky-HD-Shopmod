// Shared-memory protocol between the injected overlay DLL (owns live UI
// state - the player's chosen variant/item order, driven by mouse input
// on the in-game panel) and the external Python controller (owns actual
// game-memory patching - see shop_patch.py). One-directional: the DLL
// writes, Python only ever reads and reacts by calling
// shop_patch.sync_to_level with whatever order it last saw here.
//
// This exact layout (field order, sizes, 1-byte packing) is mirrored in
// Python via ctypes.Structure with _pack_ = 1 - keep both in sync.

#pragma once

#define PANEL_SHM_NAME "ShopmodPanelSHM"
#define PANEL_MAGIC 0x53484D31u // "1MHS" little-endian - sanity check only

#define VARIANT_COUNT 2
#define ITEMS_PER_VARIANT 4
#define ITEM_NAME_LEN 16

// All items that can ever appear in a slot (jetpack/cape toggle in
// place via double-click, so both must be loadable even though only
// one occupies a slot at a time; vlads_cape likewise - a 10-rapid-click
// easter egg on the jetpack/cape slot, see OnMouseDown).
static const char* ITEM_NAMES[] = {
    "jetpack", "teleporter", "compass", "bomb_box", "mattock", "cape", "vlads_cape",
};
#define ITEM_COUNT 7

#pragma pack(push, 1)
struct PanelState {
    uint32_t magic;
    uint32_t generation;
    char assets_dir[260];
    char variant_name[32];
    char item_ids[ITEMS_PER_VARIANT][ITEM_NAME_LEN];
};
#pragma pack(pop)
