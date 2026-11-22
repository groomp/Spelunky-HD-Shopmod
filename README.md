# Shopmod

v0.1

A practice tool for *Spelunky Classic (HD)* that live-patches the game's
shop item-pool generator so every shop in the game only ever offers a
chosen 4-item set, in a chosen shelf order. Useful for route/trick
practice where you want guaranteed access to specific shop items
(jetpack, cape, teleporter, compass, mattock, bomb box) without
resetting until the right shop rolls.

An in-game overlay panel (rendered via a D3D9 hook, so it shows up
under any capture method) lets you drag items into the order you want
and toggle between item variants; the controller process reads that
and patches the game's memory to match, live, as you move between
levels.

## How it works

- `overlay/` — a D3D9 hook DLL (`shopmod_overlay.dll`) injected into
  `Spelunky.exe`. Renders the watermark + item-order panel and owns
  live UI state (mouse input on the panel).
- `shop_patch.py` — reads the shop item-pool generator's live memory
  and patches it to force the chosen item set/order. Includes
  hand-built x86 "code cave" extensions for two shop pools whose
  vanilla dedup logic couldn't otherwise reach 4 distinct forced items
  without hanging.
- `shop_forcer.py` — main controller: injects the overlay, polls the
  overlay's shared-memory state, and applies it via `shop_patch`.
  Also runs a system tray icon and links both processes' lifetimes
  (closing the game closes Shopmod, and vice versa).
- `tools/` — Ghidra scratch scripts and decompile/disassembly dumps
  from reverse-engineering the shop generator. Kept for reference;
  not needed to run the tool.

## Usage

Run `Shopmod.exe` (built via `Shopmod.spec` with PyInstaller) while
Spelunky is running. Launching it again while it's already running
closes it — it acts as an on/off toggle. Right-click the tray icon
(or close its taskbar entry) to exit.

## Disclaimer

This works by patching another process's memory at runtime. It's a
single-player practice aid, not a cheat/multiplayer-advantage tool,
and isn't affiliated with or endorsed by Mossmouth/the game's
developer. Extracted game sprites/sounds used by the overlay remain
the original developer's assets, used here with permission for this
project specifically.
