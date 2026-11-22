// In-process Direct3D9 overlay for Spelunky.exe. Injected via LoadLibrary
// into the game's own process (see overlay_inject.py). Two pieces:
//
//  1. The "SHOPMOD" watermark - hooks IDirect3DDevice9::EndScene through
//     its vtable (the same technique ReShade/overlay tools use) so it's
//     drawn as part of the actual rendered frame, visible under every
//     capture method including true exclusive-fullscreen D3D9 and OBS's
//     hook-based Game Capture.
//
//  2. The item-order panel - originally a separate Tkinter window
//     reparented into the game's own window (SetParent). That turned out
//     to be fundamentally fragile: Tk wasn't designed to live inside a
//     foreign process's window tree, and it would silently stop
//     rendering on focus changes in EVERY display mode (fullscreen,
//     borderless, and genuine windowed alike) - not just the expected
//     exclusive-fullscreen DWM limitation. So the panel is rendered here
//     too, the same way as the watermark, with its own mouse-driven
//     drag/click handling via the game's own WndProc (see below).
//
// Shared memory (PanelState, see overlay_state.h) is how this DLL tells
// the external Python controller (which still owns the actual shop
// memory patching) what item order/variant the player has chosen: this
// DLL owns live UI state and pushes it out; Python only ever reads.
//
// A dummy device's vtable is NOT shared with the game's real device on
// this system (tested empirically - installed cleanly but never
// fired), so instead we read the game's own global IDirect3DDevice9*
// pointer directly: Spelunky.exe stores it at (module base + 0x14619C)
// once at device-creation time and keeps using it for the rest of the
// process's life (confirmed via Ghidra - that address is dereferenced
// for CreateTexture calls throughout the game's own rendering code).
// Hooking off the real pointer's own vtable is guaranteed correct, no
// sharing assumption required.
//
// Re-hooking after the game recreates its device (observed on tab-in)
// needs a live trigger, not just a one-shot hook at startup. An earlier
// version used an independent timer thread for this, but that raced
// with the game's own render thread calling through the vtable
// mid-rewrite and crashed the game three times (confirmed via Windows
// Error Reporting - faults landed inside this DLL). Subclassing the
// game's own WndProc instead means our re-check runs on the SAME
// thread that pumps messages and renders - never concurrently with the
// thing it's protecting, so no race is possible. That same WndProc
// subclass now also drives all of the panel's mouse interaction.

#include <windows.h>
#include <windowsx.h>
#include <d3d9.h>
#include <gdiplus.h>
#include <mmsystem.h>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include "overlay_state.h"

#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "winmm.lib")

static const uintptr_t DEVICE_PTR_OFFSET = 0x14619C;
static const char* WATERMARK_TEXT = "SHOPMOD v0.1";

typedef HRESULT(STDMETHODCALLTYPE* EndScene_t)(IDirect3DDevice9*);
static EndScene_t oEndScene = nullptr;

struct Vertex {
    float x, y, z, rhw;
    DWORD color;
    float u, v;
};
static const DWORD FVF = D3DFVF_XYZRHW | D3DFVF_DIFFUSE | D3DFVF_TEX1;

// ---------------------------------------------------------------------
// Text-to-texture rendering (used for the watermark and all panel text)
// ---------------------------------------------------------------------

// Renders white-on-black text into memDC/returns per-pixel coverage
// (0..255) as a standalone grayscale buffer - letting callers composite
// it as alpha however they like (e.g. with a shadow pass underneath)
// instead of fighting over the same RGB channel GDI text drawing uses.
static void RenderGlyphCoverage(HDC memDC, HFONT font, const wchar_t* text, int w, int h,
                                 int offsetX, int offsetY, uint8_t* outCoverage) {
    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = w;
    bmi.bmiHeader.biHeight = -h;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HBITMAP dib = CreateDIBSection(memDC, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    HBITMAP oldBmp = (HBITMAP)SelectObject(memDC, dib);
    HFONT oldFont = (HFONT)SelectObject(memDC, font);
    memset(bits, 0, (size_t)w * h * 4);

    SetBkMode(memDC, TRANSPARENT);
    SetTextColor(memDC, RGB(255, 255, 255));
    RECT rect = {offsetX, offsetY, w, h};
    DrawTextW(memDC, text, -1, &rect, DT_LEFT | DT_TOP | DT_SINGLELINE);

    uint32_t* px = (uint32_t*)bits;
    for (int i = 0; i < w * h; i++) {
        outCoverage[i] = (uint8_t)((px[i] >> 16) & 0xFF); // R==G==B for white-on-black text
    }

    SelectObject(memDC, oldFont);
    SelectObject(memDC, oldBmp);
    DeleteObject(dib);
}

// General-purpose text texture: measures the text, renders it (optional
// drop shadow), and uploads a premultiplied-alpha D3D9 texture sized
// exactly to fit. Caller owns the returned texture (Release() it).
static IDirect3DTexture9* CreateTextTexture(IDirect3DDevice9* device, const wchar_t* text,
                                             int fontHeight, int fontWeight, bool shadow,
                                             int* outW, int* outH, bool extraBold = false) {
    HDC screenDC = GetDC(nullptr);
    HFONT font = CreateFontW(
        fontHeight, 0, 0, 0, fontWeight, FALSE, FALSE, FALSE,
        ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
    HDC memDC = CreateCompatibleDC(screenDC);
    HFONT oldFont = (HFONT)SelectObject(memDC, font);

    SIZE sz;
    GetTextExtentPoint32W(memDC, text, (int)wcslen(text), &sz);
    SelectObject(memDC, oldFont);

    const int SHADOW_OFFSET = shadow ? 3 : 0;
    const int PAD = 6;
    int w = sz.cx + PAD * 2 + SHADOW_OFFSET;
    int h = sz.cy + PAD * 2 + SHADOW_OFFSET;

    auto mainCoverage = std::make_unique<uint8_t[]>((size_t)w * h);
    RenderGlyphCoverage(memDC, font, text, w, h, PAD, PAD, mainCoverage.get());

    // FW_HEAVY (900) is already GDI's heaviest standard weight - this
    // thickens strokes further by 1px via a cheap max-filter dilation
    // (poor man's faux-bold), for callers that still want bolder than
    // that.
    if (extraBold) {
        auto dilated = std::make_unique<uint8_t[]>((size_t)w * h);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                uint8_t best = mainCoverage[y * w + x];
                if (x + 1 < w) best = max(best, mainCoverage[y * w + x + 1]);
                if (x > 0) best = max(best, mainCoverage[y * w + x - 1]);
                if (y + 1 < h) best = max(best, mainCoverage[(y + 1) * w + x]);
                if (y > 0) best = max(best, mainCoverage[(y - 1) * w + x]);
                dilated[y * w + x] = best;
            }
        }
        mainCoverage = std::move(dilated);
    }

    std::unique_ptr<uint8_t[]> shadowCoverage;
    if (shadow) {
        shadowCoverage = std::make_unique<uint8_t[]>((size_t)w * h);
        RenderGlyphCoverage(memDC, font, text, w, h, PAD + SHADOW_OFFSET, PAD + SHADOW_OFFSET, shadowCoverage.get());
    }

    auto bits = std::make_unique<uint32_t[]>((size_t)w * h);
    for (int i = 0; i < w * h; i++) {
        float a_main = mainCoverage[i] / 255.0f;
        float a_out = a_main;
        if (shadow) {
            float a_shadow = (shadowCoverage[i] / 255.0f) * 0.75f;
            a_out = a_main + a_shadow * (1.0f - a_main);
        }
        uint8_t premulWhite = (uint8_t)(a_main * 255.0f + 0.5f);
        uint8_t aOut = (uint8_t)(a_out * 255.0f + 0.5f);
        bits[i] = ((uint32_t)aOut << 24) | ((uint32_t)premulWhite << 16) |
                  ((uint32_t)premulWhite << 8) | premulWhite;
    }

    IDirect3DTexture9* tex = nullptr;
    HRESULT hr = device->CreateTexture(w, h, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED, &tex, nullptr);
    if (SUCCEEDED(hr) && tex) {
        D3DLOCKED_RECT locked;
        tex->LockRect(0, &locked, nullptr, 0);
        for (int y = 0; y < h; y++) {
            memcpy((uint8_t*)locked.pBits + (size_t)y * locked.Pitch,
                   (uint8_t*)bits.get() + (size_t)y * w * 4, (size_t)w * 4);
        }
        tex->UnlockRect(0);
    }

    DeleteObject(font);
    DeleteDC(memDC);
    ReleaseDC(nullptr, screenDC);

    *outW = w;
    *outH = h;
    return tex;
}

// Draws a premultiplied-alpha text/sprite-style texture as a screen-space
// quad. premultipliedAlpha selects the matching blend factors.
static void DrawTexturedQuad(IDirect3DDevice9* device, IDirect3DTexture9* tex,
                              int x, int y, int w, int h, bool premultipliedAlpha, DWORD tint = 0xFFFFFFFF) {
    if (!tex) return;
    device->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE);
    device->SetRenderState(D3DRS_SRCBLEND, premultipliedAlpha ? D3DBLEND_ONE : D3DBLEND_SRCALPHA);
    device->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
    device->SetRenderState(D3DRS_ZENABLE, D3DZB_FALSE);
    device->SetRenderState(D3DRS_ZWRITEENABLE, FALSE);
    device->SetRenderState(D3DRS_LIGHTING, FALSE);
    device->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
    device->SetRenderState(D3DRS_FOGENABLE, FALSE);
    device->SetRenderState(D3DRS_ALPHATESTENABLE, FALSE);

    device->SetTexture(0, tex);
    device->SetSamplerState(0, D3DSAMP_MAGFILTER, D3DTEXF_POINT);
    device->SetSamplerState(0, D3DSAMP_MINFILTER, D3DTEXF_POINT);
    device->SetFVF(FVF);
    device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
    device->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
    device->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
    device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
    device->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
    device->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
    device->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_DISABLE);
    device->SetTextureStageState(1, D3DTSS_ALPHAOP, D3DTOP_DISABLE);

    const float hx = (float)x - 0.5f;
    const float hy = (float)y - 0.5f;
    Vertex verts[4] = {
        {hx,            hy,            0.0f, 1.0f, tint, 0.0f, 0.0f},
        {hx + w,        hy,            0.0f, 1.0f, tint, 1.0f, 0.0f},
        {hx,            hy + h,        0.0f, 1.0f, tint, 0.0f, 1.0f},
        {hx + w,        hy + h,        0.0f, 1.0f, tint, 1.0f, 1.0f},
    };
    device->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP, 2, verts, sizeof(Vertex));
}

// Draws a texture as a flat-colored silhouette: the texture's own alpha
// channel is kept as the shape mask, but its COLOR channels are
// replaced entirely by a solid color (SELECTARG2/diffuse), instead of
// modulating (multiplying) the texture's own colors by a tint - a white
// modulate tint is a no-op on color (multiplying by 1.0 changes
// nothing), which is why an earlier version of this just drew extra
// full-color copies of the sprite instead of an actual white silhouette.
static void DrawTextureSilhouette(IDirect3DDevice9* device, IDirect3DTexture9* tex,
                                   int x, int y, int w, int h, DWORD color, bool premultipliedAlpha) {
    device->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE);
    device->SetRenderState(D3DRS_SRCBLEND, premultipliedAlpha ? D3DBLEND_ONE : D3DBLEND_SRCALPHA);
    device->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
    device->SetRenderState(D3DRS_ZENABLE, D3DZB_FALSE);
    device->SetRenderState(D3DRS_LIGHTING, FALSE);
    device->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
    device->SetTexture(0, tex);
    device->SetSamplerState(0, D3DSAMP_MAGFILTER, D3DTEXF_POINT);
    device->SetSamplerState(0, D3DSAMP_MINFILTER, D3DTEXF_POINT);
    device->SetFVF(FVF);
    device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_SELECTARG2);
    device->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
    device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
    device->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
    device->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
    device->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_DISABLE);
    device->SetTextureStageState(1, D3DTSS_ALPHAOP, D3DTOP_DISABLE);

    const float hx = (float)x - 0.5f;
    const float hy = (float)y - 0.5f;
    Vertex verts[4] = {
        {hx,       hy,       0.0f, 1.0f, color, 0.0f, 0.0f},
        {hx + w,   hy,       0.0f, 1.0f, color, 1.0f, 0.0f},
        {hx,       hy + h,   0.0f, 1.0f, color, 0.0f, 1.0f},
        {hx + w,   hy + h,   0.0f, 1.0f, color, 1.0f, 1.0f},
    };
    device->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP, 2, verts, sizeof(Vertex));
}

// Cheap "poor man's outline" for a sprite: draws a solid-color
// silhouette of the sprite offset in 8 directions, underneath wherever
// the caller draws the real sprite on top - the offset copies' edges
// poke out past the real sprite's edges just enough to form a thin
// ring, while the centre gets fully covered by the normal draw.
static void DrawTextureOutline(IDirect3DDevice9* device, IDirect3DTexture9* tex,
                                int x, int y, int w, int h, int thickness, DWORD color, bool premultipliedAlpha) {
    static const int DX[8] = {-1, 1, 0, 0, -1, -1, 1, 1};
    static const int DY[8] = {0, 0, -1, 1, -1, 1, -1, 1};
    for (int i = 0; i < 8; i++) {
        DrawTextureSilhouette(device, tex, x + DX[i] * thickness, y + DY[i] * thickness, w, h, color, premultipliedAlpha);
    }
}

// Flat-colored quad (panel background, hover highlight) - no texture.
static void DrawColorQuad(IDirect3DDevice9* device, int x, int y, int w, int h, DWORD color) {
    device->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE);
    device->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
    device->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
    device->SetRenderState(D3DRS_ZENABLE, D3DZB_FALSE);
    device->SetRenderState(D3DRS_LIGHTING, FALSE);
    device->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
    device->SetTexture(0, nullptr);
    device->SetFVF(FVF);
    device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_SELECTARG1);
    device->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_DIFFUSE);
    device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1);
    device->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_DIFFUSE);

    const float hx = (float)x - 0.5f;
    const float hy = (float)y - 0.5f;
    Vertex verts[4] = {
        {hx,            hy,            0.0f, 1.0f, color, 0.0f, 0.0f},
        {hx + w,        hy,            0.0f, 1.0f, color, 1.0f, 0.0f},
        {hx,            hy + h,        0.0f, 1.0f, color, 0.0f, 1.0f},
        {hx + w,        hy + h,        0.0f, 1.0f, color, 1.0f, 1.0f},
    };
    device->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP, 2, verts, sizeof(Vertex));
}

// ---------------------------------------------------------------------
// Watermark
// ---------------------------------------------------------------------

static IDirect3DTexture9* g_watermarkTex = nullptr;
static int g_watermarkW = 0, g_watermarkH = 0;

static void DrawWatermark(IDirect3DDevice9* device) {
    if (!g_watermarkTex) {
        std::wstring wtext(WATERMARK_TEXT, WATERMARK_TEXT + strlen(WATERMARK_TEXT));
        g_watermarkTex = CreateTextTexture(device, wtext.c_str(), 64, FW_HEAVY, true, &g_watermarkW, &g_watermarkH);
    }
    if (!g_watermarkTex) return;

    IDirect3DSurface9* backbuffer = nullptr;
    if (FAILED(device->GetBackBuffer(0, 0, D3DBACKBUFFER_TYPE_MONO, &backbuffer)) || !backbuffer) {
        return;
    }
    D3DSURFACE_DESC desc;
    backbuffer->GetDesc(&desc);
    backbuffer->Release();

    int x = ((int)desc.Width - g_watermarkW) / 2;
    int y = (int)desc.Height - g_watermarkH - 50;

    IDirect3DStateBlock9* stateBlock = nullptr;
    device->CreateStateBlock(D3DSBT_ALL, &stateBlock);
    DrawTexturedQuad(device, g_watermarkTex, x, y, g_watermarkW, g_watermarkH, true);
    if (stateBlock) {
        stateBlock->Apply();
        stateBlock->Release();
    }
}

// ---------------------------------------------------------------------
// Shared memory with the Python controller (see overlay_state.h)
// ---------------------------------------------------------------------

static HANDLE g_shm = nullptr;
static PanelState* g_state = nullptr;

static void InitSharedMemory() {
    g_shm = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(PanelState), PANEL_SHM_NAME);
    if (g_shm) {
        g_state = (PanelState*)MapViewOfFile(g_shm, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(PanelState));
    }
}

static void PushPanelState() {
    if (g_state) {
        g_state->generation++;
    }
}

// ---------------------------------------------------------------------
// Panel UI state and layout
// ---------------------------------------------------------------------

static const char* VARIANT_NAMES[VARIANT_COUNT] = {"Any% Shop", "No TP Any% Shop"};
static const char* VARIANT_DEFAULT_ITEMS[VARIANT_COUNT][ITEMS_PER_VARIANT] = {
    {"jetpack", "teleporter", "compass", "bomb_box"},
    {"jetpack", "bomb_box", "mattock", "compass"},
};
static const char* CAPE_TOGGLE_PARTNER(const char* name) {
    if (strcmp(name, "jetpack") == 0) return "cape";
    if (strcmp(name, "cape") == 0) return "jetpack";
    if (strcmp(name, "vlads_cape") == 0) return "jetpack"; // 2-click resolution undoes the 10-click easter egg
    return nullptr;
}

static int g_variantIdx = 0;
static char g_orders[VARIANT_COUNT][ITEMS_PER_VARIANT][ITEM_NAME_LEN];

static void InitPanelDefaults() {
    for (int v = 0; v < VARIANT_COUNT; v++) {
        for (int i = 0; i < ITEMS_PER_VARIANT; i++) {
            strcpy_s(g_orders[v][i], VARIANT_DEFAULT_ITEMS[v][i]);
        }
    }
}

static void PublishPanelState() {
    if (!g_state) return;
    strcpy_s(g_state->variant_name, VARIANT_NAMES[g_variantIdx]);
    for (int i = 0; i < ITEMS_PER_VARIANT; i++) {
        strcpy_s(g_state->item_ids[i], g_orders[g_variantIdx][i]);
    }
    PushPanelState();
}

// Layout (screen pixels, backbuffer space). No background box and no
// title row anymore - this is meant to read as part of the game's own
// HUD (health/bombs/ropes), not a separate floating panel, so it sits
// directly below those (measured off a live capture: they bottom out
// around y=165) at a similarly compact scale, with nothing boxing it
// in or labeling it as ours.
// PANEL_X aligned to the HUD's own heart icon - measured directly off
// a live capture (its red pixels start at x~202; the icon's own
// outline pushes its true left edge a few px earlier).
static const int PANEL_PAD = 10;
static const int ARROW_W = 34;
static const int ICON_W = 90, ICON_H = 78;
static const int SPRITE_MAX = 54;
static const int PANEL_W = PANEL_PAD * 2 + ARROW_W * 2 + ICON_W * ITEMS_PER_VARIANT;
static const int PANEL_H = ICON_H;
// Centered under the HUD's health/bomb/rope row. The earlier 330
// estimate was based on a capture where the rope counter was cut off
// at the crop edge (so its true right edge, and the row's true center,
// were both underestimated) - shifted right to compensate.
static const int HUD_ROW_CENTER_X = 400;
static const int PANEL_X = HUD_ROW_CENTER_X - PANEL_W / 2, PANEL_Y = 175;
static const int ROW_Y = PANEL_Y;
static const int ROW_X = PANEL_X + PANEL_PAD + ARROW_W;

static RECT LeftArrowRect() {
    RECT r = {PANEL_X + PANEL_PAD, ROW_Y, PANEL_X + PANEL_PAD + ARROW_W, ROW_Y + ICON_H};
    return r;
}
static RECT RightArrowRect() {
    int x0 = ROW_X + ICON_W * ITEMS_PER_VARIANT;
    RECT r = {x0, ROW_Y, x0 + ARROW_W, ROW_Y + ICON_H};
    return r;
}
static RECT SlotRect(int slot) {
    int x0 = ROW_X + slot * ICON_W;
    RECT r = {x0, ROW_Y, x0 + ICON_W, ROW_Y + ICON_H};
    return r;
}
static bool PtInRect(const RECT& r, int x, int y) {
    return x >= r.left && x < r.right && y >= r.top && y < r.bottom;
}

// ---------------------------------------------------------------------
// Sprite loading (GDI+ decodes the PNGs; assets_dir comes from Python
// via shared memory, since that's where the already-extracted sprite
// files live - see shop_forcer.py's ASSETS_DIR).
// ---------------------------------------------------------------------

struct Sprite {
    IDirect3DTexture9* tex = nullptr;
    int w = 0, h = 0;
};
static Sprite g_sprites[ITEM_COUNT];
static bool g_gdiplusStarted = false;
static ULONG_PTR g_gdiplusToken = 0;

static int ItemIndex(const char* name) {
    for (int i = 0; i < ITEM_COUNT; i++) {
        if (strcmp(name, ITEM_NAMES[i]) == 0) return i;
    }
    return -1;
}

// UI sounds - the real game's own menu-navigation clips (extracted from
// its allsounds.wad, same WAD-as-concatenated-files trick as the sprite
// extraction), played fire-and-forget via the plain Win32 PlaySound API
// (SND_ASYNC - doesn't block the render thread) rather than pulling in
// a real audio engine for two short one-shot clips.
static void PlayUiSound(const wchar_t* filenameNoExt) {
    if (!g_state) return;
    wchar_t wdir[MAX_PATH] = {0};
    MultiByteToWideChar(CP_ACP, 0, g_state->assets_dir, -1, wdir, MAX_PATH);
    wchar_t wpath[MAX_PATH];
    swprintf_s(wpath, L"%s\\%s.wav", wdir, filenameNoExt);
    PlaySoundW(wpath, NULL, SND_FILENAME | SND_ASYNC | SND_NODEFAULT);
}
static void PlayConfirmSound() { PlayUiSound(L"sfx_confirm"); }
static void PlaySecretSound() { PlayUiSound(L"sfx_secret"); } // the game's own "secret found" jingle
static void PlayToggleSound() { PlayUiSound(L"sfx_toggle"); } // the pause menu's "return to main menu" click

static IDirect3DTexture9* LoadPngTexture(IDirect3DDevice9* device, const wchar_t* filenameNoExt, int* outW, int* outH) {
    if (!g_state) return nullptr;
    if (!g_gdiplusStarted) {
        Gdiplus::GdiplusStartupInput input;
        Gdiplus::GdiplusStartup(&g_gdiplusToken, &input, nullptr);
        g_gdiplusStarted = true;
    }

    wchar_t wdir[MAX_PATH] = {0};
    MultiByteToWideChar(CP_ACP, 0, g_state->assets_dir, -1, wdir, MAX_PATH);
    wchar_t wpath[MAX_PATH];
    swprintf_s(wpath, L"%s\\%s.png", wdir, filenameNoExt);

    Gdiplus::Bitmap bmp(wpath);
    if (bmp.GetLastStatus() != Gdiplus::Ok) {
        return nullptr;
    }
    int w = (int)bmp.GetWidth();
    int h = (int)bmp.GetHeight();
    if (w <= 0 || h <= 0) return nullptr;

    Gdiplus::BitmapData bmpData;
    Gdiplus::Rect rect(0, 0, w, h);
    if (bmp.LockBits(&rect, Gdiplus::ImageLockModeRead, PixelFormat32bppARGB, &bmpData) != Gdiplus::Ok) {
        return nullptr;
    }

    IDirect3DTexture9* tex = nullptr;
    HRESULT hr = device->CreateTexture(w, h, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED, &tex, nullptr);
    if (SUCCEEDED(hr) && tex) {
        D3DLOCKED_RECT locked;
        tex->LockRect(0, &locked, nullptr, 0);
        for (int y = 0; y < h; y++) {
            memcpy((uint8_t*)locked.pBits + (size_t)y * locked.Pitch,
                   (uint8_t*)bmpData.Scan0 + (size_t)y * bmpData.Stride, (size_t)w * 4);
        }
        tex->UnlockRect(0);
    }
    bmp.UnlockBits(&bmpData);

    *outW = w;
    *outH = h;
    return tex;
}

static void LoadSprite(IDirect3DDevice9* device, int itemIdx) {
    if (g_sprites[itemIdx].tex) return;
    wchar_t wname[64];
    MultiByteToWideChar(CP_ACP, 0, ITEM_NAMES[itemIdx], -1, wname, 64);
    g_sprites[itemIdx].tex = LoadPngTexture(device, wname, &g_sprites[itemIdx].w, &g_sprites[itemIdx].h);
}

// The OS-level cursor does not render at all in this game's
// exclusive-mode rendering (confirmed via GetCursorInfo showing no
// active cursor handle, and SetCursor/ShowCursor having no visible
// effect however applied), so a plain generic pointer has to be our own
// draw call too - this traces the classic Windows arrow cursor's
// silhouette (hotspot at the tip, vertex 0) as a filled fan, in white
// with a black outline (a slightly larger black copy drawn first).
static const POINT ARROW_SHAPE[] = {
    {0, 0}, {0, 16}, {4, 12}, {7, 19}, {9, 18}, {6, 11}, {12, 11},
};
static const int ARROW_SHAPE_COUNT = sizeof(ARROW_SHAPE) / sizeof(ARROW_SHAPE[0]);

static void DrawArrowFan(IDirect3DDevice9* device, int x, int y, float scale, DWORD color) {
    Vertex verts[ARROW_SHAPE_COUNT];
    for (int i = 0; i < ARROW_SHAPE_COUNT; i++) {
        verts[i] = {(float)x + ARROW_SHAPE[i].x * scale - 0.5f,
                    (float)y + ARROW_SHAPE[i].y * scale - 0.5f,
                    0.0f, 1.0f, color, 0.0f, 0.0f};
    }
    device->SetTexture(0, nullptr);
    device->SetFVF(FVF);
    device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_SELECTARG1);
    device->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_DIFFUSE);
    device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1);
    device->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_DIFFUSE);
    device->DrawPrimitiveUP(D3DPT_TRIANGLEFAN, ARROW_SHAPE_COUNT - 2, verts, sizeof(Vertex));
}

static void DrawCursorArrow(IDirect3DDevice9* device, int x, int y) {
    device->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE);
    device->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
    device->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
    device->SetRenderState(D3DRS_ZENABLE, D3DZB_FALSE);
    device->SetRenderState(D3DRS_LIGHTING, FALSE);
    device->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);

    const float scale = 1.6f;
    DrawArrowFan(device, x, y, scale * 1.2f, D3DCOLOR_ARGB(255, 0, 0, 0));
    DrawArrowFan(device, x, y, scale, D3DCOLOR_ARGB(255, 255, 255, 255));
}

// Full filled triangles (not text glyphs) for the variant-switch
// arrows - drawn as flat-colored geometry, same technique as the
// cursor arrow's fan (DrawArrowFan) above, just 3 points instead of a
// fan since a single solid triangle needs nothing more.
static const int ARROW_TRI_W = 18, ARROW_TRI_H = 25;

static void DrawTriangleArrow(IDirect3DDevice9* device, int x, int y, int w, int h, bool pointLeft, DWORD color) {
    float x0 = (float)x - 0.5f, y0 = (float)y - 0.5f;
    Vertex verts[3];
    if (pointLeft) {
        verts[0] = {x0 + w, y0,        0.0f, 1.0f, color, 0.0f, 0.0f};
        verts[1] = {x0,     y0 + h / 2.0f, 0.0f, 1.0f, color, 0.0f, 0.0f};
        verts[2] = {x0 + w, y0 + h,    0.0f, 1.0f, color, 0.0f, 0.0f};
    } else {
        verts[0] = {x0,     y0,        0.0f, 1.0f, color, 0.0f, 0.0f};
        verts[1] = {x0 + w, y0 + h / 2.0f, 0.0f, 1.0f, color, 0.0f, 0.0f};
        verts[2] = {x0,     y0 + h,    0.0f, 1.0f, color, 0.0f, 0.0f};
    }
    device->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE);
    device->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
    device->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
    device->SetRenderState(D3DRS_ZENABLE, D3DZB_FALSE);
    device->SetRenderState(D3DRS_LIGHTING, FALSE);
    device->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
    device->SetTexture(0, nullptr);
    device->SetFVF(FVF);
    device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_SELECTARG1);
    device->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_DIFFUSE);
    device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1);
    device->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_DIFFUSE);
    device->DrawPrimitiveUP(D3DPT_TRIANGLELIST, 1, verts, sizeof(Vertex));
}

// ---------------------------------------------------------------------
// Mouse interaction (driven from HookedWndProc, see below - runs on the
// game's own thread, same one that renders, so no synchronization is
// needed with the draw routine below).
// ---------------------------------------------------------------------

struct DragState {
    bool active = false;
    int slot = -1;
    int grabDX = 0; // mouse_x - slot's left edge at press time
};
static DragState g_drag;
static int g_hoverSlot = -1;
static int g_hoverArrow = -1; // -1 none, 0 left, 1 right
static POINT g_mouse = {-1, -1};
static DWORD g_lastClickTime = 0;
static POINT g_lastClickPos = {-10000, -10000};

// Rapid-click tracking for the slot's item: 2 clicks toggles
// jetpack<->cape, 10 toggles it to Vlad's Cape instead. Counts every
// click landing on the same slot within GetDoubleClickTime() of the
// previous one, but doesn't act on any of them as they happen - acting
// per-click meant every pair within a longer run (clicks 2&3, 4&5...)
// re-toggled it right back, so a 10-click run just flickered between
// jetpack and cape instead of ever reaching Vlad's Cape. Resolved once
// instead, based on the final count, the moment clicking actually
// stops - see ResolveRapidClickIfQuiet(), polled once per rendered
// frame from DrawPanel since a quiet mouse produces no further
// messages at all to react to.
static int g_rapidClickSlot = -1;
static int g_rapidClickCount = 0;
static bool g_rapidClickPending = false;
static const int VLADS_CAPE_CLICK_THRESHOLD = 10;

static void SwitchVariant(int direction) {
    g_variantIdx = (g_variantIdx + direction + VARIANT_COUNT) % VARIANT_COUNT;
    PublishPanelState();
    PlayConfirmSound();
}

static void ToggleCape(int slot) {
    const char* partner = CAPE_TOGGLE_PARTNER(g_orders[g_variantIdx][slot]);
    if (!partner) return;
    strcpy_s(g_orders[g_variantIdx][slot], partner);
    PublishPanelState();
    PlayToggleSound();
}

static void ResolveRapidClickIfQuiet() {
    if (!g_rapidClickPending) return;
    if ((GetTickCount() - g_lastClickTime) < GetDoubleClickTime()) return; // still clicking
    g_rapidClickPending = false;
    int slot = g_rapidClickSlot;
    int count = g_rapidClickCount;
    g_rapidClickCount = 0;
    if (slot < 0 || slot >= ITEMS_PER_VARIANT) return;
    if (count >= VLADS_CAPE_CLICK_THRESHOLD) {
        const char* cur = g_orders[g_variantIdx][slot];
        if (strcmp(cur, "jetpack") == 0 || strcmp(cur, "cape") == 0) {
            strcpy_s(g_orders[g_variantIdx][slot], "vlads_cape");
            PublishPanelState();
            PlaySecretSound();
        }
    } else if (count >= 2) {
        ToggleCape(slot);
    }
}

static void OnMouseDown(int x, int y) {
    RECT leftArrow = LeftArrowRect();
    RECT rightArrow = RightArrowRect();
    if (PtInRect(leftArrow, x, y)) {
        SwitchVariant(-1);
        return;
    }
    if (PtInRect(rightArrow, x, y)) {
        SwitchVariant(1);
        return;
    }

    for (int slot = 0; slot < ITEMS_PER_VARIANT; slot++) {
        RECT r = SlotRect(slot);
        if (PtInRect(r, x, y)) {
            DWORD now = GetTickCount();
            bool withinRapidWindow = (now - g_lastClickTime) < GetDoubleClickTime();
            g_lastClickTime = now;
            g_lastClickPos = {x, y};

            // No pixel-proximity requirement (unlike a strict double-
            // click check) - repeatedly clicking the same icon can
            // drift a few pixels without it feeling like a different
            // click. The actual toggle/Vlad's-Cape decision happens
            // later, once clicking stops - see ResolveRapidClickIfQuiet.
            if (withinRapidWindow && g_rapidClickSlot == slot) {
                g_rapidClickCount++;
            } else {
                g_rapidClickCount = 1;
                g_rapidClickSlot = slot;
            }
            g_rapidClickPending = true;

            if (g_rapidClickCount >= 2) {
                return; // mid rapid-click run - don't also start a drag
            }
            g_drag.active = true;
            g_drag.slot = slot;
            g_drag.grabDX = x - r.left;
            return;
        }
    }
}

static void OnMouseMove(int x, int y) {
    g_mouse = {x, y};
    g_hoverSlot = -1;
    for (int slot = 0; slot < ITEMS_PER_VARIANT; slot++) {
        if (PtInRect(SlotRect(slot), x, y)) {
            g_hoverSlot = slot;
            break;
        }
    }
    g_hoverArrow = -1;
    if (PtInRect(LeftArrowRect(), x, y)) g_hoverArrow = 0;
    else if (PtInRect(RightArrowRect(), x, y)) g_hoverArrow = 1;

    if (!g_drag.active) return;
    int dragLeft = x - g_drag.grabDX;
    int dragCenter = dragLeft + ICON_W / 2;
    int targetVisual = (dragCenter - ROW_X) / ICON_W;
    if (targetVisual < 0) targetVisual = 0;
    if (targetVisual >= ITEMS_PER_VARIANT) targetVisual = ITEMS_PER_VARIANT - 1;
    if (targetVisual != g_drag.slot) {
        char tmp[ITEM_NAME_LEN];
        strcpy_s(tmp, g_orders[g_variantIdx][g_drag.slot]);
        if (targetVisual > g_drag.slot) {
            for (int i = g_drag.slot; i < targetVisual; i++) {
                strcpy_s(g_orders[g_variantIdx][i], g_orders[g_variantIdx][i + 1]);
            }
        } else {
            for (int i = g_drag.slot; i > targetVisual; i--) {
                strcpy_s(g_orders[g_variantIdx][i], g_orders[g_variantIdx][i - 1]);
            }
        }
        strcpy_s(g_orders[g_variantIdx][targetVisual], tmp);
        g_drag.slot = targetVisual;
    }
}

static void OnMouseUp(int x, int y) {
    if (g_drag.active) {
        g_drag.active = false;
        g_drag.slot = -1;
        PublishPanelState();
    }
}

// ---------------------------------------------------------------------
// Panel rendering
// ---------------------------------------------------------------------

static void DrawPanel(IDirect3DDevice9* device) {
    ResolveRapidClickIfQuiet(); // polled every frame - see its own comment for why
    for (int i = 0; i < ITEMS_PER_VARIANT; i++) {
        int idx = ItemIndex(g_orders[g_variantIdx][i]);
        if (idx >= 0) {
            LoadSprite(device, idx);
        }
    }

    IDirect3DStateBlock9* stateBlock = nullptr;
    device->CreateStateBlock(D3DSBT_ALL, &stateBlock);

    // Hover glow for the arrows: a larger, tinted copy of the same
    // triangle drawn underneath the normal one.
    const float GLOW_SCALE = 1.3f;
    const DWORD ARROW_COLOR = D3DCOLOR_ARGB(255, 255, 255, 255);
    const DWORD ARROW_GLOW_TINT = D3DCOLOR_ARGB(160, 255, 200, 60);

    RECT leftArrow = LeftArrowRect();
    RECT rightArrow = RightArrowRect();
    {
        int ax = leftArrow.left + (ARROW_W - ARROW_TRI_W) / 2;
        int ay = leftArrow.top + (ICON_H - ARROW_TRI_H) / 2;
        if (g_hoverArrow == 0) {
            int gw = (int)(ARROW_TRI_W * GLOW_SCALE), gh = (int)(ARROW_TRI_H * GLOW_SCALE);
            DrawTriangleArrow(device, ax - (gw - ARROW_TRI_W) / 2, ay - (gh - ARROW_TRI_H) / 2,
                               gw, gh, true, ARROW_GLOW_TINT);
        }
        DrawTriangleArrow(device, ax, ay, ARROW_TRI_W, ARROW_TRI_H, true, ARROW_COLOR);
    }
    {
        int ax = rightArrow.left + (ARROW_W - ARROW_TRI_W) / 2;
        int ay = rightArrow.top + (ICON_H - ARROW_TRI_H) / 2;
        if (g_hoverArrow == 1) {
            int gw = (int)(ARROW_TRI_W * GLOW_SCALE), gh = (int)(ARROW_TRI_H * GLOW_SCALE);
            DrawTriangleArrow(device, ax - (gw - ARROW_TRI_W) / 2, ay - (gh - ARROW_TRI_H) / 2,
                               gw, gh, false, ARROW_GLOW_TINT);
        }
        DrawTriangleArrow(device, ax, ay, ARROW_TRI_W, ARROW_TRI_H, false, ARROW_COLOR);
    }

    for (int visual = 0; visual < ITEMS_PER_VARIANT; visual++) {
        if (g_drag.active && visual == g_drag.slot) continue; // drawn last, on top, following the mouse
        RECT r = SlotRect(visual);
        int idx = ItemIndex(g_orders[g_variantIdx][visual]);
        if (idx < 0) continue;
        bool hovered = (visual == g_hoverSlot) && !g_drag.active;
        Sprite& spr = g_sprites[idx];
        if (spr.tex) {
            float scale = min(1.0f, (float)SPRITE_MAX / max(spr.w, spr.h));
            int sw = (int)(spr.w * scale), sh = (int)(spr.h * scale);
            int sx = r.left + (ICON_W - sw) / 2;
            int sy = r.top + (ICON_H - sh) / 2;
            // sprites are straight (non-premultiplied) alpha from GDI+
            device->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
            if (hovered) {
                DrawTextureOutline(device, spr.tex, sx, sy, sw, sh, 4, 0xFFFFFFFF, false);
            }
            DrawTexturedQuad(device, spr.tex, sx, sy, sw, sh, false);
        }
    }

    if (g_drag.active) {
        int visual = g_drag.slot;
        RECT r = SlotRect(visual);
        int idx = ItemIndex(g_orders[g_variantIdx][visual]);
        int dragLeft = g_mouse.x - g_drag.grabDX;
        if (idx >= 0) {
            Sprite& spr = g_sprites[idx];
            if (spr.tex) {
                float scale = min(1.0f, (float)SPRITE_MAX / max(spr.w, spr.h));
                int sw = (int)(spr.w * scale), sh = (int)(spr.h * scale);
                int sx = dragLeft + (ICON_W - sw) / 2;
                int sy = r.top + (ICON_H - sh) / 2;
                device->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
                DrawTexturedQuad(device, spr.tex, sx, sy, sw, sh, false);
            }
        }
    }

    if (stateBlock) {
        stateBlock->Apply();
        stateBlock->Release();
    }

    // The game draws its own cursor earlier in the same frame (before
    // EndScene, where we hook), so our panel draws over it, and the OS
    // cursor doesn't render at all here (see note above) - draw a plain
    // arrow ourselves, as the very last thing, only while it's over the
    // panel so normal gameplay elsewhere is unaffected.
    RECT panelRect = {PANEL_X, PANEL_Y, PANEL_X + PANEL_W, PANEL_Y + PANEL_H};
    if (PtInRect(panelRect, g_mouse.x, g_mouse.y)) {
        DrawCursorArrow(device, g_mouse.x, g_mouse.y);
    }
}

// ---------------------------------------------------------------------
// D3D9 device hook
// ---------------------------------------------------------------------

// Confirmed via crash dump analysis (cdb on the resulting minidump):
// the game crashed trying to EXECUTE a non-executable (and once, flat
// null) address that was our own saved oEndScene pointer - i.e. we
// grabbed vtable[42] at a moment the device's vtable slot didn't hold a
// real function pointer yet (device creation/recreation is presumably
// multi-step - the global device pointer can go non-null before its
// vtable is fully populated), then later called through that garbage.
// This checks a candidate pointer actually lands on committed,
// executable memory before it's trusted, used in two places: before
// InstallHook() saves it as oEndScene (skips re-hooking this attempt
// if it fails, retried on the next WndProc message, which is always
// moments away), and again right before HookedEndScene calls through
// oEndScene (a last-resort guard - if oEndScene is somehow still bad
// despite that, skip the call for this one frame rather than crash).
static bool LooksLikeCode(void* addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!addr || !VirtualQuery(addr, &mbi, sizeof(mbi))) {
        return false;
    }
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    const DWORD execMask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & execMask) != 0;
}

static HRESULT STDMETHODCALLTYPE HookedEndScene(IDirect3DDevice9* device) {
    DrawWatermark(device);
    DrawPanel(device);
    if (!LooksLikeCode((void*)oEndScene)) {
        return D3D_OK; // shouldn't happen, but never call through a pointer we can't verify
    }
    return oEndScene(device);
}

static void InstallHook() {
    uintptr_t moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    auto devicePtrAddr = reinterpret_cast<IDirect3DDevice9**>(moduleBase + DEVICE_PTR_OFFSET);

    IDirect3DDevice9* dev = *devicePtrAddr;
    if (!dev) {
        return; // no device yet
    }

    void** vtable = *reinterpret_cast<void***>(dev);
    if (vtable[42] == (void*)HookedEndScene) {
        return; // this exact vtable slot already points at us - nothing to do.
        // Checking the slot itself (not a cached device/vtable pointer)
        // matters because a destroyed device's memory can be reused by
        // a freshly-allocated new one at the SAME address, which would
        // fool an "already hooked" check based on a remembered pointer
        // value into skipping a device that's actually new/unhooked.
    }
    if (!LooksLikeCode(vtable[42])) {
        return; // vtable not fully populated yet - try again next message
    }

    oEndScene = (EndScene_t)vtable[42];
    DWORD oldProtect;
    VirtualProtect(&vtable[42], sizeof(void*), PAGE_READWRITE, &oldProtect);
    vtable[42] = (void*)HookedEndScene;
    VirtualProtect(&vtable[42], sizeof(void*), oldProtect, &oldProtect);

    // Textures belonged to the old device - drop them, don't Release()
    // (the device backing them may already be gone). They're recreated
    // lazily (sprites/labels cached per item, watermark/variant/arrows
    // on next draw).
    g_watermarkTex = nullptr;
    for (int i = 0; i < ITEM_COUNT; i++) {
        g_sprites[i].tex = nullptr;
    }
}

// Root cause of the real crashes found via crash-dump analysis (cdb):
// every time this DLL got FreeLibrary'd (overlay_inject.unload(), used
// both for the normal toggle-off and for swapping DLL builds during
// testing) without this, the game's vtable[42] slot was left pointing
// at HookedEndScene's address - which, the instant the DLL is actually
// unmapped, becomes unmapped memory too. The very next frame the game
// tried to render, it jumped straight into freed memory and crashed
// (confirmed: WER's own crash log named the faulting module
// "shopmod_overlay.dll_unloaded" the whole time - a label that was
// hiding the actual bug in plain sight for a dozen or so test cycles).
// Static helper, not exported directly - see RestoreHook() below
// (after the WndProc section) for the actual exported entry point,
// which also restores the WndProc subclass (a SECOND dangling-pointer
// crash this same unload bug produced, missed the first time around:
// confirmed via a second live crash, this time inside
// user32!_InternalCallWinProc calling through the still-subclassed,
// now-unloaded WndProc).
static void RestoreEndSceneHook() {
    uintptr_t moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    auto devicePtrAddr = reinterpret_cast<IDirect3DDevice9**>(moduleBase + DEVICE_PTR_OFFSET);
    IDirect3DDevice9* dev = *devicePtrAddr;
    if (!dev || !oEndScene) {
        return;
    }
    void** vtable = *reinterpret_cast<void***>(dev);
    if (vtable[42] != (void*)HookedEndScene) {
        return; // not (or no longer) our hook - leave it alone
    }
    DWORD oldProtect;
    VirtualProtect(&vtable[42], sizeof(void*), PAGE_READWRITE, &oldProtect);
    vtable[42] = (void*)oEndScene;
    VirtualProtect(&vtable[42], sizeof(void*), oldProtect, &oldProtect);
}

// ---------------------------------------------------------------------
// WndProc subclass: safe re-hook trigger (see file header) + all panel
// mouse input.
// ---------------------------------------------------------------------

static WNDPROC oWndProc = nullptr;
static HWND g_subclassedHwnd = nullptr;  // remembered so RestoreHook() can re-find it on unload

static LRESULT CALLBACK HookedWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    InstallHook();
    switch (msg) {
        case WM_LBUTTONDOWN:
            OnMouseDown(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            break;
        case WM_MOUSEMOVE:
            OnMouseMove(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            break;
        case WM_LBUTTONUP:
            OnMouseUp(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            break;
    }
    return CallWindowProcA(oWndProc, hwnd, msg, wParam, lParam);
}

static BOOL CALLBACK FindMainWindowProc(HWND hwnd, LPARAM outHwnd) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == GetCurrentProcessId() && IsWindowVisible(hwnd) && GetWindow(hwnd, GW_OWNER) == nullptr) {
        *reinterpret_cast<HWND*>(outHwnd) = hwnd;
        return FALSE; // found it, stop enumerating
    }
    return TRUE;
}

static void InstallWndProcHook() {
    if (oWndProc) {
        return; // already subclassed
    }
    HWND hwnd = nullptr;
    EnumWindows(FindMainWindowProc, reinterpret_cast<LPARAM>(&hwnd));
    if (hwnd) {
        oWndProc = (WNDPROC)SetWindowLongPtrA(hwnd, GWLP_WNDPROC, (LONG_PTR)HookedWndProc);
        g_subclassedHwnd = hwnd;
    }
}

// Exported entry point actually called from overlay_inject.py's
// unload() via CreateRemoteThread, BEFORE FreeLibrary - see
// RestoreEndSceneHook() above for why this exists at all. Restores
// BOTH hooks this DLL ever installs: the D3D EndScene vtable patch and
// this WndProc subclass, so nothing is left pointing into this DLL's
// memory once it's unmapped.
extern "C" __declspec(dllexport) void __cdecl RestoreHook() {
    RestoreEndSceneHook();
    if (oWndProc && g_subclassedHwnd && IsWindow(g_subclassedHwnd)) {
        SetWindowLongPtrA(g_subclassedHwnd, GWLP_WNDPROC, (LONG_PTR)oWndProc);
    }
}

static DWORD WINAPI MainThread(LPVOID) {
    InitSharedMemory();
    InitPanelDefaults();
    if (g_state && g_state->magic != PANEL_MAGIC) {
        g_state->magic = PANEL_MAGIC;
        g_state->generation = 0;
    }
    PublishPanelState();

    // Retry both for a while in case we're injected before the game's
    // device/window exist yet (e.g. right at process start). Once the
    // WndProc subclass is in, THAT becomes responsible for any further
    // re-hooking (see above) - this thread does no more vtable writes
    // of its own after this loop ends.
    for (int i = 0; i < 100 && (!oEndScene || !oWndProc); i++) {
        Sleep(200);
        InstallHook();
        InstallWndProcHook();
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
