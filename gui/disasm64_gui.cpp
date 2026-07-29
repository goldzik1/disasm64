// disasm64 GUI -- a small native Win32 disassembler front-end. Dark theme, live decode
// as you type, syntax colouring, and the encoding-quirk / anti-disassembly annotations.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <richedit.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "disasm64/disasm64.h"
#include "disasm64/analysis.h"
#include "disasm64/loader.h"
using namespace disasm64;

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")

namespace {

enum { ID_HEX = 101, ID_BASE = 102, ID_ATT = 103, ID_FLAGS = 104, ID_SEM = 105, ID_OUT = 106, ID_LOAD = 107 };

HWND g_hex, g_base, g_att, g_flags, g_sem, g_out, g_load;
HFONT g_mono, g_ui;
LoadedImage g_image;          // last loaded file
bool g_fileMode = false;      // disassemble g_image instead of the hex box
const int kMaxInsns = 40000;  // cap the listing so large sections stay responsive

const COLORREF C_BG      = RGB(30, 30, 30);
const COLORREF C_INPUT   = RGB(37, 37, 38);
const COLORREF C_OUTBG   = RGB(24, 24, 24);
const COLORREF C_TEXT    = RGB(212, 212, 212);
const COLORREF C_ADDR    = RGB(128, 128, 132);
const COLORREF C_BYTES   = RGB(96, 110, 130);
const COLORREF C_MNEM    = RGB(86, 156, 214);
const COLORREF C_META    = RGB(120, 160, 120);
const COLORREF C_QUIRK   = RGB(206, 145, 120);
const COLORREF C_ANTI    = RGB(224, 108, 117);
const COLORREF C_BAD     = RGB(150, 150, 150);

std::wstring widen(const std::string& s) { return std::wstring(s.begin(), s.end()); }

std::wstring getText(HWND h) {
    int n = GetWindowTextLengthW(h);
    std::wstring s(n, L'\0');
    if (n) GetWindowTextW(h, &s[0], n + 1);
    return s;
}

// Colour indices into the RTF colour table (see colorTable()).
enum { RC_TEXT = 1, RC_ADDR, RC_BYTES, RC_MNEM, RC_META, RC_QUIRK, RC_ANTI, RC_BAD };

struct Rtf {
    std::string s;
    int cur = -1;
    void run(int color, const std::string& t) {
        if (color != cur) { s += "\\cf" + std::to_string(color) + " "; cur = color; }
        for (char c : t) {
            if (c == '\n') s += "\\par\n";
            else if (c == '\\' || c == '{' || c == '}') { s += '\\'; s += c; }
            else s += c;
        }
    }
};

std::string colorTable() {
    auto e = [](COLORREF c) {
        return "\\red" + std::to_string(GetRValue(c)) + "\\green" + std::to_string(GetGValue(c)) + "\\blue" + std::to_string(GetBValue(c)) + ";";
    };
    return "{\\colortbl;" + e(C_TEXT) + e(C_ADDR) + e(C_BYTES) + e(C_MNEM) + e(C_META) + e(C_QUIRK) + e(C_ANTI) + e(C_BAD) + "}";
}

DWORD CALLBACK rtfStream(DWORD_PTR cookie, LPBYTE buf, LONG cb, LONG* done) {
    auto* p = reinterpret_cast<std::pair<const std::string*, size_t>*>(cookie);
    size_t left = p->first->size() - p->second;
    LONG n = LONG(left < size_t(cb) ? left : size_t(cb));
    memcpy(buf, p->first->data() + p->second, n);
    p->second += n;
    *done = n;
    return 0;
}

void setRtf(HWND h, const std::string& rtf) {
    std::pair<const std::string*, size_t> ctx{&rtf, 0};
    EDITSTREAM es{(DWORD_PTR)&ctx, 0, rtfStream};
    SendMessageW(h, EM_STREAMIN, SF_RTF, (LPARAM)&es);
}

int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

const char* catName(Category c) {
    static const char* n[] = {"unknown", "gpr", "branch", "stack", "string", "flags",
                              "sse", "avx", "avx512", "x87", "system", "nop"};
    return n[int(c)];
}
const char* accName(OperandAccess a) {
    switch (a) { case OperandAccess::Read: return "r"; case OperandAccess::Write: return "w";
                 case OperandAccess::ReadWrite: return "rw"; default: return "-"; }
}

int emitRegion(Rtf& rtf, const uint8_t* code, size_t n, uint64_t base, bool att, bool flags, bool sem, int budget) {
    char line[128];
    size_t pos = 0;
    while (pos < n && budget > 0) {
        DecodeResult r = decode(code + pos, n - pos, base + pos);
        size_t len = r.status == DecodeStatus::Ok ? r.insn.length : 1;
        --budget;

        std::snprintf(line, sizeof line, "%016llx  ", (unsigned long long)(base + pos));
        rtf.run(RC_ADDR, line);

        std::string bytes;
        for (size_t k = 0; k < len && k < 12; ++k) { char b[4]; std::snprintf(b, sizeof b, "%02x ", code[pos + k]); bytes += b; }
        while (bytes.size() < 8 * 3) bytes += ' ';
        rtf.run(RC_BYTES, bytes);

        if (r.status == DecodeStatus::Ok) {
            std::string text = att ? formatAtt(r.insn) : formatIntel(r.insn);
            size_t sp = text.find(' ');
            if (sp == std::string::npos) rtf.run(RC_MNEM, " " + text);
            else { rtf.run(RC_MNEM, " " + text.substr(0, sp)); rtf.run(RC_TEXT, text.substr(sp)); }

            if (flags && (r.insn.flagsWritten || r.insn.flagsRead)) {
                std::snprintf(line, sizeof line, "   [w:%s r:%s]", flagsToString(r.insn.flagsWritten).c_str(), flagsToString(r.insn.flagsRead).c_str());
                rtf.run(RC_META, line);
            }
            if (sem) {
                std::string s = std::string("   [") + catName(r.insn.category);
                for (int k = 0; k < r.insn.operandCount; ++k) { char b[16]; std::snprintf(b, sizeof b, " op%d:%s", k, accName(r.insn.operands[k].access)); s += b; }
                s += "]";
                rtf.run(RC_META, s);
            }
            rtf.run(RC_TEXT, "\n");

            for (const char* q : analyzeEncoding(code + pos, n - pos, base + pos))
                rtf.run(RC_QUIRK, std::string("                    ! ") + q + "\n");
        } else if (r.status == DecodeStatus::Truncated) { rtf.run(RC_BAD, " (truncated)\n"); break; }
        else rtf.run(RC_BAD, " (bad)\n");
        pos += len;
    }
    if (pos < n && budget <= 0) {
        std::snprintf(line, sizeof line, "                    ; ... %llu more bytes not shown\n", (unsigned long long)(n - pos));
        rtf.run(RC_ADDR, line);
    }
    for (const SweepIssue& s : antiDisasmScan(code, n, base)) {
        std::snprintf(line, sizeof line, "%016llx  !! %s\n", (unsigned long long)s.address, s.what);
        rtf.run(RC_ANTI, line);
    }
    return budget;
}

void refresh() {
    bool att   = SendMessageW(g_att, BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool flags = SendMessageW(g_flags, BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool sem   = SendMessageW(g_sem, BM_GETCHECK, 0, 0) == BST_CHECKED;

    Rtf rtf;
    rtf.s = "{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0\\fmodern Consolas;}}" + colorTable() + "\\f0\\fs18 ";
    char line[160];

    if (g_fileMode && !g_image.code.empty()) {
        std::snprintf(line, sizeof line, "; %s  %s  imagebase %llx  entry %llx\n\n",
                      g_image.format.c_str(), g_image.machine.empty() ? "?" : g_image.machine.c_str(),
                      (unsigned long long)g_image.imageBase, (unsigned long long)g_image.entry);
        rtf.run(RC_META, line);
        int budget = kMaxInsns;
        for (const CodeRegion& rg : g_image.code) {
            std::snprintf(line, sizeof line, "; section %-8s  va %llx  size %llx\n",
                          rg.name.c_str(), (unsigned long long)rg.vaddr, (unsigned long long)rg.size);
            rtf.run(RC_META, line);
            budget = emitRegion(rtf, regionData(g_image, rg), rg.size, rg.vaddr, att, flags, sem, budget);
            rtf.run(RC_TEXT, "\n");
            if (budget <= 0) break;
        }
    } else {
        std::wstring hx = getText(g_hex);
        std::vector<uint8_t> code;
        int hi = -1;
        for (wchar_t wc : hx) {
            int v = hexv((int)wc);
            if (v < 0) { hi = -1; continue; }
            if (hi < 0) hi = v; else { code.push_back(uint8_t(hi * 16 + v)); hi = -1; }
        }
        uint64_t base = wcstoull(getText(g_base).c_str(), nullptr, 0);
        emitRegion(rtf, code.data(), code.size(), base, att, flags, sem, kMaxInsns);
    }
    rtf.s += "}";
    setRtf(g_out, rtf.s);
}

void loadPath(HWND hwnd, const wchar_t* path) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER sz; GetFileSizeEx(h, &sz);
    std::vector<uint8_t> data(size_t(sz.QuadPart));
    DWORD got = 0;
    if (!data.empty()) ReadFile(h, data.data(), DWORD(data.size()), &got, nullptr);
    CloseHandle(h);
    data.resize(got);

    g_image = loadImage(std::move(data));
    g_fileMode = true;
    const wchar_t* base = wcsrchr(path, L'\\');
    std::wstring title = std::wstring(L"disasm64  \x2014  ") + (base ? base + 1 : path);
    SetWindowTextW(hwnd, title.c_str());
    refresh();
}

void loadFile(HWND hwnd) {
    wchar_t path[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof ofn;
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"Executables (*.exe;*.dll;*.sys;*.bin)\0*.exe;*.dll;*.sys;*.bin\0All files\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameW(&ofn)) loadPath(hwnd, path);
}

HWND mk(const wchar_t* cls, const wchar_t* text, DWORD style, HWND parent, int id, HFONT font) {
    HWND h = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0,
                             parent, (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
    SendMessageW(h, WM_SETFONT, (WPARAM)font, TRUE);
    return h;
}

void layout(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom, pad = 10;
    int inH = 84, ctlY = pad + inH + 8, ctlH = 24;
    MoveWindow(g_hex, pad, pad, W - 2 * pad, inH, TRUE);
    int x = pad;
    MoveWindow(GetDlgItem(hwnd, 200), x, ctlY + 4, 42, ctlH, TRUE); x += 46;
    MoveWindow(g_base, x, ctlY, 130, ctlH, TRUE); x += 140;
    MoveWindow(g_att, x, ctlY, 110, ctlH, TRUE); x += 118;
    MoveWindow(g_flags, x, ctlY, 84, ctlH, TRUE); x += 90;
    MoveWindow(g_sem, x, ctlY, 100, ctlH, TRUE); x += 110;
    MoveWindow(g_load, x, ctlY, 104, ctlH, TRUE);
    int outY = ctlY + ctlH + 10;
    MoveWindow(g_out, pad, outY, W - 2 * pad, H - outY - pad, TRUE);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            BOOL dark = TRUE;
            DwmSetWindowAttribute(hwnd, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &dark, sizeof dark);
            g_ui = CreateFontW(-15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
            g_mono = CreateFontW(-16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");

            g_hex = mk(L"EDIT", L"55 48 89 e5 48 83 ec 20 e8 00 00 00 00 c5 f8 58 c1 62 f1 6c 48 58 cb c9 c3",
                       ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL | WS_BORDER, hwnd, ID_HEX, g_mono);
            CreateWindowExW(0, L"STATIC", L"Base:", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, (HMENU)200, GetModuleHandleW(nullptr), nullptr);
            SendMessageW(GetDlgItem(hwnd, 200), WM_SETFONT, (WPARAM)g_ui, TRUE);
            g_base  = mk(L"EDIT", L"0x401000", ES_AUTOHSCROLL | WS_BORDER, hwnd, ID_BASE, g_mono);
            g_att   = mk(L"BUTTON", L"AT&&T syntax", BS_AUTOCHECKBOX, hwnd, ID_ATT, g_ui);
            g_flags = mk(L"BUTTON", L"flags", BS_AUTOCHECKBOX, hwnd, ID_FLAGS, g_ui);
            g_sem   = mk(L"BUTTON", L"semantics", BS_AUTOCHECKBOX, hwnd, ID_SEM, g_ui);
            g_load  = mk(L"BUTTON", L"Load file\x2026", BS_PUSHBUTTON, hwnd, ID_LOAD, g_ui);
            g_out   = mk(MSFTEDIT_CLASS, L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_BORDER, hwnd, ID_OUT, g_mono);
            SendMessageW(g_out, EM_SETBKGNDCOLOR, 0, (LPARAM)C_OUTBG);
            SendMessageW(g_out, EM_EXLIMITTEXT, 0, 64 << 20);
            DragAcceptFiles(hwnd, TRUE);
            layout(hwnd);
            refresh();
            return 0;
        }
        case WM_DROPFILES: {
            wchar_t path[MAX_PATH];
            if (DragQueryFileW((HDROP)wp, 0, path, MAX_PATH)) loadPath(hwnd, path);
            DragFinish((HDROP)wp);
            return 0;
        }
        case WM_SIZE: layout(hwnd); return 0;
        case WM_COMMAND:
            if (LOWORD(wp) == ID_HEX && HIWORD(wp) == EN_CHANGE) { if (GetFocus() == g_hex) { g_fileMode = false; refresh(); } }
            else if (LOWORD(wp) == ID_BASE && HIWORD(wp) == EN_CHANGE) { if (!g_fileMode) refresh(); }
            else if ((LOWORD(wp) == ID_ATT || LOWORD(wp) == ID_FLAGS || LOWORD(wp) == ID_SEM) && HIWORD(wp) == BN_CLICKED) refresh();
            else if (LOWORD(wp) == ID_LOAD && HIWORD(wp) == BN_CLICKED) loadFile(hwnd);
            return 0;
        case WM_CTLCOLOREDIT: {
            HDC dc = (HDC)wp; SetTextColor(dc, C_TEXT); SetBkColor(dc, C_INPUT);
            static HBRUSH br = CreateSolidBrush(C_INPUT); return (LRESULT)br;
        }
        case WM_CTLCOLORSTATIC: {
            HDC dc = (HDC)wp; SetTextColor(dc, C_TEXT); SetBkColor(dc, C_BG);
            static HBRUSH br = CreateSolidBrush(C_BG); return (LRESULT)br;
        }
        case WM_CTLCOLORBTN: {
            HDC dc = (HDC)wp; SetTextColor(dc, C_TEXT); SetBkColor(dc, C_BG);
            static HBRUSH br = CreateSolidBrush(C_BG); return (LRESULT)br;
        }
        case WM_ERASEBKGND: {
            RECT rc; GetClientRect(hwnd, &rc);
            static HBRUSH br = CreateSolidBrush(C_BG);
            FillRect((HDC)wp, &rc, br);
            return 1;
        }
        case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

} // namespace

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR lpCmdLine, int nShow) {
    InitCommonControls();
    LoadLibraryW(L"Msftedit.dll");

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(C_BG);
    wc.lpszClassName = L"disasm64_gui";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"disasm64",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 720,
                                nullptr, nullptr, hInst, nullptr);
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    if (lpCmdLine && *lpCmdLine) {
        std::wstring cl = lpCmdLine;
        if (cl.size() >= 2 && cl.front() == L'"' && cl.back() == L'"') cl = cl.substr(1, cl.size() - 2);
        loadPath(hwnd, cl.c_str());
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
