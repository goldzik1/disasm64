// disasm64 GUI -- a small native Win32 disassembler front-end. Dark theme, live decode
// as you type, syntax colouring, and the encoding-quirk / anti-disassembly annotations.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <richedit.h>
#include <dwmapi.h>
#include <cstdio>
#include <string>
#include <vector>

#include "disasm64/disasm64.h"
#include "disasm64/analysis.h"
using namespace disasm64;

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dwmapi.lib")

namespace {

enum { ID_HEX = 101, ID_BASE = 102, ID_ATT = 103, ID_FLAGS = 104, ID_SEM = 105, ID_OUT = 106 };

HWND g_hex, g_base, g_att, g_flags, g_sem, g_out;
HFONT g_mono, g_ui;

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

void appendColored(const std::wstring& s, COLORREF c) {
    CHARFORMAT2W cf = {};
    cf.cbSize = sizeof cf;
    cf.dwMask = CFM_COLOR | CFM_FACE | CFM_SIZE;
    cf.crTextColor = c;
    cf.yHeight = 200;
    lstrcpynW(cf.szFaceName, L"Consolas", LF_FACESIZE);
    CHARRANGE cr; cr.cpMin = cr.cpMax = -1;
    SendMessageW(g_out, EM_EXSETSEL, 0, (LPARAM)&cr);
    SendMessageW(g_out, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessageW(g_out, EM_REPLACESEL, FALSE, (LPARAM)s.c_str());
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

void refresh() {
    // parse hex
    std::wstring hx = getText(g_hex);
    std::vector<uint8_t> code;
    int hi = -1;
    for (wchar_t wc : hx) {
        int v = hexv((int)wc);
        if (v < 0) { hi = -1; continue; }
        if (hi < 0) hi = v; else { code.push_back(uint8_t(hi * 16 + v)); hi = -1; }
    }
    uint64_t base = wcstoull(getText(g_base).c_str(), nullptr, 0);
    bool att   = SendMessageW(g_att, BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool flags = SendMessageW(g_flags, BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool sem   = SendMessageW(g_sem, BM_GETCHECK, 0, 0) == BST_CHECKED;

    SetWindowTextW(g_out, L"");
    char line[128];

    size_t pos = 0;
    while (pos < code.size()) {
        DecodeResult r = decode(code.data() + pos, code.size() - pos, base + pos);
        size_t len = r.status == DecodeStatus::Ok ? r.insn.length : 1;

        std::snprintf(line, sizeof line, "%016llx  ", (unsigned long long)(base + pos));
        appendColored(widen(line), C_ADDR);

        std::string bytes;
        for (size_t k = 0; k < len && k < 12; ++k) { char b[4]; std::snprintf(b, sizeof b, "%02x ", code[pos + k]); bytes += b; }
        while (bytes.size() < 8 * 3) bytes += ' ';
        appendColored(widen(bytes), C_BYTES);

        if (r.status == DecodeStatus::Ok) {
            std::string text = att ? formatAtt(r.insn) : formatIntel(r.insn);
            // colour the mnemonic (first token) apart from the operands
            size_t sp = text.find(' ');
            if (sp == std::string::npos) { appendColored(L" " + widen(text), C_MNEM); }
            else { appendColored(L" " + widen(text.substr(0, sp)), C_MNEM); appendColored(widen(text.substr(sp)), C_TEXT); }

            if (flags && (r.insn.flagsWritten || r.insn.flagsRead)) {
                std::snprintf(line, sizeof line, "   [w:%s r:%s]", flagsToString(r.insn.flagsWritten).c_str(), flagsToString(r.insn.flagsRead).c_str());
                appendColored(widen(line), C_META);
            }
            if (sem) {
                std::string s = std::string("   [") + catName(r.insn.category);
                for (int k = 0; k < r.insn.operandCount; ++k) { char b[16]; std::snprintf(b, sizeof b, " op%d:%s", k, accName(r.insn.operands[k].access)); s += b; }
                s += "]";
                appendColored(widen(s), C_META);
            }
            appendColored(L"\n", C_TEXT);

            for (const char* q : analyzeEncoding(code.data() + pos, code.size() - pos, base + pos)) {
                appendColored(L"                    ! ", C_QUIRK);
                appendColored(widen(q) + L"\n", C_QUIRK);
            }
        } else if (r.status == DecodeStatus::Truncated) {
            appendColored(L" (truncated)\n", C_BAD);
            break;
        } else {
            appendColored(L" (bad)\n", C_BAD);
        }
        pos += len;
    }
    for (const SweepIssue& s : antiDisasmScan(code.data(), code.size(), base)) {
        std::snprintf(line, sizeof line, "%016llx  !! %s\n", (unsigned long long)s.address, s.what);
        appendColored(widen(line), C_ANTI);
    }
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
    MoveWindow(g_flags, x, ctlY, 90, ctlH, TRUE); x += 98;
    MoveWindow(g_sem, x, ctlY, 110, ctlH, TRUE);
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
            g_out   = mk(MSFTEDIT_CLASS, L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_BORDER, hwnd, ID_OUT, g_mono);
            SendMessageW(g_out, EM_SETBKGNDCOLOR, 0, (LPARAM)C_OUTBG);
            SendMessageW(g_out, EM_EXLIMITTEXT, 0, 1 << 20);
            layout(hwnd);
            refresh();
            return 0;
        }
        case WM_SIZE: layout(hwnd); return 0;
        case WM_COMMAND:
            if (LOWORD(wp) == ID_HEX && HIWORD(wp) == EN_CHANGE) refresh();
            else if (LOWORD(wp) == ID_BASE && HIWORD(wp) == EN_CHANGE) refresh();
            else if ((LOWORD(wp) == ID_ATT || LOWORD(wp) == ID_FLAGS || LOWORD(wp) == ID_SEM) && HIWORD(wp) == BN_CLICKED) refresh();
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

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
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

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
