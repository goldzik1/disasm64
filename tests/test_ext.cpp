#include "check.h"
#include "disasm64/disasm64.h"
#include <string>
using namespace disasm64;

static std::string fmt(std::initializer_list<uint8_t> bytes, uint64_t addr = 0) {
    static uint8_t buf[16];
    size_t n = 0; for (uint8_t b : bytes) buf[n++] = b;
    DecodeResult r = decode(buf, n, addr);
    if (r.status != DecodeStatus::Ok) return "<invalid>";
    return formatIntel(r.insn);
}

// Cases found and pinned by the iced-x86 differential harness (tools/diff_iced.py).
TEST_MAIN({
    // immediate / branch length rules
    CHECK_STR(fmt({0x48, 0x05, 0x11, 0x22, 0x33, 0x44}), "add rax, 0x44332211");
    CHECK_STR(fmt({0x66, 0x48, 0x05, 0x11, 0x22, 0x33, 0x44}), "add rax, 0x44332211");   // REX.W overrides 0x66
    CHECK_STR(fmt({0x66, 0xE8, 0x00, 0x00, 0x00, 0x00}, 0), "call 0x6");                 // near rel is rel32
    CHECK_STR(fmt({0x40, 0x40, 0x11, 0x00}), "adc dword ptr [rax], eax");                // redundant REX chain

    // previously-missing legacy ops
    CHECK_STR(fmt({0xE4, 0x12}), "in al, 0x12");
    CHECK_STR(fmt({0xEC}), "in al, dx");
    CHECK_STR(fmt({0xE2, 0x05}), "loop 0x7");
    CHECK_STR(fmt({0xC8, 0x00, 0x11, 0x22}), "enter 0x1100, 0x22");
    CHECK_STR(fmt({0x0F, 0xB2, 0x00}), "lss eax, dword ptr [rax]");
    CHECK_STR(fmt({0x0F, 0xC3, 0x00}), "movnti dword ptr [rax], eax");

    // system / privileged (RE-relevant)
    CHECK_STR(fmt({0x0F, 0x20, 0xC0}), "mov rax, cr0");
    CHECK_STR(fmt({0x0F, 0x00, 0xC0}), "sldt eax");
    CHECK_STR(fmt({0x0F, 0x01, 0x00}), "sgdt [rax]");
    CHECK_STR(fmt({0x0F, 0x01, 0xF9}), "rdtscp");
    CHECK_STR(fmt({0x0F, 0x01, 0xF8}), "swapgs");
    CHECK_STR(fmt({0x0F, 0xA4, 0xC1, 0x08}), "shld ecx, eax, 0x8");
    CHECK_STR(fmt({0x0F, 0x02, 0xC1}), "lar eax, ecx");
    CHECK_STR(fmt({0x0F, 0xAE, 0x00}), "fxsave [rax]");

    // SSE/SSE2/SSE3 + SHA-NI
    CHECK_STR(fmt({0x66, 0x0F, 0xD6, 0xC1}), "movq xmm1, xmm0");
    CHECK_STR(fmt({0x66, 0x0F, 0x7C, 0xC1}), "haddpd xmm0, xmm1");
    CHECK_STR(fmt({0x0F, 0x38, 0xC8, 0xC1}), "sha1nexte xmm0, xmm1");

    // LOCK legality: memory destination + lockable op only
    CHECK_STR(fmt({0xF0, 0x01, 0x00}), "lock add dword ptr [rax], eax");
    CHECK_STR(fmt({0xF0, 0x01, 0xC3}), "<invalid>");   // lock on register destination
    CHECK_STR(fmt({0xF0, 0x90}), "<invalid>");         // lock on a non-lockable op

    // strictness caught by the harness
    CHECK_STR(fmt({0x0F, 0xAE, 0xC0}), "<invalid>");             // fxsave has no register form
    CHECK_STR(fmt({0xC5, 0x84, 0x28, 0x00}), "<invalid>");       // VEX.vvvv must be 1111 here
})
