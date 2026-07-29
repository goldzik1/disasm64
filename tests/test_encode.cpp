#include "check.h"
#include "disasm64/disasm64.h"
#include <cstdint>
using namespace disasm64;

static bool regEq(const Reg& a, const Reg& b) { return a.cls == b.cls && a.idx == b.idx; }

static bool opEq(const Operand& a, const Operand& b) {
    if (a.kind != b.kind || a.sizeBytes != b.sizeBytes) return false;
    switch (a.kind) {
        case OperandKind::Reg: return regEq(a.reg, b.reg);
        case OperandKind::Imm: {
            uint64_t mask = (a.sizeBytes == 0 || a.sizeBytes >= 8) ? ~0ull : ((1ull << (8 * a.sizeBytes)) - 1);
            return (uint64_t(a.imm) & mask) == (uint64_t(b.imm) & mask);
        }
        case OperandKind::Rel: return a.relTarget == b.relTarget;
        case OperandKind::Mem:
            return regEq(a.mem.base, b.mem.base) && regEq(a.mem.index, b.mem.index) &&
                   a.mem.scale == b.mem.scale && a.mem.disp == b.mem.disp &&
                   a.mem.ripRelative == b.mem.ripRelative && a.mem.segment == b.mem.segment;
        default: return true;
    }
}

static bool structEq(const Instruction& a, const Instruction& b) {
    if (a.mnemonic != b.mnemonic || a.operandCount != b.operandCount) return false;
    if (a.cc != b.cc) return false;
    if (a.prefixes.lock != b.prefixes.lock) return false;   // rep/opsize on non-string GP ops is redundant noise
    for (int i = 0; i < a.operandCount; ++i)
        if (!opEq(a.operands[i], b.operands[i])) return false;
    return true;
}

// decode -> encode -> decode, and require the two decodes to match structurally.
static int roundtrip(std::initializer_list<uint8_t> bytes, uint64_t addr = 0x401000) {
    uint8_t buf[16]; size_t n = 0; for (uint8_t b : bytes) buf[n++] = b;
    DecodeResult r = decode(buf, n, addr);
    if (r.status != DecodeStatus::Ok) return -1;
    uint8_t enc[16];
    EncodeResult e = encode(r.insn, enc, sizeof enc);
    if (e.status != EncodeStatus::Ok) return -2;
    DecodeResult r2 = decode(enc, e.length, addr);
    if (r2.status != DecodeStatus::Ok) return -3;
    return structEq(r.insn, r2.insn) ? 1 : 0;
}

static uint32_t rng(uint32_t& s) { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }

TEST_MAIN({
    // golden GP round-trips
    CHECK_EQ(roundtrip({0x48, 0x89, 0xE5}), 1);                          // mov rbp, rsp
    CHECK_EQ(roundtrip({0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00}), 1);  // mov rax, [rip+0x10]
    CHECK_EQ(roundtrip({0x01, 0xD8}), 1);                                // add eax, ebx
    CHECK_EQ(roundtrip({0x48, 0x01, 0xD8}), 1);                          // add rax, rbx
    CHECK_EQ(roundtrip({0x83, 0xC0, 0x05}), 1);                          // add eax, 5
    CHECK_EQ(roundtrip({0x48, 0x83, 0xEC, 0x20}), 1);                    // sub rsp, 0x20
    CHECK_EQ(roundtrip({0x81, 0xC1, 0x00, 0x01, 0x00, 0x00}), 1);        // add ecx, 0x100
    CHECK_EQ(roundtrip({0xB8, 0x01, 0x00, 0x00, 0x00}), 1);              // mov eax, 1
    CHECK_EQ(roundtrip({0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8}), 1);        // mov rax, imm64
    CHECK_EQ(roundtrip({0xC6, 0x00, 0xFF}), 1);                          // mov byte [rax], 0xff
    CHECK_EQ(roundtrip({0x88, 0xD8}), 1);                                // mov al, bl
    CHECK_EQ(roundtrip({0x8D, 0x04, 0x08}), 1);                          // lea eax, [rax+rcx]
    CHECK_EQ(roundtrip({0x48, 0x8D, 0x44, 0x08, 0x10}), 1);              // lea rax, [rax+rcx+0x10]
    CHECK_EQ(roundtrip({0x50}), 1);                                      // push rax
    CHECK_EQ(roundtrip({0x41, 0x58}), 1);                                // pop r8
    CHECK_EQ(roundtrip({0xFF, 0x30}), 1);                                // push [rax]
    CHECK_EQ(roundtrip({0xFF, 0xD0}), 1);                                // call rax
    CHECK_EQ(roundtrip({0xE8, 0x00, 0x10, 0x00, 0x00}), 1);              // call rel32
    CHECK_EQ(roundtrip({0xE9, 0x05, 0x00, 0x00, 0x00}), 1);             // jmp rel32
    CHECK_EQ(roundtrip({0x0F, 0x84, 0x10, 0x00, 0x00, 0x00}), 1);        // jz rel32
    CHECK_EQ(roundtrip({0xEB, 0x05}), 1);                                // jmp rel8 -> re-encodes to rel32
    CHECK_EQ(roundtrip({0xF7, 0xD8}), 1);                                // neg eax
    CHECK_EQ(roundtrip({0xC1, 0xE0, 0x04}), 1);                          // shl eax, 4
    CHECK_EQ(roundtrip({0xD3, 0xE0}), 1);                                // shl eax, cl
    CHECK_EQ(roundtrip({0x0F, 0xB6, 0xC0}), 1);                          // movzx eax, al
    CHECK_EQ(roundtrip({0x48, 0x0F, 0xBE, 0xC0}), 1);                    // movsx rax, al
    CHECK_EQ(roundtrip({0x0F, 0xAF, 0xC1}), 1);                          // imul eax, ecx
    CHECK_EQ(roundtrip({0x6B, 0xC1, 0x05}), 1);                          // imul eax, ecx, 5
    CHECK_EQ(roundtrip({0x84, 0xC0}), 1);                                // test al, al
    CHECK_EQ(roundtrip({0x0F, 0x94, 0xC0}), 1);                          // setz al
    CHECK_EQ(roundtrip({0x0F, 0x44, 0xC1}), 1);                          // cmovz eax, ecx
    CHECK_EQ(roundtrip({0x87, 0xD8}), 1);                                // xchg eax, ebx
    CHECK_EQ(roundtrip({0xC3}), 1);                                      // ret
    CHECK_EQ(roundtrip({0x90}), 1);                                      // nop
    CHECK_EQ(roundtrip({0x48, 0x63, 0xC1}), 1);                          // movsxd rax, ecx

    // random round-trip sweep: every encodable decode must survive decode->encode->decode
    uint32_t s = 0x1234567u; int checked = 0, bad = 0;
    for (int i = 0; i < 400000; ++i) {
        uint8_t b[15]; for (int k = 0; k < 15; ++k) b[k] = uint8_t(rng(s));
        DecodeResult r = decode(b, 15, 0x401000);
        if (r.status != DecodeStatus::Ok) continue;
        uint8_t enc[16];
        EncodeResult e = encode(r.insn, enc, sizeof enc);
        if (e.status != EncodeStatus::Ok) continue;
        DecodeResult r2 = decode(enc, e.length, 0x401000);
        ++checked;
        if (r2.status != DecodeStatus::Ok || !structEq(r.insn, r2.insn)) {
            ++bad;
            if (bad <= 20) {
                std::printf("MISMATCH in:");
                for (int k = 0; k < r.insn.length; ++k) std::printf(" %02x", b[k]);
                std::printf("  '%s' -> enc", formatIntel(r.insn).c_str());
                for (uint32_t k = 0; k < e.length; ++k) std::printf(" %02x", enc[k]);
                std::printf(" -> '%s'\n", r2.status == DecodeStatus::Ok ? formatIntel(r2.insn).c_str() : "<invalid>");
            }
        }
    }
    CHECK(checked > 1000);
    CHECK_EQ(bad, 0);
})
