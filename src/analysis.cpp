#include "disasm64/analysis.h"
#include "disasm64/disasm64.h"

namespace disasm64 {

std::vector<const char*> analyzeEncoding(const uint8_t* p, size_t n, uint64_t address) {
    std::vector<const char*> out;
    bool seen[256] = {}; int segCount = 0, repCount = 0, rexCount = 0; bool afterRex = false;
    for (size_t i = 0; i < n; ++i) {
        uint8_t b = p[i];
        bool legacy = b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 || b == 0x3E ||
                      b == 0x26 || b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67;
        if (legacy) {
            if (afterRex) out.push_back("prefix after REX (REX ignored)");
            if (seen[b]) out.push_back("duplicate prefix");
            seen[b] = true;
            if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) { if (++segCount == 2) out.push_back("multiple segment overrides"); }
            if (b == 0xF2 || b == 0xF3) { if (++repCount == 2) out.push_back("conflicting rep prefixes"); }
            continue;
        }
        if (b >= 0x40 && b <= 0x4F) { if (rexCount++) out.push_back("multiple REX prefixes"); afterRex = true; continue; }
        break;
    }
    DecodeResult dr = decode(p, n, address);
    if (dr.status == DecodeStatus::Ok) {
        for (int k = 0; k < dr.insn.operandCount; ++k) {
            const Operand& o = dr.insn.operands[k];
            if (o.kind != OperandKind::Mem || o.mem.ripRelative || o.mem.base.cls == RegClass::None) continue;
            if (o.mem.dispSize == 4 && o.mem.disp >= -128 && o.mem.disp <= 127) out.push_back("over-long disp32 (fits in disp8)");
            if (o.mem.dispSize == 1 && o.mem.disp == 0 && o.mem.base.idx != 5 && o.mem.base.idx != 13) out.push_back("redundant disp8 = 0");
        }
    }
    return out;
}

HookPlan planHook(const uint8_t* p, size_t n, uint64_t address, uint64_t newAddress, unsigned minBytes) {
    HookPlan hp;
    size_t pos = 0; unsigned total = 0; bool allReloc = true;
    std::vector<uint8_t> reloc;
    while (total < minBytes) {
        DecodeResult dr = decode(p + pos, n - pos, address + pos);
        if (dr.status != DecodeStatus::Ok || dr.insn.length == 0) return hp;
        std::vector<uint8_t> one;
        if (relocate(p + pos, n - pos, address + pos, newAddress + total, one)) reloc.insert(reloc.end(), one.begin(), one.end());
        else allReloc = false;
        pos += dr.insn.length; total += dr.insn.length;
    }
    hp.ok = true; hp.stolenBytes = uint8_t(total); hp.relocatable = allReloc;
    if (allReloc) hp.relocated = std::move(reloc);
    return hp;
}

std::vector<SweepIssue> antiDisasmScan(const uint8_t* p, size_t n, uint64_t baseAddress) {
    std::vector<SweepIssue> out;
    std::vector<char> boundary(n, 0);
    struct Br { uint64_t at; uint64_t target; };
    std::vector<Br> branches;
    size_t pos = 0;
    while (pos < n) {
        DecodeResult dr = decode(p + pos, n - pos, baseAddress + pos);
        boundary[pos] = 1;
        if (dr.status == DecodeStatus::Ok && dr.insn.length) {
            for (int k = 0; k < dr.insn.operandCount; ++k)
                if (dr.insn.operands[k].kind == OperandKind::Rel) branches.push_back({baseAddress + pos, dr.insn.operands[k].relTarget});
            pos += dr.insn.length;
        } else pos += 1;
    }
    for (const Br& b : branches) {
        if (b.target < baseAddress || b.target >= baseAddress + n) continue;
        size_t off = size_t(b.target - baseAddress);
        if (!boundary[off]) out.push_back({b.at, "branch target inside another instruction (anti-disassembly)"});
    }
    return out;
}

} // namespace disasm64
