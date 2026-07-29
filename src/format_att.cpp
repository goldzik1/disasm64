#include "disasm64/disasm64.h"
#include "fmt.h"
#include <string>
#include <cstdio>

namespace disasm64 {
namespace {

const char* kSegAtt[6] = {"es", "cs", "ss", "ds", "fs", "gs"};

std::string hexA(uint64_t v) { char b[19]; std::snprintf(b, sizeof b, "0x%llx", (unsigned long long)v); return b; }

std::string attOperand(const Operand& o) {
    switch (o.kind) {
        case OperandKind::Reg: return "%" + registerName(o.reg);
        case OperandKind::Imm: {
            uint64_t mask = (o.sizeBytes == 0 || o.sizeBytes >= 8) ? ~0ull : ((1ull << (8 * o.sizeBytes)) - 1);
            return "$" + hexA(uint64_t(o.imm) & mask);
        }
        case OperandKind::Rel: return hexA(o.relTarget);
        case OperandKind::Mem: {
            const MemOperand& m = o.mem;
            std::string s;
            if (m.segment != 0xFF && m.segment < 6) s += std::string("%") + kSegAtt[m.segment] + ":";
            bool paren = m.ripRelative || m.base.cls != RegClass::None || m.index.cls != RegClass::None;
            if (m.disp != 0 || !paren) { if (m.disp < 0) s += "-"; s += hexA(uint64_t(m.disp < 0 ? -m.disp : m.disp)); }
            if (paren) {
                s += "(";
                if (m.ripRelative) s += "%rip";
                else if (m.base.cls != RegClass::None) s += "%" + registerName(m.base);
                if (m.index.cls != RegClass::None) s += ",%" + registerName(m.index) + "," + std::to_string(m.scale);
                s += ")";
            }
            return s;
        }
        default: return "";
    }
}

char sizeSuffix(uint8_t bytes) {
    switch (bytes) { case 1: return 'b'; case 2: return 'w'; case 4: return 'l'; case 8: return 'q'; default: return 0; }
}

} // namespace

std::string formatAtt(const Instruction& insn) {
    std::string s;
    if (insn.prefixes.lock) s += "lock ";
    const Mnemonic m = insn.mnemonic;
    const bool strOp = m == Mnemonic::Movs || m == Mnemonic::Stos || m == Mnemonic::Lods ||
                       m == Mnemonic::Scas || m == Mnemonic::Cmps;
    if (strOp && insn.prefixes.rep == 0xF3) s += "rep ";
    else if (strOp && insn.prefixes.rep == 0xF2) s += "repne ";
    if (insn.prefixes.vex) s += "v";

    std::string base = mnemonicName(insn);
    bool hasMem = false, hasReg = false; uint8_t memWidth = 0;
    for (int i = 0; i < insn.operandCount; ++i) {
        if (insn.operands[i].kind == OperandKind::Mem) { hasMem = true; memWidth = insn.operands[i].sizeBytes; }
        if (insn.operands[i].kind == OperandKind::Reg) hasReg = true;
    }
    if (!insn.rawName && hasMem && !hasReg && memWidth && m != Mnemonic::Lea) { char c = sizeSuffix(memWidth); if (c) base += c; }
    s += base;

    for (int i = insn.operandCount - 1; i >= 0; --i) {
        s += (i == insn.operandCount - 1) ? " " : ", ";
        s += attOperand(insn.operands[i]);
    }
    return s;
}

} // namespace disasm64
