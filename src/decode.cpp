#include "disasm64/disasm64.h"
#include "prefix.h"
#include "operand.h"

namespace disasm64 {
namespace {
using M = Mnemonic;

const M kAlu[8]  = {M::Add, M::Or, M::Adc, M::Sbb, M::And, M::Sub, M::Xor, M::Cmp};
const M kGrp2[8] = {M::Rol, M::Ror, M::Rcl, M::Rcr, M::Shl, M::Shr, M::Shl, M::Sar};
const M kGrp3[8] = {M::Test, M::Test, M::Not, M::Neg, M::Mul, M::Imul, M::Div, M::Idiv};

int SZv(const Prefixes& p) { return p.rexW ? 8 : (p.opsize ? 2 : 4); }
int SZz(const Prefixes& p) { return p.opsize ? 2 : 4; }
int SZd64(const Prefixes& p) { return p.opsize ? 2 : 8; }

int sizeOfClass(RegClass c) {
    switch (c) {
        case RegClass::Gpr8: case RegClass::Gpr8Hi: return 1;
        case RegClass::Gpr16: return 2;
        case RegClass::Gpr32: return 4;
        case RegClass::Gpr64: return 8;
        case RegClass::Xmm: return 16;
        case RegClass::Ymm: return 32;
        default: return 0;
    }
}

Operand regOp(Reg reg) {
    Operand o; o.kind = OperandKind::Reg; o.reg = reg; o.sizeBytes = uint8_t(sizeOfClass(reg.cls)); return o;
}
Operand immOp(Reader& r, int size) {
    Operand o; o.kind = OperandKind::Imm; o.sizeBytes = uint8_t(size); o.imm = r.imm(size); return o;
}
Operand oneOp() { Operand o; o.kind = OperandKind::Imm; o.sizeBytes = 1; o.imm = 1; return o; }
Operand clOp(const Prefixes& p) { return regOp(makeGpr(1, 1, p.rex)); }
Operand relOp(Reader& r, int size) {
    Operand o; o.kind = OperandKind::Rel; o.relSize = uint8_t(size); o.imm = r.imm(size); return o;
}

struct EG { Operand e; Operand g; };
EG decodeEG(Reader& r, const Prefixes& p, int eSize, int gSize) {
    EG x; int reg = decodeModRM(r, p, eSize, x.e);
    x.g.kind = OperandKind::Reg; x.g.sizeBytes = uint8_t(gSize); x.g.reg = makeGpr(reg, gSize, p.rex);
    return x;
}

void addOp(Instruction& insn, const Operand& o) {
    if (insn.operandCount < 4) insn.operands[insn.operandCount++] = o;
}

bool decode0F(Reader& r, Instruction& insn) {
    const Prefixes& p = insn.prefixes;
    uint8_t op = r.u8();
    if (op == 0x05) { insn.mnemonic = M::Syscall; return true; }
    if (op == 0x0B) { insn.mnemonic = M::Ud2; return true; }
    if (op == 0x1E) { if (p.rep == 0xF3) { uint8_t m = r.u8(); if (m == 0xFA) { insn.mnemonic = M::Endbr64; return true; } if (m == 0xFB) { insn.mnemonic = M::Endbr32; return true; } } return false; }
    if (op == 0x1F) { Operand e; decodeModRM(r, p, SZv(p), e); insn.mnemonic = M::Nop; addOp(insn, e); return true; }
    if (op == 0x31) { insn.mnemonic = M::Rdtsc; return true; }
    if (op == 0xA2) { insn.mnemonic = M::Cpuid; return true; }
    if (op == 0xAF) { auto x = decodeEG(r, p, SZv(p), SZv(p)); insn.mnemonic = M::Imul; addOp(insn, x.g); addOp(insn, x.e); return true; }
    if (op >= 0x40 && op <= 0x4F) { auto x = decodeEG(r, p, SZv(p), SZv(p)); insn.mnemonic = M::Cmovcc; insn.cc = op & 0xF; addOp(insn, x.g); addOp(insn, x.e); return true; }
    if (op >= 0x80 && op <= 0x8F) { insn.mnemonic = M::Jcc; insn.cc = op & 0xF; addOp(insn, relOp(r, SZz(p))); return true; }
    if (op >= 0x90 && op <= 0x9F) { Operand e; decodeModRM(r, p, 1, e); insn.mnemonic = M::Setcc; insn.cc = op & 0xF; addOp(insn, e); return true; }
    if (op == 0xB6 || op == 0xB7) { int es = (op == 0xB6) ? 1 : 2; auto x = decodeEG(r, p, es, SZv(p)); insn.mnemonic = M::Movzx; addOp(insn, x.g); addOp(insn, x.e); return true; }
    if (op == 0xBE || op == 0xBF) { int es = (op == 0xBE) ? 1 : 2; auto x = decodeEG(r, p, es, SZv(p)); insn.mnemonic = M::Movsx; addOp(insn, x.g); addOp(insn, x.e); return true; }
    if (op == 0xB0 || op == 0xB1) { int s = op == 0xB0 ? 1 : SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = M::Cmpxchg; addOp(insn, x.e); addOp(insn, x.g); return true; }
    if (op == 0xC0 || op == 0xC1) { int s = op == 0xC0 ? 1 : SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = M::Xadd; addOp(insn, x.e); addOp(insn, x.g); return true; }
    if (op == 0xA3 || op == 0xAB || op == 0xB3 || op == 0xBB) { int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = op == 0xA3 ? M::Bt : op == 0xAB ? M::Bts : op == 0xB3 ? M::Btr : M::Btc; addOp(insn, x.e); addOp(insn, x.g); return true; }
    if (op == 0xBA) { int s = SZv(p); Operand e; int reg = decodeModRM(r, p, s, e); M mm = (reg & 7) == 4 ? M::Bt : (reg & 7) == 5 ? M::Bts : (reg & 7) == 6 ? M::Btr : (reg & 7) == 7 ? M::Btc : M::Invalid; insn.mnemonic = mm; addOp(insn, e); addOp(insn, immOp(r, 1)); return mm != M::Invalid; }
    if (op >= 0xC8 && op <= 0xCF) { insn.mnemonic = M::Bswap; addOp(insn, regOp(makeGpr((op - 0xC8) | (p.rexB ? 8 : 0), SZv(p), p.rex))); return true; }

    // SSE (curated subset). Mandatory prefix selects the variant: none/66/F3/F2.
    const int pp = p.rep == 0xF3 ? 2 : p.rep == 0xF2 ? 3 : p.opsize ? 1 : 0;
    auto xmm = [](int idx) { Operand o; o.kind = OperandKind::Reg; o.reg.cls = RegClass::Xmm; o.reg.idx = uint8_t(idx); o.sizeBytes = 16; return o; };
    auto vecEG = [&](int memSz, bool store) {
        Operand rm; int reg = decodeModRM(r, p, memSz, rm, RegClass::Xmm);
        if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16;
        if (store) { addOp(insn, rm); addOp(insn, xmm(reg)); }
        else { addOp(insn, xmm(reg)); addOp(insn, rm); }
    };
    auto sseArith = [&](M base) { int msz = (pp == 2) ? 4 : (pp == 3) ? 8 : 16; insn.mnemonic = M(int(base) + pp); vecEG(msz, false); };
    switch (op) {
        case 0x58: sseArith(M::Addps); return true;
        case 0x59: sseArith(M::Mulps); return true;
        case 0x5C: sseArith(M::Subps); return true;
        case 0x5E: sseArith(M::Divps); return true;
        case 0x51: sseArith(M::Sqrtps); return true;
        case 0x2E: if (pp >= 2) return false; { int msz = pp == 1 ? 8 : 4; insn.mnemonic = M(int(M::Ucomiss) + pp); vecEG(msz, false); } return true;
        case 0x2F: if (pp >= 2) return false; { int msz = pp == 1 ? 8 : 4; insn.mnemonic = M(int(M::Comiss) + pp); vecEG(msz, false); } return true;
        case 0x10: case 0x11: { int msz = (pp == 2) ? 4 : (pp == 3) ? 8 : 16;
            insn.mnemonic = pp == 0 ? M::Movups : pp == 1 ? M::Movupd : pp == 2 ? M::Movss : M::Movsd;
            vecEG(msz, op == 0x11); return true; }
        case 0x28: case 0x29: { if (pp >= 2) return false; insn.mnemonic = pp == 1 ? M::Movapd : M::Movaps; vecEG(16, op == 0x29); return true; }
        case 0x6F: case 0x7F: { if (pp != 1 && pp != 2) return false; insn.mnemonic = pp == 1 ? M::Movdqa : M::Movdqu; vecEG(16, op == 0x7F); return true; }
        case 0x54: if (pp >= 2) return false; insn.mnemonic = M(int(M::Andps) + pp); vecEG(16, false); return true;
        case 0x55: if (pp >= 2) return false; insn.mnemonic = M(int(M::Andnps) + pp); vecEG(16, false); return true;
        case 0x56: if (pp >= 2) return false; insn.mnemonic = M(int(M::Orps) + pp); vecEG(16, false); return true;
        case 0x57: { if (pp >= 2) return false; insn.mnemonic = pp == 1 ? M::Xorpd : M::Xorps; vecEG(16, false); return true; }
        case 0xDB: if (pp != 1) return false; insn.mnemonic = M::Pand; vecEG(16, false); return true;
        case 0xDF: if (pp != 1) return false; insn.mnemonic = M::Pandn; vecEG(16, false); return true;
        case 0xEB: if (pp != 1) return false; insn.mnemonic = M::Por; vecEG(16, false); return true;
        case 0xEF: { if (pp != 1) return false; insn.mnemonic = M::Pxor; vecEG(16, false); return true; }
        case 0x6E: { if (pp != 1) return false; int gs = p.rexW ? 8 : 4; Operand rm; int reg = decodeModRM(r, p, gs, rm);
            insn.mnemonic = p.rexW ? M::Movq : M::Movd; addOp(insn, xmm(reg)); addOp(insn, rm); return true; }
        case 0x7E: {
            if (pp == 1) { int gs = p.rexW ? 8 : 4; Operand rm; int reg = decodeModRM(r, p, gs, rm);
                insn.mnemonic = p.rexW ? M::Movq : M::Movd; addOp(insn, rm); addOp(insn, xmm(reg)); return true; }
            if (pp == 2) { insn.mnemonic = M::Movq; vecEG(8, false); return true; }
            return false; }
        default: return false;
    }
}

bool decodeOne(Reader& r, Instruction& insn, uint8_t op) {
    const Prefixes& p = insn.prefixes;

    // ALU block 0x00..0x3F, forms 0..5
    if (op < 0x40 && (op & 7) < 6) {
        M m = kAlu[op >> 3];
        switch (op & 7) {
            case 0: { auto x = decodeEG(r, p, 1, 1); insn.mnemonic = m; addOp(insn, x.e); addOp(insn, x.g); return true; }
            case 1: { int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = m; addOp(insn, x.e); addOp(insn, x.g); return true; }
            case 2: { auto x = decodeEG(r, p, 1, 1); insn.mnemonic = m; addOp(insn, x.g); addOp(insn, x.e); return true; }
            case 3: { int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = m; addOp(insn, x.g); addOp(insn, x.e); return true; }
            case 4: { insn.mnemonic = m; addOp(insn, regOp(makeGpr(0, 1, p.rex))); addOp(insn, immOp(r, 1)); return true; }
            case 5: { int s = SZv(p); insn.mnemonic = m; addOp(insn, regOp(makeGpr(0, s, p.rex))); addOp(insn, immOp(r, SZz(p))); return true; }
        }
    }

    switch (op) {
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
            insn.mnemonic = M::Push; addOp(insn, regOp(makeGpr((op - 0x50) | (p.rexB ? 8 : 0), SZd64(p), p.rex))); return true;
        case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            insn.mnemonic = M::Pop; addOp(insn, regOp(makeGpr((op - 0x58) | (p.rexB ? 8 : 0), SZd64(p), p.rex))); return true;
        case 0x63: { auto x = decodeEG(r, p, 4, SZv(p)); insn.mnemonic = M::Movsxd; addOp(insn, x.g); addOp(insn, x.e); return true; }
        case 0x68: insn.mnemonic = M::Push; addOp(insn, immOp(r, SZz(p))); return true;
        case 0x6A: insn.mnemonic = M::Push; addOp(insn, immOp(r, 1)); return true;
        case 0x69: { int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = M::Imul; addOp(insn, x.g); addOp(insn, x.e); addOp(insn, immOp(r, SZz(p))); return true; }
        case 0x6B: { int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = M::Imul; addOp(insn, x.g); addOp(insn, x.e); addOp(insn, immOp(r, 1)); return true; }
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            insn.mnemonic = M::Jcc; insn.cc = op & 0xF; addOp(insn, relOp(r, 1)); return true;
        case 0x80: { Operand e; int reg = decodeModRM(r, p, 1, e); insn.mnemonic = kAlu[reg & 7]; addOp(insn, e); addOp(insn, immOp(r, 1)); return true; }
        case 0x81: { int s = SZv(p); Operand e; int reg = decodeModRM(r, p, s, e); insn.mnemonic = kAlu[reg & 7]; addOp(insn, e); addOp(insn, immOp(r, SZz(p))); return true; }
        case 0x83: { int s = SZv(p); Operand e; int reg = decodeModRM(r, p, s, e); insn.mnemonic = kAlu[reg & 7]; addOp(insn, e); addOp(insn, immOp(r, 1)); return true; }
        case 0x84: { auto x = decodeEG(r, p, 1, 1); insn.mnemonic = M::Test; addOp(insn, x.e); addOp(insn, x.g); return true; }
        case 0x85: { int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = M::Test; addOp(insn, x.e); addOp(insn, x.g); return true; }
        case 0x86: { auto x = decodeEG(r, p, 1, 1); insn.mnemonic = M::Xchg; addOp(insn, x.e); addOp(insn, x.g); return true; }
        case 0x87: { int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = M::Xchg; addOp(insn, x.e); addOp(insn, x.g); return true; }
        case 0x88: { auto x = decodeEG(r, p, 1, 1); insn.mnemonic = M::Mov; addOp(insn, x.e); addOp(insn, x.g); return true; }
        case 0x89: { int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = M::Mov; addOp(insn, x.e); addOp(insn, x.g); return true; }
        case 0x8A: { auto x = decodeEG(r, p, 1, 1); insn.mnemonic = M::Mov; addOp(insn, x.g); addOp(insn, x.e); return true; }
        case 0x8B: { int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = M::Mov; addOp(insn, x.g); addOp(insn, x.e); return true; }
        case 0x8D: { int s = SZv(p); Operand e; int reg = decodeModRM(r, p, s, e); if (e.kind != OperandKind::Mem) return false; e.sizeBytes = 0; insn.mnemonic = M::Lea; addOp(insn, regOp(makeGpr(reg, s, p.rex))); addOp(insn, e); return true; }
        case 0x8F: { uint8_t mb = r.peek(); int reg = (mb >> 3) & 7; Operand e; decodeModRM(r, p, SZd64(p), e); insn.mnemonic = (reg == 0) ? M::Pop : M::Invalid; addOp(insn, e); return true; }
        case 0x90: insn.mnemonic = M::Nop; return true;
        case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97: {
            int s = SZv(p); insn.mnemonic = M::Xchg; addOp(insn, regOp(makeGpr(0, s, p.rex))); addOp(insn, regOp(makeGpr((op - 0x90) | (p.rexB ? 8 : 0), s, p.rex))); return true; }
        case 0x98: insn.mnemonic = p.rexW ? M::Cdqe : M::Cwde; return true;
        case 0x99: insn.mnemonic = p.rexW ? M::Cqo : M::Cdq; return true;
        case 0xA0: case 0xA1: case 0xA2: case 0xA3: {
            int s = (op == 0xA0 || op == 0xA2) ? 1 : SZv(p);
            Operand mo; mo.kind = OperandKind::Mem; mo.sizeBytes = uint8_t(s); mo.mem.dispOffset = uint8_t(r.pos); mo.mem.disp = int64_t(r.u64());
            Operand reg = regOp(makeGpr(0, s, p.rex));
            insn.mnemonic = M::Mov;
            if (op == 0xA0 || op == 0xA1) { addOp(insn, reg); addOp(insn, mo); }
            else { addOp(insn, mo); addOp(insn, reg); }
            return true;
        }
        case 0xA8: insn.mnemonic = M::Test; addOp(insn, regOp(makeGpr(0, 1, p.rex))); addOp(insn, immOp(r, 1)); return true;
        case 0xA9: { int s = SZv(p); insn.mnemonic = M::Test; addOp(insn, regOp(makeGpr(0, s, p.rex))); addOp(insn, immOp(r, SZz(p))); return true; }
        case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            insn.mnemonic = M::Mov; addOp(insn, regOp(makeGpr((op - 0xB0) | (p.rexB ? 8 : 0), 1, p.rex))); addOp(insn, immOp(r, 1)); return true;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
            int s = SZv(p); insn.mnemonic = M::Mov; addOp(insn, regOp(makeGpr((op - 0xB8) | (p.rexB ? 8 : 0), s, p.rex))); addOp(insn, immOp(r, s)); return true; }
        case 0xC0: { Operand e; int reg = decodeModRM(r, p, 1, e); insn.mnemonic = kGrp2[reg & 7]; addOp(insn, e); addOp(insn, immOp(r, 1)); return true; }
        case 0xC1: { int s = SZv(p); Operand e; int reg = decodeModRM(r, p, s, e); insn.mnemonic = kGrp2[reg & 7]; addOp(insn, e); addOp(insn, immOp(r, 1)); return true; }
        case 0xC2: insn.mnemonic = M::Ret; addOp(insn, immOp(r, 2)); return true;
        case 0xC3: insn.mnemonic = M::Ret; return true;
        case 0xC6: { Operand e; int reg = decodeModRM(r, p, 1, e); insn.mnemonic = (reg == 0) ? M::Mov : M::Invalid; addOp(insn, e); addOp(insn, immOp(r, 1)); return true; }
        case 0xC7: { int s = SZv(p); Operand e; int reg = decodeModRM(r, p, s, e); insn.mnemonic = (reg == 0) ? M::Mov : M::Invalid; addOp(insn, e); addOp(insn, immOp(r, SZz(p))); return true; }
        case 0xC9: insn.mnemonic = M::Leave; return true;
        case 0xCC: insn.mnemonic = M::Int3; return true;
        case 0xCD: insn.mnemonic = M::Int; addOp(insn, immOp(r, 1)); return true;
        case 0xD0: { Operand e; int reg = decodeModRM(r, p, 1, e); insn.mnemonic = kGrp2[reg & 7]; addOp(insn, e); addOp(insn, oneOp()); return true; }
        case 0xD1: { int s = SZv(p); Operand e; int reg = decodeModRM(r, p, s, e); insn.mnemonic = kGrp2[reg & 7]; addOp(insn, e); addOp(insn, oneOp()); return true; }
        case 0xD2: { Operand e; int reg = decodeModRM(r, p, 1, e); insn.mnemonic = kGrp2[reg & 7]; addOp(insn, e); addOp(insn, clOp(p)); return true; }
        case 0xD3: { int s = SZv(p); Operand e; int reg = decodeModRM(r, p, s, e); insn.mnemonic = kGrp2[reg & 7]; addOp(insn, e); addOp(insn, clOp(p)); return true; }
        case 0xE8: insn.mnemonic = M::Call; addOp(insn, relOp(r, SZz(p))); return true;
        case 0xE9: insn.mnemonic = M::Jmp; addOp(insn, relOp(r, SZz(p))); return true;
        case 0xEB: insn.mnemonic = M::Jmp; addOp(insn, relOp(r, 1)); return true;
        case 0xF4: insn.mnemonic = M::Hlt; return true;
        case 0xF6: { Operand e; int reg = decodeModRM(r, p, 1, e); insn.mnemonic = kGrp3[reg & 7]; addOp(insn, e); if ((reg & 7) < 2) addOp(insn, immOp(r, 1)); return true; }
        case 0xF7: { int s = SZv(p); Operand e; int reg = decodeModRM(r, p, s, e); insn.mnemonic = kGrp3[reg & 7]; addOp(insn, e); if ((reg & 7) < 2) addOp(insn, immOp(r, SZz(p))); return true; }
        case 0xFE: { Operand e; int reg = decodeModRM(r, p, 1, e); insn.mnemonic = (reg & 7) == 0 ? M::Inc : (reg & 7) == 1 ? M::Dec : M::Invalid; addOp(insn, e); return true; }
        case 0xFF: {
            uint8_t mb = r.peek(); int reg = (mb >> 3) & 7;
            int s = (reg >= 2 && reg <= 6) ? SZd64(p) : SZv(p);
            Operand e; decodeModRM(r, p, s, e);
            switch (reg) {
                case 0: insn.mnemonic = M::Inc; break;
                case 1: insn.mnemonic = M::Dec; break;
                case 2: insn.mnemonic = M::Call; break;
                case 4: insn.mnemonic = M::Jmp; break;
                case 6: insn.mnemonic = M::Push; break;
                default: insn.mnemonic = M::Invalid; break;
            }
            addOp(insn, e); return true;
        }
        case 0x9C: insn.mnemonic = M::Pushf; return true;
        case 0x9D: insn.mnemonic = M::Popf; return true;
        case 0xA4: insn.mnemonic = M::Movs; insn.suffix = 1; return true;
        case 0xA5: insn.mnemonic = M::Movs; insn.suffix = uint8_t(SZv(p)); return true;
        case 0xA6: insn.mnemonic = M::Cmps; insn.suffix = 1; return true;
        case 0xA7: insn.mnemonic = M::Cmps; insn.suffix = uint8_t(SZv(p)); return true;
        case 0xAA: insn.mnemonic = M::Stos; insn.suffix = 1; return true;
        case 0xAB: insn.mnemonic = M::Stos; insn.suffix = uint8_t(SZv(p)); return true;
        case 0xAC: insn.mnemonic = M::Lods; insn.suffix = 1; return true;
        case 0xAD: insn.mnemonic = M::Lods; insn.suffix = uint8_t(SZv(p)); return true;
        case 0xAE: insn.mnemonic = M::Scas; insn.suffix = 1; return true;
        case 0xAF: insn.mnemonic = M::Scas; insn.suffix = uint8_t(SZv(p)); return true;
        case 0xF5: insn.mnemonic = M::Cmc; return true;
        case 0xF8: insn.mnemonic = M::Clc; return true;
        case 0xF9: insn.mnemonic = M::Stc; return true;
        case 0xFA: insn.mnemonic = M::Cli; return true;
        case 0xFB: insn.mnemonic = M::Sti; return true;
        case 0xFC: insn.mnemonic = M::Cld; return true;
        case 0xFD: insn.mnemonic = M::Std; return true;
        default: return false;
    }
    return false;
}

void finalize(Reader& r, Instruction& insn) {
    insn.length = uint8_t(r.pos > 255 ? 255 : r.pos);
    for (int i = 0; i < insn.operandCount; ++i) {
        Operand& o = insn.operands[i];
        if (o.kind == OperandKind::Rel) { o.relTarget = insn.address + insn.length + uint64_t(o.imm); insn.positionDependent = true; }
        else if (o.kind == OperandKind::Mem && o.mem.ripRelative) { o.mem.ripTarget = insn.address + insn.length + uint64_t(o.mem.disp); insn.positionDependent = true; }
    }
}

} // namespace

DecodeResult decode(const uint8_t* p, size_t n, uint64_t address) {
    DecodeResult res;
    Instruction& insn = res.insn;
    insn.address = address;
    if (n == 0) { res.status = DecodeStatus::Truncated; return res; }

    Reader r(p, n);
    decodePrefixes(r, insn.prefixes);
    if (r.overflow) { res.status = DecodeStatus::Truncated; return res; }

    if (insn.prefixes.vex) { insn.length = uint8_t(r.pos); res.status = DecodeStatus::Invalid; return res; }

    uint8_t op = r.u8();
    bool handled = (op == 0x0F) ? decode0F(r, insn) : decodeOne(r, insn, op);

    if (r.overflow) { res.status = DecodeStatus::Truncated; return res; }
    if (!handled || insn.mnemonic == M::Invalid) { insn.length = uint8_t(r.pos); res.status = DecodeStatus::Invalid; return res; }

    finalize(r, insn);
    res.status = DecodeStatus::Ok;
    return res;
}

} // namespace disasm64
