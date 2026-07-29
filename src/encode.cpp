#include "disasm64/encode.h"

namespace disasm64 {
namespace {

using M = Mnemonic;

struct Buf {
    uint8_t b[16];
    int n = 0;
    void put(uint8_t x) { if (n < 16) b[n++] = x; }
    void imm(int64_t v, int s) { for (int i = 0; i < s; ++i) put(uint8_t(uint64_t(v) >> (8 * i))); }
};

// modrm + sib + disp, plus the REX bits the addressing implies
struct RM {
    Buf bytes;
    bool r = false, x = false, b = false;
    bool forceRex = false;   // spl/sil/dil/bpl
    bool badRex = false;     // ah/ch/dh/bh -- must not carry REX
    bool ok = true;
};

bool fitsI8(int64_t v) { return v >= -128 && v <= 127; }
bool fitsI32(int64_t v) { return v >= -2147483648LL && v <= 2147483647LL; }

void mark8(RM& e, const Reg& r) {
    if (r.cls == RegClass::Gpr8 && r.idx >= 4 && r.idx <= 7) e.forceRex = true;
    if (r.cls == RegClass::Gpr8Hi) e.badRex = true;
}

RM rmReg(int regField, const Operand& o) {
    RM e;
    e.r = regField >= 8;
    e.b = o.reg.idx >= 8;
    mark8(e, o.reg);
    e.bytes.put(uint8_t(0xC0 | ((regField & 7) << 3) | (o.reg.idx & 7)));
    return e;
}

RM rmMem(int regField, const Operand& o) {
    RM e;
    e.r = regField >= 8;
    const MemOperand& m = o.mem;
    int rf = (regField & 7) << 3;

    if (m.ripRelative) {                       // [rip + disp32]
        e.bytes.put(uint8_t(0x00 | rf | 0x05));
        e.bytes.imm(m.disp, 4);
        return e;
    }

    int base = m.base.valid() ? m.base.idx : -1;
    int index = m.index.valid() ? m.index.idx : -1;
    if (index == 4) { e.ok = false; return e; }   // rsp can't be an index
    e.b = base >= 8;
    e.x = index >= 8;

    uint8_t scaleBits = m.scale == 8 ? 3 : m.scale == 4 ? 2 : m.scale == 2 ? 1 : 0;
    bool needSib = index >= 0 || base < 0 || (base & 7) == 4;

    if (base < 0 && !fitsI32(m.disp)) { e.ok = false; return e; }   // [abs64] needs the moffs form
    int mod; int dispSz;
    if (base < 0) { mod = 0; dispSz = 4; }                          // absolute / index-only -> disp32
    else if (m.disp == 0 && (base & 7) != 5) { mod = 0; dispSz = 0; }
    else if (fitsI8(m.disp)) { mod = 1; dispSz = 1; }
    else { mod = 2; dispSz = 4; }

    if (needSib) {
        e.bytes.put(uint8_t((mod << 6) | rf | 0x04));
        uint8_t sibBase = base < 0 ? 0x05 : uint8_t(base & 7);
        uint8_t sibIndex = index < 0 ? 0x04 : uint8_t(index & 7);
        e.bytes.put(uint8_t((scaleBits << 6) | (sibIndex << 3) | sibBase));
        e.bytes.imm(m.disp, dispSz);
    } else {
        e.bytes.put(uint8_t((mod << 6) | rf | (base & 7)));
        e.bytes.imm(m.disp, dispSz);
    }
    return e;
}

RM buildRM(int regField, const Operand& o) {
    return o.kind == OperandKind::Reg ? rmReg(regField, o) : rmMem(regField, o);
}

int opWidth(const Instruction& in) {
    for (int i = 0; i < in.operandCount; ++i) {
        const Operand& o = in.operands[i];
        if (o.kind == OperandKind::Reg || o.kind == OperandKind::Mem) return o.sizeBytes;
    }
    return 4;
}

struct Out {
    uint8_t* p; size_t cap; size_t n = 0; bool over = false;
    void put(uint8_t x) { if (n < cap) p[n] = x; else over = true; ++n; }
    void imm(int64_t v, int s) { for (int i = 0; i < s; ++i) put(uint8_t(uint64_t(v) >> (8 * i))); }
    void buf(const Buf& b) { for (int i = 0; i < b.n; ++i) put(b.b[i]); }
};

// Emit legacy prefixes, REX (from width + the RM addressing), the opcode bytes, then the RM bytes.
bool emit(Out& out, const Instruction& in, int width, const uint8_t* opc, int opcLen, const RM& e) {
    if (!e.ok) return false;
    if (in.prefixes.lock) out.put(0xF0);
    if (in.prefixes.rep) out.put(in.prefixes.rep);
    if (in.prefixes.segment != 0xFF) {
        static const uint8_t seg[6] = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65};
        if (in.prefixes.segment < 6) out.put(seg[in.prefixes.segment]);
    }
    if (in.prefixes.addrsize) out.put(0x67);
    if (width == 2) out.put(0x66);
    bool w = width == 8;
    uint8_t rex = uint8_t(0x40 | (w << 3) | (e.r << 2) | (e.x << 1) | (e.b ? 1 : 0));
    bool need = w || e.r || e.x || e.b || e.forceRex;
    if (need && e.badRex) return false;
    if (need) out.put(rex);
    for (int i = 0; i < opcLen; ++i) out.put(opc[i]);
    out.buf(e.bytes);
    return true;
}

int immWidth(int width) { return width == 8 ? 4 : width == 2 ? 2 : width == 1 ? 1 : 4; }

// which operand is the r/m (memory always is; else operand[0]); returns index or -1
int rmIndex(const Instruction& in) {
    if (in.operands[0].kind == OperandKind::Mem) return 0;
    if (in.operandCount > 1 && in.operands[1].kind == OperandKind::Mem) return 1;
    return 0;
}

int aluIndex(M m) {
    if (m >= M::Add && m <= M::Cmp) return int(m) - int(M::Add);
    return -1;
}

int shiftIndex(M m) {
    switch (m) {
        case M::Rol: return 0; case M::Ror: return 1; case M::Rcl: return 2; case M::Rcr: return 3;
        case M::Shl: return 4; case M::Shr: return 5; case M::Sar: return 7;
        default: return -1;
    }
}

int ccOf(const Instruction& in) { return in.cc & 0x0F; }

EncodeResult done(Out& out) {
    EncodeResult r;
    r.status = out.over ? EncodeStatus::Buffer : EncodeStatus::Ok;
    r.length = uint8_t(out.n);
    return r;
}

} // namespace

EncodeResult encode(const Instruction& in, uint8_t* dst, size_t cap) {
    Out out{dst, cap};
    const M m = in.mnemonic;
    const int width = opWidth(in);

    auto twoOperandArith = [&](int mrOp8, int mrOpV) -> bool {
        // forms: rm,reg (MR)  reg,rm (RM->emit as MR by swapping)  rm,imm (group1)  acc,imm
        const Operand& a = in.operands[0];
        const Operand& b = in.operands[1];
        int idx = aluIndex(m);
        if (b.kind == OperandKind::Imm) {
            if (idx < 0 && m != M::Test) return false;
            if (m == M::Test) {                         // F6/F7 /0
                uint8_t op = width == 1 ? 0xF6 : 0xF7;
                RM e = buildRM(0, a);
                if (!emit(out, in, width, &op, 1, e)) return false;
                out.imm(b.imm, immWidth(width) == 4 && width == 8 ? 4 : immWidth(width));
                return true;
            }
            bool imm8 = b.sizeBytes == 1 && width != 1;
            uint8_t op = width == 1 ? 0x80 : imm8 ? 0x83 : 0x81;
            RM e = buildRM(idx, a);
            if (!emit(out, in, width, &op, 1, e)) return false;
            out.imm(b.imm, imm8 ? 1 : immWidth(width));
            return true;
        }
        // register/memory source: MR when the r/m is operand[0], RM (base+2/+3) when it is operand[1]
        (void)mrOp8; (void)mrOpV;
        int ri = rmIndex(in);
        int reg = ri == 0 ? 1 : 0;
        if (in.operands[reg].kind != OperandKind::Reg) return false;
        uint8_t base = uint8_t(idx * 8);
        uint8_t op = uint8_t(base + (ri == 1 ? 2 : 0) + (width == 1 ? 0 : 1));
        RM e = buildRM(in.operands[reg].reg.idx, in.operands[ri]);
        mark8(e, in.operands[reg].reg);
        return emit(out, in, width, &op, 1, e);
    };

    int idx = aluIndex(m);
    if (idx >= 0) {
        if (!twoOperandArith(uint8_t(idx * 8), uint8_t(idx * 8 + 1))) return {EncodeStatus::Unsupported, 0};
        return done(out);
    }

    switch (m) {
        case M::Mov: {
            const Operand& a = in.operands[0];
            const Operand& b = in.operands[1];
            if (a.kind == OperandKind::Reg && a.reg.cls == RegClass::Sreg) {   // mov Sreg, r/m16  (8E)
                uint8_t op = 0x8E; RM e = buildRM(a.reg.idx, b);
                if (!emit(out, in, 4, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
                return done(out);
            }
            if (b.kind == OperandKind::Reg && b.reg.cls == RegClass::Sreg) {   // mov r/m16, Sreg  (8C)
                uint8_t op = 0x8C; RM e = buildRM(b.reg.idx, a);
                if (!emit(out, in, 4, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
                return done(out);
            }
            // mov r64, CR/DR and reverse (0F 20-23) -- fixed 64-bit GPR, REX.R extends the CR/DR number
            {
                bool aCtl = a.reg.cls == RegClass::Cr || a.reg.cls == RegClass::Dr;
                bool bCtl = b.reg.cls == RegClass::Cr || b.reg.cls == RegClass::Dr;
                if (aCtl || bCtl) {
                    const Operand& ctl = aCtl ? a : b;
                    const Operand& gpr = aCtl ? b : a;
                    if (gpr.kind != OperandKind::Reg) return {EncodeStatus::Unsupported, 0};
                    bool isDr = ctl.reg.cls == RegClass::Dr;
                    uint8_t op2 = uint8_t((aCtl ? 0x22 : 0x20) + (isDr ? 1 : 0));
                    if (in.prefixes.lock) out.put(0xF0);
                    uint8_t rex = uint8_t(0x40 | ((ctl.reg.idx >= 8) << 2) | (gpr.reg.idx >= 8 ? 1 : 0));
                    if (rex != 0x40) out.put(rex);
                    out.put(0x0F); out.put(op2);
                    out.put(uint8_t(0xC0 | ((ctl.reg.idx & 7) << 3) | (gpr.reg.idx & 7)));
                    return done(out);
                }
            }
            auto isAbs = [](const Operand& o) {
                return o.kind == OperandKind::Mem && !o.mem.base.valid() &&
                       !o.mem.index.valid() && !o.mem.ripRelative;
            };
            int memI = isAbs(a) ? 0 : (in.operandCount > 1 && isAbs(b)) ? 1 : -1;
            if (memI >= 0 && !fitsI32(in.operands[memI].mem.disp)) {   // mov acc, [abs64] / mov [abs64], acc
                int accI = memI == 0 ? 1 : 0;
                const Operand& acc = in.operands[accI];
                bool isGpr = acc.reg.cls == RegClass::Gpr8 || acc.reg.cls == RegClass::Gpr8Hi ||
                             acc.reg.cls == RegClass::Gpr16 || acc.reg.cls == RegClass::Gpr32 ||
                             acc.reg.cls == RegClass::Gpr64;
                if (acc.kind != OperandKind::Reg || acc.reg.idx != 0 || !isGpr) return {EncodeStatus::Unsupported, 0};
                int w = acc.sizeBytes;
                bool load = memI == 1;
                uint8_t op = w == 1 ? (load ? 0xA0 : 0xA2) : (load ? 0xA1 : 0xA3);
                if (w == 2) out.put(0x66);
                if (w == 8) out.put(0x48);
                out.put(op); out.imm(in.operands[memI].mem.disp, 8);
                return done(out);
            }
            if (b.kind == OperandKind::Imm) {
                // B8+r takes an immediate of the full register width; only valid when the
                // immediate is that wide (r64,imm64). r64 with a 32-bit imm must use C7 /0.
                if (a.kind == OperandKind::Reg && b.sizeBytes == width) {
                    RM e; e.b = a.reg.idx >= 8; mark8(e, a.reg);
                    uint8_t op = uint8_t((width == 1 ? 0xB0 : 0xB8) + (a.reg.idx & 7));
                    if (width == 2) out.put(0x66);
                    bool w = width == 8; bool need = w || e.b || e.forceRex;
                    if (need && e.badRex) return {EncodeStatus::Unsupported, 0};
                    if (in.prefixes.lock) out.put(0xF0);
                    if (need) out.put(uint8_t(0x40 | (w << 3) | (e.b ? 1 : 0)));
                    out.put(op); out.imm(b.imm, width);
                    return done(out);
                }
                uint8_t op = width == 1 ? 0xC6 : 0xC7;             // C6/C7 /0
                RM e = buildRM(0, a);
                if (!emit(out, in, width, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
                out.imm(b.imm, width == 8 ? 4 : immWidth(width));
                return done(out);
            }
            int ri = rmIndex(in);
            int reg = ri == 0 ? 1 : 0;
            if (in.operands[reg].kind != OperandKind::Reg) return {EncodeStatus::Unsupported, 0};
            uint8_t op = uint8_t((width == 1 ? 0x88 : 0x89) + (ri == 0 ? 0 : 2));
            RM e = buildRM(in.operands[reg].reg.idx, in.operands[ri]);
            mark8(e, in.operands[reg].reg);
            if (!emit(out, in, width, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
            return done(out);
        }

        case M::Lea: {
            if (in.operands[1].kind != OperandKind::Mem) return {EncodeStatus::Unsupported, 0};
            uint8_t op = 0x8D;
            RM e = buildRM(in.operands[0].reg.idx, in.operands[1]);
            if (!emit(out, in, width, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
            return done(out);
        }

        case M::Push: case M::Pop: {
            const Operand& a = in.operands[0];
            if (a.kind == OperandKind::Reg && a.reg.cls != RegClass::Sreg) {
                if (in.prefixes.opsize) out.put(0x66);
                if (a.reg.idx >= 8) out.put(0x41);
                out.put(uint8_t((m == M::Push ? 0x50 : 0x58) + (a.reg.idx & 7)));
                return done(out);
            }
            if (m == M::Push && a.kind == OperandKind::Imm) {
                if (a.sizeBytes == 1) { out.put(0x6A); out.imm(a.imm, 1); }
                else if (a.sizeBytes == 2) { out.put(0x66); out.put(0x68); out.imm(a.imm, 2); }
                else { out.put(0x68); out.imm(a.imm, 4); }
                return done(out);
            }
            if (a.kind == OperandKind::Mem) {
                uint8_t op = m == M::Push ? 0xFF : 0x8F;
                RM e = buildRM(m == M::Push ? 6 : 0, a);
                int w = in.prefixes.opsize ? 2 : 4;   // default 64 -> no rexW needed
                if (!emit(out, in, w, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
                return done(out);
            }
            return {EncodeStatus::Unsupported, 0};
        }

        case M::Inc: case M::Dec: {
            uint8_t op = width == 1 ? 0xFE : 0xFF;
            RM e = buildRM(m == M::Inc ? 0 : 1, in.operands[0]);
            if (!emit(out, in, width, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
            return done(out);
        }

        case M::Neg: case M::Not: case M::Mul: case M::Div: case M::Idiv: {
            int sub = m == M::Not ? 2 : m == M::Neg ? 3 : m == M::Mul ? 4 : m == M::Div ? 6 : 7;
            uint8_t op = width == 1 ? 0xF6 : 0xF7;
            RM e = buildRM(sub, in.operands[0]);
            if (!emit(out, in, width, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
            return done(out);
        }

        case M::Imul: {
            if (in.operandCount == 1) {                     // F6/F7 /5
                uint8_t op = width == 1 ? 0xF6 : 0xF7;
                RM e = buildRM(5, in.operands[0]);
                if (!emit(out, in, width, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
                return done(out);
            }
            if (in.operandCount == 2) {                     // 0F AF /r
                uint8_t op[2] = {0x0F, 0xAF};
                RM e = buildRM(in.operands[0].reg.idx, in.operands[1]);
                if (!emit(out, in, width, op, 2, e)) return {EncodeStatus::Unsupported, 0};
                return done(out);
            }
            if (in.operandCount == 3) {                     // 69/6B /r ib/iz
                const Operand& im = in.operands[2];
                bool imm8 = im.sizeBytes == 1;
                uint8_t op = imm8 ? 0x6B : 0x69;
                RM e = buildRM(in.operands[0].reg.idx, in.operands[1]);
                if (!emit(out, in, width, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
                out.imm(im.imm, imm8 ? 1 : immWidth(width));
                return done(out);
            }
            return {EncodeStatus::Unsupported, 0};
        }

        case M::Shl: case M::Shr: case M::Sar: case M::Rol: case M::Ror: case M::Rcl: case M::Rcr: {
            int sub = shiftIndex(m);
            const Operand& cnt = in.operands[1];
            RM e = buildRM(sub, in.operands[0]);
            if (cnt.kind == OperandKind::Reg) {             // by CL: D2/D3
                uint8_t op = width == 1 ? 0xD2 : 0xD3;
                if (!emit(out, in, width, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
                return done(out);
            }
            if (cnt.kind == OperandKind::Imm && cnt.imm == 1) {   // by 1: D0/D1
                uint8_t op = width == 1 ? 0xD0 : 0xD1;
                if (!emit(out, in, width, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
                return done(out);
            }
            uint8_t op = width == 1 ? 0xC0 : 0xC1;          // by imm8: C0/C1
            if (!emit(out, in, width, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
            out.imm(cnt.imm, 1);
            return done(out);
        }

        case M::Test: {
            if (in.operands[1].kind == OperandKind::Imm) {
                uint8_t op = width == 1 ? 0xF6 : 0xF7;
                RM e = buildRM(0, in.operands[0]);
                if (!emit(out, in, width, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
                out.imm(in.operands[1].imm, width == 8 ? 4 : immWidth(width));
                return done(out);
            }
            uint8_t op = width == 1 ? 0x84 : 0x85;
            int ri = rmIndex(in), reg = ri == 0 ? 1 : 0;
            RM e = buildRM(in.operands[reg].reg.idx, in.operands[ri]);
            mark8(e, in.operands[reg].reg);
            if (!emit(out, in, width, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
            return done(out);
        }

        case M::Xchg: {
            uint8_t op = width == 1 ? 0x86 : 0x87;
            int ri = rmIndex(in), reg = ri == 0 ? 1 : 0;
            if (in.operands[reg].kind != OperandKind::Reg) return {EncodeStatus::Unsupported, 0};
            RM e = buildRM(in.operands[reg].reg.idx, in.operands[ri]);
            mark8(e, in.operands[reg].reg);
            if (!emit(out, in, width, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
            return done(out);
        }

        case M::Movzx: case M::Movsx: {
            int es = in.operands[1].sizeBytes;              // 1 or 2
            uint8_t op[2] = {0x0F, uint8_t((m == M::Movzx ? 0xB6 : 0xBE) + (es == 2 ? 1 : 0))};
            RM e = buildRM(in.operands[0].reg.idx, in.operands[1]);
            if (!emit(out, in, in.operands[0].sizeBytes, op, 2, e)) return {EncodeStatus::Unsupported, 0};
            return done(out);
        }
        case M::Movsxd: {
            uint8_t op = 0x63;
            RM e = buildRM(in.operands[0].reg.idx, in.operands[1]);
            if (!emit(out, in, in.operands[0].sizeBytes, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
            return done(out);
        }

        case M::Setcc: {
            uint8_t op[2] = {0x0F, uint8_t(0x90 + ccOf(in))};
            RM e = buildRM(0, in.operands[0]);
            if (!emit(out, in, 1, op, 2, e)) return {EncodeStatus::Unsupported, 0};
            return done(out);
        }
        case M::Cmovcc: {
            uint8_t op[2] = {0x0F, uint8_t(0x40 + ccOf(in))};
            RM e = buildRM(in.operands[0].reg.idx, in.operands[1]);
            if (!emit(out, in, width, op, 2, e)) return {EncodeStatus::Unsupported, 0};
            return done(out);
        }

        case M::Jmp: case M::Call: {
            const Operand& a = in.operands[0];
            if (a.kind == OperandKind::Rel) {
                uint8_t op = m == M::Jmp ? 0xE9 : 0xE8;
                int len = 5;
                int64_t rel = int64_t(a.relTarget) - int64_t(in.address + len);
                out.put(op); out.imm(rel, 4);
                return done(out);
            }
            uint8_t op = 0xFF;
            RM e = buildRM(m == M::Jmp ? 4 : 2, a);          // near indirect
            int w = in.prefixes.opsize ? 2 : 4;
            if (!emit(out, in, w, &op, 1, e)) return {EncodeStatus::Unsupported, 0};
            return done(out);
        }
        case M::Jcc: {
            uint8_t op[2] = {0x0F, uint8_t(0x80 + ccOf(in))};
            int len = 6;
            int64_t rel = int64_t(in.operands[0].relTarget) - int64_t(in.address + len);
            out.put(op[0]); out.put(op[1]); out.imm(rel, 4);
            return done(out);
        }

        case M::Ret: {
            if (in.operandCount == 1) { out.put(0xC2); out.imm(in.operands[0].imm, 2); }
            else out.put(0xC3);
            return done(out);
        }
        case M::Nop:
            if (in.operandCount == 0) { out.put(0x90); return done(out); }
            return {EncodeStatus::Unsupported, 0};
        case M::Leave:   out.put(0xC9); return done(out);
        case M::Int3:    out.put(0xCC); return done(out);
        case M::Int:     out.put(0xCD); out.imm(in.operands[0].imm, 1); return done(out);
        case M::Hlt:     out.put(0xF4); return done(out);
        case M::Cmc:     out.put(0xF5); return done(out);
        case M::Clc:     out.put(0xF8); return done(out);
        case M::Stc:     out.put(0xF9); return done(out);
        case M::Cli:     out.put(0xFA); return done(out);
        case M::Sti:     out.put(0xFB); return done(out);
        case M::Cld:     out.put(0xFC); return done(out);
        case M::Std:     out.put(0xFD); return done(out);
        case M::Pushf:   out.put(0x9C); return done(out);
        case M::Popf:    out.put(0x9D); return done(out);
        case M::Cpuid:   out.put(0x0F); out.put(0xA2); return done(out);
        case M::Rdtsc:   out.put(0x0F); out.put(0x31); return done(out);
        case M::Syscall: out.put(0x0F); out.put(0x05); return done(out);
        case M::Ud2:     out.put(0x0F); out.put(0x0B); return done(out);
        case M::Cwde:    if (width == 8) out.put(0x48); out.put(0x98); return done(out);
        case M::Cdqe:    out.put(0x48); out.put(0x98); return done(out);
        case M::Cdq:     out.put(0x99); return done(out);
        case M::Cqo:     out.put(0x48); out.put(0x99); return done(out);

        default: return {EncodeStatus::Unsupported, 0};
    }
}

} // namespace disasm64
