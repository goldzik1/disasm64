#include "disasm64/disasm64.h"
#include "prefix.h"
#include "operand.h"
#include <cstring>

namespace disasm64 {
namespace {
using M = Mnemonic;

const M kAlu[8]  = {M::Add, M::Or, M::Adc, M::Sbb, M::And, M::Sub, M::Xor, M::Cmp};
const M kGrp2[8] = {M::Rol, M::Ror, M::Rcl, M::Rcr, M::Shl, M::Shr, M::Shl, M::Sar};
const M kGrp3[8] = {M::Test, M::Test, M::Not, M::Neg, M::Mul, M::Imul, M::Div, M::Idiv};

int SZv(const Prefixes& p) { return p.rexW ? 8 : (p.opsize ? 2 : 4); }
int SZz(const Prefixes& p) { return p.rexW ? 4 : (p.opsize ? 2 : 4); }
int SZd64(const Prefixes& p) { return p.opsize ? 2 : 8; }

int sizeOfClass(RegClass c) {
    switch (c) {
        case RegClass::Gpr8: case RegClass::Gpr8Hi: return 1;
        case RegClass::Gpr16: return 2;
        case RegClass::Gpr32: return 4;
        case RegClass::Gpr64: return 8;
        case RegClass::Xmm: return 16;
        case RegClass::Ymm: return 32;
        case RegClass::St: return 10;
        case RegClass::Sreg: return 2;
        case RegClass::Cr: case RegClass::Dr: return 8;
        default: return 0;
    }
}

Operand regOp(Reg reg) {
    Operand o; o.kind = OperandKind::Reg; o.reg = reg; o.sizeBytes = uint8_t(sizeOfClass(reg.cls)); return o;
}
Operand xmmReg(int idx) { Operand o; o.kind = OperandKind::Reg; o.reg.cls = RegClass::Xmm; o.reg.idx = uint8_t(idx); o.sizeBytes = 16; return o; }
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

struct SseEnt { uint8_t o; const char* n; };
const char* findSse(const SseEnt* t, size_t n, uint8_t op) { for (size_t i = 0; i < n; ++i) if (t[i].o == op) return t[i].n; return nullptr; }
static const SseEnt kPackedInt[] = {
    {0x60,"punpcklbw"},{0x61,"punpcklwd"},{0x62,"punpckldq"},{0x63,"packsswb"},{0x67,"packuswb"},
    {0x68,"punpckhbw"},{0x69,"punpckhwd"},{0x6A,"punpckhdq"},{0x6B,"packssdw"},{0x6C,"punpcklqdq"},{0x6D,"punpckhqdq"},
    {0xD1,"psrlw"},{0xD2,"psrld"},{0xD3,"psrlq"},{0xD5,"pmullw"},{0xD8,"psubusb"},{0xD9,"psubusw"},{0xDA,"pminub"},
    {0xDC,"paddusb"},{0xDD,"paddusw"},{0xDE,"pmaxub"},{0xE0,"pavgb"},{0xE1,"psraw"},{0xE2,"psrad"},{0xE3,"pavgw"},
    {0xE4,"pmulhuw"},{0xE5,"pmulhw"},{0xE8,"psubsb"},{0xE9,"psubsw"},{0xEA,"pminsw"},{0xEC,"paddsb"},{0xED,"paddsw"},
    {0xEE,"pmaxsw"},{0xF1,"psllw"},{0xF2,"pslld"},{0xF3,"psllq"},{0xF4,"pmuludq"},{0xF5,"pmaddwd"},{0xF6,"psadbw"},
};
const size_t kPackedIntN = sizeof(kPackedInt) / sizeof(kPackedInt[0]);

const char* pshiftName(uint8_t op, int reg) {   // 0F 71/72/73 /r group
    if (op == 0x71) return reg == 2 ? "psrlw" : reg == 4 ? "psraw" : reg == 6 ? "psllw" : nullptr;
    if (op == 0x72) return reg == 2 ? "psrld" : reg == 4 ? "psrad" : reg == 6 ? "pslld" : nullptr;
    if (op == 0x73) return reg == 2 ? "psrlq" : reg == 3 ? "psrldq" : reg == 6 ? "psllq" : reg == 7 ? "pslldq" : nullptr;
    return nullptr;
}

bool decode0F38(Reader& r, Instruction& insn) {
    const Prefixes& p = insn.prefixes;
    uint8_t op = r.u8();
    if ((op == 0xF0 || op == 0xF1) && p.rep == 0xF2) {   // crc32 Gd, Eb/Ev
        int es = op == 0xF0 ? 1 : SZv(p); int gs = SZv(p); Operand rm; int reg = decodeModRM(r, p, es, rm);
        insn.rawName = "crc32"; addOp(insn, regOp(makeGpr(reg, gs, p.rex))); addOp(insn, rm); return true;
    }
    if (op == 0xF0 || op == 0xF1) {   // movbe (GP)
        int s = SZv(p); Operand rm; int reg = decodeModRM(r, p, s, rm);
        insn.rawName = "movbe";
        if (op == 0xF0) { addOp(insn, regOp(makeGpr(reg, s, p.rex))); addOp(insn, rm); }
        else { addOp(insn, rm); addOp(insn, regOp(makeGpr(reg, s, p.rex))); }
        return true;
    }
    if (op >= 0xC8 && op <= 0xCD && p.rep == 0 && !p.opsize) {   // SHA-NI
        static const char* n[] = {"sha1nexte","sha1msg1","sha1msg2","sha256rnds2","sha256msg1","sha256msg2"};
        Operand rm; int reg = decodeModRM(r, p, 16, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16;
        insn.rawName = n[op - 0xC8]; addOp(insn, xmmReg(reg)); addOp(insn, rm); return true;
    }
    const int pp = p.rep == 0xF3 ? 2 : p.rep == 0xF2 ? 3 : p.opsize ? 1 : 0;
    if (pp != 1) return false;
    if ((op >= 0x20 && op <= 0x25) || (op >= 0x30 && op <= 0x35)) {   // pmovsx / pmovzx
        static const char* nz[] = {"pmovzxbw","pmovzxbd","pmovzxbq","pmovzxwd","pmovzxwq","pmovzxdq"};
        static const char* ns[] = {"pmovsxbw","pmovsxbd","pmovsxbq","pmovsxwd","pmovsxwq","pmovsxdq"};
        static const int msz[] = {8, 4, 2, 8, 4, 8};
        int i = op & 0x0F; bool zx = op >= 0x30;
        Operand rm; int reg = decodeModRM(r, p, msz[i], rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16;
        insn.rawName = zx ? nz[i] : ns[i];
        addOp(insn, xmmReg(reg)); addOp(insn, rm); return true;
    }
    static const struct { uint8_t o; const char* n; } tbl[] = {
        {0x00,"pshufb"},{0x01,"phaddw"},{0x02,"phaddd"},{0x03,"phaddsw"},{0x04,"pmaddubsw"},
        {0x05,"phsubw"},{0x06,"phsubd"},{0x07,"phsubsw"},{0x08,"psignb"},{0x09,"psignw"},{0x0A,"psignd"},
        {0x0B,"pmulhrsw"},{0x17,"ptest"},{0x1C,"pabsb"},{0x1D,"pabsw"},{0x1E,"pabsd"},{0x28,"pmuldq"},
        {0x29,"pcmpeqq"},{0x2B,"packusdw"},{0x37,"pcmpgtq"},{0x38,"pminsb"},{0x39,"pminsd"},{0x3A,"pminuw"},
        {0x3B,"pminud"},{0x3C,"pmaxsb"},{0x3D,"pmaxsd"},{0x3E,"pmaxuw"},{0x3F,"pmaxud"},{0x40,"pmulld"},{0x41,"phminposuw"},
    };
    for (auto& e : tbl) if (e.o == op) {
        Operand rm; int reg = decodeModRM(r, p, 16, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16;
        insn.rawName = e.n; addOp(insn, xmmReg(reg)); addOp(insn, rm); return true;
    }
    return false;
}

bool decode0F3A(Reader& r, Instruction& insn) {
    const Prefixes& p = insn.prefixes;
    uint8_t op = r.u8();
    const int pp = p.rep == 0xF3 ? 2 : p.rep == 0xF2 ? 3 : p.opsize ? 1 : 0;
    if (pp != 1) return false;
    if (op == 0x20 || op == 0x22) {
        bool isReg = (r.peek() >> 6) == 3;
        int s = op == 0x22 ? (p.rexW ? 8 : 4) : (isReg ? 4 : 1);
        Operand rm; int reg = decodeModRM(r, p, s, rm);
        insn.rawName = op == 0x20 ? "pinsrb" : (p.rexW ? "pinsrq" : "pinsrd");
        addOp(insn, xmmReg(reg)); addOp(insn, rm); addOp(insn, immOp(r, 1)); return true;
    }
    if (op == 0x14 || op == 0x15 || op == 0x16 || op == 0x17) {
        bool isReg = (r.peek() >> 6) == 3;
        int s = op == 0x16 ? (p.rexW ? 8 : 4) : op == 0x17 ? 4 : op == 0x15 ? (isReg ? 4 : 2) : (isReg ? 4 : 1);
        Operand rm; int reg = decodeModRM(r, p, s, rm);
        insn.rawName = op == 0x14 ? "pextrb" : op == 0x15 ? "pextrw" : op == 0x17 ? "extractps" : (p.rexW ? "pextrq" : "pextrd");
        addOp(insn, rm); addOp(insn, xmmReg(reg)); addOp(insn, immOp(r, 1)); return true;
    }
    static const struct { uint8_t o; const char* n; } tbl[] = {
        {0x08,"roundps"},{0x09,"roundpd"},{0x0A,"roundss"},{0x0B,"roundsd"},{0x0C,"blendps"},
        {0x0D,"blendpd"},{0x0E,"pblendw"},{0x0F,"palignr"},{0x21,"insertps"},{0x40,"dpps"},
        {0x41,"dppd"},{0x42,"mpsadbw"},{0x44,"pclmulqdq"},{0x60,"pcmpestrm"},{0x61,"pcmpestri"},
        {0x62,"pcmpistrm"},{0x63,"pcmpistri"},
    };
    for (auto& e : tbl) if (e.o == op) {
        Operand rm; int reg = decodeModRM(r, p, 16, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16;
        insn.rawName = e.n; addOp(insn, xmmReg(reg)); addOp(insn, rm); addOp(insn, immOp(r, 1)); return true;
    }
    return false;
}

bool decode0F(Reader& r, Instruction& insn) {
    const Prefixes& p = insn.prefixes;
    uint8_t op = r.u8();
    if (op == 0x38) return decode0F38(r, insn);
    if (op == 0x3A) return decode0F3A(r, insn);
    if (op == 0x05) { insn.mnemonic = M::Syscall; return true; }
    if (op == 0x0B) { insn.mnemonic = M::Ud2; return true; }
    if (op == 0x1E && p.rep == 0xF3) { uint8_t m = r.peek(); if (m == 0xFA) { r.u8(); insn.mnemonic = M::Endbr64; return true; } if (m == 0xFB) { r.u8(); insn.mnemonic = M::Endbr32; return true; } }   // else falls through to reserved-nop
    if (op == 0x1F) { Operand e; decodeModRM(r, p, SZv(p), e); insn.mnemonic = M::Nop; addOp(insn, e); return true; }
    if (op == 0x31) { insn.mnemonic = M::Rdtsc; return true; }
    if (op >= 0x20 && op <= 0x23) {   // mov r64, CR/DR and reverse (mod ignored, always 64-bit GPR)
        uint8_t mb = r.u8();
        int reg = ((mb >> 3) & 7) | (p.rexR ? 8 : 0);
        int rm = (mb & 7) | (p.rexB ? 8 : 0);
        Operand gpr = regOp(makeGpr(rm, 8, p.rex));
        Operand ctl; ctl.kind = OperandKind::Reg; ctl.sizeBytes = 8;
        ctl.reg.cls = (op == 0x21 || op == 0x23) ? RegClass::Dr : RegClass::Cr;
        ctl.reg.idx = uint8_t(reg);
        insn.mnemonic = M::Mov;
        if (op == 0x20 || op == 0x21) { addOp(insn, gpr); addOp(insn, ctl); }
        else { addOp(insn, ctl); addOp(insn, gpr); }
        return true;
    }
    if (op == 0xA2) { insn.mnemonic = M::Cpuid; return true; }
    if (op == 0x02 || op == 0x03) { auto x = decodeEG(r, p, SZv(p), SZv(p)); insn.rawName = op == 0x02 ? "lar" : "lsl"; addOp(insn, x.g); addOp(insn, x.e); return true; }
    if (op == 0x06) { insn.rawName = "clts"; return true; }
    if (op == 0x07) { insn.rawName = "sysret"; return true; }
    if (op == 0x08) { insn.rawName = "invd"; return true; }
    if (op == 0x09) { insn.rawName = "wbinvd"; return true; }
    if (op == 0x37 && p.rep == 0 && !p.opsize) { insn.rawName = "getsec"; return true; }
    if (op == 0xB2 || op == 0xB4 || op == 0xB5) { int s = SZv(p); auto x = decodeEG(r, p, s, s); if (x.e.kind != OperandKind::Mem) return false; insn.rawName = op == 0xB2 ? "lss" : op == 0xB4 ? "lfs" : "lgs"; addOp(insn, x.g); addOp(insn, x.e); return true; }
    if (op == 0xC3 && p.rep == 0 && !p.opsize) { int s = p.rexW ? 8 : 4; auto x = decodeEG(r, p, s, s); if (x.e.kind != OperandKind::Mem) return false; insn.rawName = "movnti"; addOp(insn, x.e); addOp(insn, x.g); return true; }
    if (op == 0xB9 || op == 0xFF) { int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.rawName = op == 0xB9 ? "ud1" : "ud0"; addOp(insn, x.g); addOp(insn, x.e); return true; }
    if ((op == 0x78 || op == 0x79) && p.rep == 0 && !p.opsize) {
        auto x = decodeEG(r, p, 8, 8); insn.rawName = op == 0x78 ? "vmread" : "vmwrite";
        if (op == 0x78) { addOp(insn, x.e); addOp(insn, x.g); } else { addOp(insn, x.g); addOp(insn, x.e); }
        return true;
    }
    if (op == 0x30) { insn.rawName = "wrmsr"; return true; }
    if (op == 0x32) { insn.rawName = "rdmsr"; return true; }
    if (op == 0x33) { insn.rawName = "rdpmc"; return true; }
    if (op == 0x0E) { insn.rawName = "femms"; return true; }
    if (op == 0x0D) { uint8_t m = r.peek(); int reg = (m >> 3) & 7; Operand e; decodeModRM(r, p, 1, e); insn.rawName = reg == 1 ? "prefetchw" : "prefetch"; addOp(insn, e); return true; }
    if (op >= 0x18 && op <= 0x1E) {
        uint8_t m = r.peek(); int reg = (m >> 3) & 7;
        if (op == 0x18 && reg < 4) { static const char* n[] = {"prefetchnta","prefetcht0","prefetcht1","prefetcht2"}; Operand e; decodeModRM(r, p, 1, e); insn.rawName = n[reg]; addOp(insn, e); return true; }
        Operand e; decodeModRM(r, p, SZv(p), e); insn.mnemonic = M::Nop; addOp(insn, e); return true;
    }
    if (op == 0x34) { insn.rawName = "sysenter"; return true; }
    if (op == 0x35) { insn.rawName = "sysexit"; return true; }
    if (op == 0xAA) { insn.rawName = "rsm"; return true; }
    if (op == 0xA0 || op == 0xA1 || op == 0xA8 || op == 0xA9) {
        Operand s; s.kind = OperandKind::Reg; s.reg.cls = RegClass::Sreg; s.reg.idx = uint8_t(op < 0xA8 ? 4 : 5); s.sizeBytes = 8;
        insn.rawName = (op == 0xA0 || op == 0xA8) ? "push" : "pop"; addOp(insn, s); return true;
    }
    if (op == 0xA4 || op == 0xA5 || op == 0xAC || op == 0xAD) {
        int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.rawName = (op == 0xA4 || op == 0xA5) ? "shld" : "shrd";
        addOp(insn, x.e); addOp(insn, x.g);
        if (op == 0xA4 || op == 0xAC) addOp(insn, immOp(r, 1)); else addOp(insn, clOp(p));
        return true;
    }
    if (op == 0xAF) { auto x = decodeEG(r, p, SZv(p), SZv(p)); insn.mnemonic = M::Imul; addOp(insn, x.g); addOp(insn, x.e); return true; }
    if (op >= 0x40 && op <= 0x4F) { auto x = decodeEG(r, p, SZv(p), SZv(p)); insn.mnemonic = M::Cmovcc; insn.cc = op & 0xF; addOp(insn, x.g); addOp(insn, x.e); return true; }
    if (op >= 0x80 && op <= 0x8F) { insn.mnemonic = M::Jcc; insn.cc = op & 0xF; addOp(insn, relOp(r, 4)); return true; }
    if (op >= 0x90 && op <= 0x9F) { Operand e; decodeModRM(r, p, 1, e); insn.mnemonic = M::Setcc; insn.cc = op & 0xF; addOp(insn, e); return true; }
    if (op == 0xB6 || op == 0xB7) { int es = (op == 0xB6) ? 1 : 2; auto x = decodeEG(r, p, es, SZv(p)); insn.mnemonic = M::Movzx; addOp(insn, x.g); addOp(insn, x.e); return true; }
    if (op == 0xBE || op == 0xBF) { int es = (op == 0xBE) ? 1 : 2; auto x = decodeEG(r, p, es, SZv(p)); insn.mnemonic = M::Movsx; addOp(insn, x.g); addOp(insn, x.e); return true; }
    if (op == 0xBC || op == 0xBD) { int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.rawName = op == 0xBC ? (p.rep == 0xF3 ? "tzcnt" : "bsf") : (p.rep == 0xF3 ? "lzcnt" : "bsr"); addOp(insn, x.g); addOp(insn, x.e); return true; }
    if (op == 0xB8 && p.rep == 0xF3) { int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.rawName = "popcnt"; addOp(insn, x.g); addOp(insn, x.e); return true; }
    if (op == 0xAE) {
        uint8_t m = r.peek();
        if (!p.opsize && !p.rep) {
            if (m == 0xE8) { r.u8(); insn.rawName = "lfence"; return true; }
            if (m == 0xF0) { r.u8(); insn.rawName = "mfence"; return true; }
            if (m == 0xF8) { r.u8(); insn.rawName = "sfence"; return true; }
        }
        int reg = (m >> 3) & 7;
        if (p.rep == 0xF3) {   // rd/wr fs/gs base -- register operand only
            static const char* n[4] = {"rdfsbase","rdgsbase","wrfsbase","wrgsbase"};
            if ((m >> 6) != 3 || reg > 3) return false;
            Operand e; decodeModRM(r, p, p.rexW ? 8 : 4, e); insn.rawName = n[reg]; addOp(insn, e); return true;
        }
        if ((m >> 6) == 3) return false;   // remaining /r forms are all memory
        const char* nm = nullptr; int sz = 0;
        if (p.opsize) { nm = reg == 6 ? "clwb" : reg == 7 ? "clflushopt" : nullptr; sz = 1; }
        else if (p.rep == 0) { static const char* n[8] = {"fxsave","fxrstor","ldmxcsr","stmxcsr","xsave","xrstor","xsaveopt","clflush"}; nm = n[reg]; sz = (reg == 2 || reg == 3) ? 4 : reg == 7 ? 1 : 0; }
        if (!nm) return false;
        Operand rm; decodeModRM(r, p, sz, rm); insn.rawName = nm; addOp(insn, rm); return true;
    }
    if (op == 0x00) {   // group 6
        uint8_t mb = r.peek(); int reg = (mb >> 3) & 7, mod = mb >> 6;
        static const char* n[8] = {"sldt","str","lldt","ltr","verr","verw",nullptr,nullptr};
        if (!n[reg]) return false;
        int sz = (mod == 3 && reg < 2) ? SZv(p) : 2;
        Operand e; decodeModRM(r, p, sz, e); insn.rawName = n[reg]; addOp(insn, e); return true;
    }
    if (op == 0x01) {   // group 7 (+ register-form leaves)
        uint8_t mb = r.peek(); int reg = (mb >> 3) & 7, mod = mb >> 6;
        if (mod == 3) {
            if (reg == 4) { Operand e; decodeModRM(r, p, SZv(p), e); insn.rawName = "smsw"; addOp(insn, e); return true; }
            if (reg == 6) { Operand e; decodeModRM(r, p, 2, e); insn.rawName = "lmsw"; addOp(insn, e); return true; }
            if (p.rep || p.opsize) return false;   // the no-operand leaves take no mandatory prefix
            const char* nm = nullptr;
            switch (mb) {
                case 0xC0: nm = "enclv"; break;    case 0xC1: nm = "vmcall"; break;
                case 0xC2: nm = "vmlaunch"; break;
                case 0xC3: nm = "vmresume"; break; case 0xC4: nm = "vmxoff"; break;
                case 0xC8: nm = "monitor"; break;  case 0xC9: nm = "mwait"; break;
                case 0xCA: nm = "clac"; break;     case 0xCB: nm = "stac"; break;
                case 0xCF: nm = "encls"; break;    case 0xD0: nm = "xgetbv"; break;
                case 0xD1: nm = "xsetbv"; break;   case 0xD4: nm = "vmfunc"; break;
                case 0xD5: nm = "xend"; break;     case 0xD6: nm = "xtest"; break;
                case 0xD7: nm = "enclu"; break;    case 0xEE: nm = "rdpkru"; break;
                case 0xEF: nm = "wrpkru"; break;   case 0xF8: nm = "swapgs"; break;
                case 0xF9: nm = "rdtscp"; break;
            }
            if (!nm) return false;
            r.u8(); insn.rawName = nm; return true;
        }
        static const char* n[8] = {"sgdt","sidt","lgdt","lidt","smsw",nullptr,"lmsw","invlpg"};
        if (!n[reg]) return false;
        int sz = (reg == 4 || reg == 6) ? 2 : 0;
        Operand e; decodeModRM(r, p, sz, e); insn.rawName = n[reg]; addOp(insn, e); return true;
    }
    if (op == 0xB0 || op == 0xB1) { int s = op == 0xB0 ? 1 : SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = M::Cmpxchg; addOp(insn, x.e); addOp(insn, x.g); return true; }
    if (op == 0xC0 || op == 0xC1) { int s = op == 0xC0 ? 1 : SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = M::Xadd; addOp(insn, x.e); addOp(insn, x.g); return true; }
    if (op == 0xA3 || op == 0xAB || op == 0xB3 || op == 0xBB) { int s = SZv(p); auto x = decodeEG(r, p, s, s); insn.mnemonic = op == 0xA3 ? M::Bt : op == 0xAB ? M::Bts : op == 0xB3 ? M::Btr : M::Btc; addOp(insn, x.e); addOp(insn, x.g); return true; }
    if (op == 0xBA) { int s = SZv(p); Operand e; int reg = decodeModRM(r, p, s, e); M mm = (reg & 7) == 4 ? M::Bt : (reg & 7) == 5 ? M::Bts : (reg & 7) == 6 ? M::Btr : (reg & 7) == 7 ? M::Btc : M::Invalid; insn.mnemonic = mm; addOp(insn, e); addOp(insn, immOp(r, 1)); return mm != M::Invalid; }
    if (op >= 0xC8 && op <= 0xCF) { insn.mnemonic = M::Bswap; addOp(insn, regOp(makeGpr((op - 0xC8) | (p.rexB ? 8 : 0), SZv(p), p.rex))); return true; }

    const int pp = p.rep == 0xF3 ? 2 : p.rep == 0xF2 ? 3 : p.opsize ? 1 : 0;   // mandatory prefix
    const int sc = pp == 2 ? 4 : pp == 3 ? 8 : 16;   // scalar/packed mem size
    auto xmm = [](int idx) { Operand o; o.kind = OperandKind::Reg; o.reg.cls = RegClass::Xmm; o.reg.idx = uint8_t(idx); o.sizeBytes = 16; return o; };
    auto vecEG = [&](int memSz, bool store) {
        Operand rm; int reg = decodeModRM(r, p, memSz, rm, RegClass::Xmm);
        if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16;
        if (store) { addOp(insn, rm); addOp(insn, xmm(reg)); }
        else { addOp(insn, xmm(reg)); addOp(insn, rm); }
    };
    auto sseArith = [&](M base) { int msz = (pp == 2) ? 4 : (pp == 3) ? 8 : 16; insn.mnemonic = M(int(base) + pp); vecEG(msz, false); };
    if (pp == 1) { const char* nm = findSse(kPackedInt, kPackedIntN, op); if (nm) { Operand rm; int reg = decodeModRM(r, p, 16, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16; insn.rawName = nm; addOp(insn, xmm(reg)); addOp(insn, rm); return true; } }
    if (pp == 1 && (op == 0x71 || op == 0x72 || op == 0x73)) {
        int reg = (r.peek() >> 3) & 7; const char* nm = pshiftName(op, reg); if (!nm) return false;
        Operand rm; decodeModRM(r, p, 16, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16;
        insn.rawName = nm; addOp(insn, rm); addOp(insn, immOp(r, 1)); return true;
    }
    switch (op) {
        case 0x58: sseArith(M::Addps); return true;
        case 0x59: sseArith(M::Mulps); return true;
        case 0x5C: sseArith(M::Subps); return true;
        case 0x5E: sseArith(M::Divps); return true;
        case 0x51: sseArith(M::Sqrtps); return true;
        case 0x52: { if (pp == 1 || pp == 3) return false; insn.rawName = pp == 2 ? "rsqrtss" : "rsqrtps"; vecEG(pp == 2 ? 4 : 16, false); return true; }
        case 0x53: { if (pp == 1 || pp == 3) return false; insn.rawName = pp == 2 ? "rcpss" : "rcpps"; vecEG(pp == 2 ? 4 : 16, false); return true; }
        case 0x7C: { if (pp != 1 && pp != 3) return false; insn.rawName = pp == 1 ? "haddpd" : "haddps"; vecEG(16, false); return true; }
        case 0x7D: { if (pp != 1 && pp != 3) return false; insn.rawName = pp == 1 ? "hsubpd" : "hsubps"; vecEG(16, false); return true; }
        case 0xD0: { if (pp != 1 && pp != 3) return false; insn.rawName = pp == 1 ? "addsubpd" : "addsubps"; vecEG(16, false); return true; }
        case 0x5D: insn.mnemonic = M(int(M::Minps) + pp); vecEG(sc, false); return true;
        case 0x5F: insn.mnemonic = M(int(M::Maxps) + pp); vecEG(sc, false); return true;
        case 0xC2: { insn.mnemonic = M(int(M::Cmpps) + pp); Operand rm; int reg = decodeModRM(r, p, sc, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16; addOp(insn, xmm(reg)); addOp(insn, rm); addOp(insn, immOp(r, 1)); return true; }
        case 0xC4: { if (pp != 1) return false; int s = (r.peek() >> 6) == 3 ? 4 : 2; Operand rm; int reg = decodeModRM(r, p, s, rm); insn.rawName = "pinsrw"; addOp(insn, xmm(reg)); addOp(insn, rm); addOp(insn, immOp(r, 1)); return true; }
        case 0xC5: { if (pp != 1 || (r.peek() >> 6) != 3) return false; Operand rm; int reg = decodeModRM(r, p, 16, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16; insn.rawName = "pextrw"; addOp(insn, regOp(makeGpr(reg, 4, p.rex))); addOp(insn, rm); addOp(insn, immOp(r, 1)); return true; }
        case 0x14: if (pp >= 2) return false; insn.mnemonic = pp == 1 ? M::Unpcklpd : M::Unpcklps; vecEG(16, false); return true;
        case 0x15: if (pp >= 2) return false; insn.mnemonic = pp == 1 ? M::Unpckhpd : M::Unpckhps; vecEG(16, false); return true;
        case 0x50: { if (pp >= 2 || (r.peek() >> 6) != 3) return false; Operand rm; int reg = decodeModRM(r, p, 16, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16; insn.mnemonic = pp == 1 ? M::Movmskpd : M::Movmskps; addOp(insn, regOp(makeGpr(reg, 4, p.rex))); addOp(insn, rm); return true; }
        case 0x70: { if (pp == 0) return false; Operand rm; int reg = decodeModRM(r, p, 16, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16; insn.mnemonic = pp == 1 ? M::Pshufd : pp == 2 ? M::Pshufhw : M::Pshuflw; addOp(insn, xmm(reg)); addOp(insn, rm); addOp(insn, immOp(r, 1)); return true; }
        case 0xC6: { if (pp >= 2) return false; Operand rm; int reg = decodeModRM(r, p, 16, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16; insn.mnemonic = pp == 1 ? M::Shufpd : M::Shufps; addOp(insn, xmm(reg)); addOp(insn, rm); addOp(insn, immOp(r, 1)); return true; }
        case 0xD7: { if (pp != 1 || (r.peek() >> 6) != 3) return false; Operand rm; int reg = decodeModRM(r, p, 16, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16; insn.mnemonic = M::Pmovmskb; addOp(insn, regOp(makeGpr(reg, 4, p.rex))); addOp(insn, rm); return true; }
        case 0x2A: { if (pp != 2 && pp != 3) return false; int gs = p.rexW ? 8 : 4; Operand rm; int reg = decodeModRM(r, p, gs, rm); insn.mnemonic = pp == 2 ? M::Cvtsi2ss : M::Cvtsi2sd; addOp(insn, xmm(reg)); addOp(insn, rm); return true; }
        case 0x2C: case 0x2D: { if (pp != 2 && pp != 3) return false; int ms = pp == 2 ? 4 : 8; Operand rm; int reg = decodeModRM(r, p, ms, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16; int gs = p.rexW ? 8 : 4; bool tr = op == 0x2C; insn.mnemonic = tr ? (pp == 2 ? M::Cvttss2si : M::Cvttsd2si) : (pp == 2 ? M::Cvtss2si : M::Cvtsd2si); addOp(insn, regOp(makeGpr(reg, gs, p.rex))); addOp(insn, rm); return true; }
        case 0x5A: { int ms = pp == 2 ? 4 : pp == 3 ? 8 : 16; Operand rm; int reg = decodeModRM(r, p, ms, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16; insn.mnemonic = pp == 2 ? M::Cvtss2sd : pp == 3 ? M::Cvtsd2ss : pp == 1 ? M::Cvtpd2ps : M::Cvtps2pd; addOp(insn, xmm(reg)); addOp(insn, rm); return true; }
        case 0x5B: { if (pp == 3) return false; Operand rm; int reg = decodeModRM(r, p, 16, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16; insn.mnemonic = pp == 0 ? M::Cvtdq2ps : pp == 1 ? M::Cvtps2dq : M::Cvttps2dq; addOp(insn, xmm(reg)); addOp(insn, rm); return true; }
        case 0x2E: if (pp >= 2) return false; { int msz = pp == 1 ? 8 : 4; insn.mnemonic = M(int(M::Ucomiss) + pp); vecEG(msz, false); } return true;
        case 0x2F: if (pp >= 2) return false; { int msz = pp == 1 ? 8 : 4; insn.mnemonic = M(int(M::Comiss) + pp); vecEG(msz, false); } return true;
        case 0x10: case 0x11: { int msz = (pp == 2) ? 4 : (pp == 3) ? 8 : 16;
            insn.mnemonic = pp == 0 ? M::Movups : pp == 1 ? M::Movupd : pp == 2 ? M::Movss : M::Movsd;
            vecEG(msz, op == 0x11); return true; }
        case 0x12: {
            if (pp == 2) { insn.rawName = "movsldup"; vecEG(16, false); return true; }
            if (pp == 3) { insn.rawName = "movddup"; Operand rm; int reg = decodeModRM(r, p, 8, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16; addOp(insn, xmm(reg)); addOp(insn, rm); return true; }
            if ((r.peek() >> 6) == 3 && pp == 0) { insn.rawName = "movhlps"; vecEG(16, false); return true; }
            if (pp >= 2 || (r.peek() >> 6) == 3) return false;
            insn.rawName = pp == 1 ? "movlpd" : "movlps"; Operand rm; int reg = decodeModRM(r, p, 8, rm, RegClass::Xmm); addOp(insn, xmm(reg)); addOp(insn, rm); return true;
        }
        case 0x13: { if (pp >= 2 || (r.peek() >> 6) == 3) return false; insn.rawName = pp == 1 ? "movlpd" : "movlps"; Operand rm; int reg = decodeModRM(r, p, 8, rm, RegClass::Xmm); addOp(insn, rm); addOp(insn, xmm(reg)); return true; }
        case 0x16: {
            if (pp == 2) { insn.rawName = "movshdup"; vecEG(16, false); return true; }
            if ((r.peek() >> 6) == 3 && pp == 0) { insn.rawName = "movlhps"; vecEG(16, false); return true; }
            if (pp >= 2 || (r.peek() >> 6) == 3) return false;
            insn.rawName = pp == 1 ? "movhpd" : "movhps"; Operand rm; int reg = decodeModRM(r, p, 8, rm, RegClass::Xmm); addOp(insn, xmm(reg)); addOp(insn, rm); return true;
        }
        case 0x17: { if (pp >= 2 || (r.peek() >> 6) == 3) return false; insn.rawName = pp == 1 ? "movhpd" : "movhps"; Operand rm; int reg = decodeModRM(r, p, 8, rm, RegClass::Xmm); addOp(insn, rm); addOp(insn, xmm(reg)); return true; }
        case 0x2B: { if (pp >= 2 || (r.peek() >> 6) == 3) return false; insn.rawName = pp == 1 ? "movntpd" : "movntps"; Operand rm; int reg = decodeModRM(r, p, 16, rm, RegClass::Xmm); addOp(insn, rm); addOp(insn, xmm(reg)); return true; }
        case 0xE7: { if (pp != 1 || (r.peek() >> 6) == 3) return false; insn.rawName = "movntdq"; Operand rm; int reg = decodeModRM(r, p, 16, rm, RegClass::Xmm); addOp(insn, rm); addOp(insn, xmm(reg)); return true; }
        case 0xD6: { if (pp != 1) return false; insn.mnemonic = M::Movq; Operand rm; int reg = decodeModRM(r, p, 8, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16; addOp(insn, rm); addOp(insn, xmm(reg)); return true; }
        case 0xE6: { if (pp == 0) return false; insn.rawName = pp == 1 ? "cvttpd2dq" : pp == 2 ? "cvtdq2pd" : "cvtpd2dq"; vecEG(pp == 2 ? 8 : 16, false); return true; }
        case 0xF7: { if (pp != 1 || (r.peek() >> 6) != 3) return false; insn.rawName = "maskmovdqu"; Operand rm; int reg = decodeModRM(r, p, 16, rm, RegClass::Xmm); if (rm.kind == OperandKind::Reg) rm.sizeBytes = 16; addOp(insn, xmm(reg)); addOp(insn, rm); return true; }
        case 0xF0: { if (pp != 3 || (r.peek() >> 6) == 3) return false; insn.rawName = "lddqu"; vecEG(16, false); return true; }
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
        case 0xFC: if (pp != 1) return false; insn.mnemonic = M::Paddb; vecEG(16, false); return true;
        case 0xFD: if (pp != 1) return false; insn.mnemonic = M::Paddw; vecEG(16, false); return true;
        case 0xFE: if (pp != 1) return false; insn.mnemonic = M::Paddd; vecEG(16, false); return true;
        case 0xD4: if (pp != 1) return false; insn.mnemonic = M::Paddq; vecEG(16, false); return true;
        case 0xF8: if (pp != 1) return false; insn.mnemonic = M::Psubb; vecEG(16, false); return true;
        case 0xF9: if (pp != 1) return false; insn.mnemonic = M::Psubw; vecEG(16, false); return true;
        case 0xFA: if (pp != 1) return false; insn.mnemonic = M::Psubd; vecEG(16, false); return true;
        case 0xFB: if (pp != 1) return false; insn.mnemonic = M::Psubq; vecEG(16, false); return true;
        case 0x74: if (pp != 1) return false; insn.mnemonic = M::Pcmpeqb; vecEG(16, false); return true;
        case 0x75: if (pp != 1) return false; insn.mnemonic = M::Pcmpeqw; vecEG(16, false); return true;
        case 0x76: if (pp != 1) return false; insn.mnemonic = M::Pcmpeqd; vecEG(16, false); return true;
        case 0x64: if (pp != 1) return false; insn.mnemonic = M::Pcmpgtb; vecEG(16, false); return true;
        case 0x65: if (pp != 1) return false; insn.mnemonic = M::Pcmpgtw; vecEG(16, false); return true;
        case 0x66: if (pp != 1) return false; insn.mnemonic = M::Pcmpgtd; vecEG(16, false); return true;
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

bool decodeX87(Reader& r, Instruction& insn, uint8_t op) {
    const Prefixes& p = insn.prefixes;
    auto st = [](int i) { Operand o; o.kind = OperandKind::Reg; o.reg.cls = RegClass::St; o.reg.idx = uint8_t(i & 7); o.sizeBytes = 10; return o; };
    uint8_t m = r.peek();
    int mod = m >> 6, reg = (m >> 3) & 7, rm = m & 7;
    if (mod != 3) {
        static const char* AR[8] = {"fadd","fmul","fcom","fcomp","fsub","fsubr","fdiv","fdivr"};
        static const char* FI[8] = {"fiadd","fimul","ficom","ficomp","fisub","fisubr","fidiv","fidivr"};
        static const char* D9[8] = {"fld",nullptr,"fst","fstp","fldenv","fldcw","fnstenv","fnstcw"};
        static const int   D9S[8] = {4,0,4,4,0,2,0,2};
        static const char* DB[8] = {"fild","fisttp","fist","fistp",nullptr,"fld",nullptr,"fstp"};
        static const int   DBS[8] = {4,4,4,4,0,10,0,10};
        static const char* DD[8] = {"fld","fisttp","fst","fstp","frstor",nullptr,"fnsave","fnstsw"};
        static const int   DDS[8] = {8,8,8,8,0,0,0,2};
        static const char* DF[8] = {"fild","fisttp","fist","fistp","fbld","fild","fbstp","fistp"};
        static const int   DFS[8] = {2,2,2,2,10,8,10,8};
        const char* nm = nullptr; int sz = 0;
        switch (op) {
            case 0xD8: nm = AR[reg]; sz = 4; break;
            case 0xDC: nm = AR[reg]; sz = 8; break;
            case 0xDA: nm = FI[reg]; sz = 4; break;
            case 0xDE: nm = FI[reg]; sz = 2; break;
            case 0xD9: nm = D9[reg]; sz = D9S[reg]; break;
            case 0xDB: nm = DB[reg]; sz = DBS[reg]; break;
            case 0xDD: nm = DD[reg]; sz = DDS[reg]; break;
            case 0xDF: nm = DF[reg]; sz = DFS[reg]; break;
        }
        if (!nm) return false;
        Operand mem; decodeModRM(r, p, sz, mem);
        insn.rawName = nm; addOp(insn, mem); return true;
    }
    r.u8();
    switch (op) {
        case 0xD8: { static const char* n[8] = {"fadd","fmul","fcom","fcomp","fsub","fsubr","fdiv","fdivr"}; insn.rawName = n[reg]; addOp(insn, st(0)); addOp(insn, st(rm)); return true; }
        case 0xDC: {
            if (reg == 2 || reg == 3) { insn.rawName = reg == 2 ? "fcom" : "fcomp"; addOp(insn, st(0)); addOp(insn, st(rm)); return true; }   // undocumented alias
            static const char* n[8] = {"fadd","fmul",nullptr,nullptr,"fsubr","fsub","fdivr","fdiv"};
            insn.rawName = n[reg]; addOp(insn, st(rm)); addOp(insn, st(0)); return true;
        }
        case 0xD9:
            if (m < 0xC8) { insn.rawName = "fld"; addOp(insn, st(rm)); return true; }
            if (m < 0xD0) { insn.rawName = "fxch"; addOp(insn, st(rm)); return true; }
            if (m >= 0xD8 && m < 0xE0) { insn.rawName = "fstpnce"; addOp(insn, st(rm)); return true; }   // undocumented alias
            switch (m) {
                case 0xD0: insn.rawName = "fnop"; return true;
                case 0xE0: insn.rawName = "fchs"; return true;
                case 0xE1: insn.rawName = "fabs"; return true;
                case 0xE4: insn.rawName = "ftst"; return true;
                case 0xE5: insn.rawName = "fxam"; return true;
                case 0xE8: insn.rawName = "fld1"; return true;
                case 0xE9: insn.rawName = "fldl2t"; return true;
                case 0xEA: insn.rawName = "fldl2e"; return true;
                case 0xEB: insn.rawName = "fldpi"; return true;
                case 0xEC: insn.rawName = "fldlg2"; return true;
                case 0xED: insn.rawName = "fldln2"; return true;
                case 0xEE: insn.rawName = "fldz"; return true;
                case 0xF0: insn.rawName = "f2xm1"; return true;
                case 0xF1: insn.rawName = "fyl2x"; return true;
                case 0xF2: insn.rawName = "fptan"; return true;
                case 0xF3: insn.rawName = "fpatan"; return true;
                case 0xF4: insn.rawName = "fxtract"; return true;
                case 0xF5: insn.rawName = "fprem1"; return true;
                case 0xF6: insn.rawName = "fdecstp"; return true;
                case 0xF7: insn.rawName = "fincstp"; return true;
                case 0xF8: insn.rawName = "fprem"; return true;
                case 0xF9: insn.rawName = "fyl2xp1"; return true;
                case 0xFA: insn.rawName = "fsqrt"; return true;
                case 0xFB: insn.rawName = "fsincos"; return true;
                case 0xFC: insn.rawName = "frndint"; return true;
                case 0xFD: insn.rawName = "fscale"; return true;
                case 0xFE: insn.rawName = "fsin"; return true;
                case 0xFF: insn.rawName = "fcos"; return true;
            }
            return false;
        case 0xDA:
            if (m < 0xC8) { insn.rawName = "fcmovb"; }
            else if (m < 0xD0) { insn.rawName = "fcmove"; }
            else if (m < 0xD8) { insn.rawName = "fcmovbe"; }
            else if (m < 0xE0) { insn.rawName = "fcmovu"; }
            else if (m == 0xE9) { insn.rawName = "fucompp"; return true; }
            else return false;
            addOp(insn, st(0)); addOp(insn, st(rm)); return true;
        case 0xDB:
            if (m < 0xC8) { insn.rawName = "fcmovnb"; addOp(insn, st(0)); addOp(insn, st(rm)); return true; }
            if (m < 0xD0) { insn.rawName = "fcmovne"; addOp(insn, st(0)); addOp(insn, st(rm)); return true; }
            if (m < 0xD8) { insn.rawName = "fcmovnbe"; addOp(insn, st(0)); addOp(insn, st(rm)); return true; }
            if (m < 0xE0) { insn.rawName = "fcmovnu"; addOp(insn, st(0)); addOp(insn, st(rm)); return true; }
            if (m == 0xE0) { insn.rawName = "fneni"; return true; }     // deprecated no-op
            if (m == 0xE1) { insn.rawName = "fndisi"; return true; }
            if (m == 0xE2) { insn.rawName = "fnclex"; return true; }
            if (m == 0xE3) { insn.rawName = "fninit"; return true; }
            if (m == 0xE4) { insn.rawName = "fnsetpm"; return true; }
            if (m >= 0xE8 && m < 0xF0) { insn.rawName = "fucomi"; addOp(insn, st(0)); addOp(insn, st(rm)); return true; }
            if (m >= 0xF0 && m < 0xF8) { insn.rawName = "fcomi"; addOp(insn, st(0)); addOp(insn, st(rm)); return true; }
            return false;
        case 0xDD:
            if (m < 0xC8) { insn.rawName = "ffree"; addOp(insn, st(rm)); return true; }
            if (m >= 0xC8 && m < 0xD0) { insn.rawName = "fxch"; addOp(insn, st(rm)); return true; }   // undocumented alias
            if (m >= 0xD0 && m < 0xD8) { insn.rawName = "fst"; addOp(insn, st(rm)); return true; }
            if (m >= 0xD8 && m < 0xE0) { insn.rawName = "fstp"; addOp(insn, st(rm)); return true; }
            if (m >= 0xE0 && m < 0xE8) { insn.rawName = "fucom"; addOp(insn, st(rm)); return true; }
            if (m >= 0xE8 && m < 0xF0) { insn.rawName = "fucomp"; addOp(insn, st(rm)); return true; }
            return false;
        case 0xDE:
            if (m >= 0xD0 && m < 0xD8) { insn.rawName = "fcomp"; addOp(insn, st(rm)); return true; }   // undocumented alias
            if (m < 0xC8) { insn.rawName = "faddp"; }
            else if (m < 0xD0) { insn.rawName = "fmulp"; }
            else if (m == 0xD9) { insn.rawName = "fcompp"; return true; }
            else if (m >= 0xE0 && m < 0xE8) { insn.rawName = "fsubrp"; }
            else if (m >= 0xE8 && m < 0xF0) { insn.rawName = "fsubp"; }
            else if (m >= 0xF0 && m < 0xF8) { insn.rawName = "fdivrp"; }
            else if (m >= 0xF8) { insn.rawName = "fdivp"; }
            else return false;
            addOp(insn, st(rm)); addOp(insn, st(0)); return true;
        case 0xDF:
            if (m < 0xC8) { insn.rawName = "ffreep"; addOp(insn, st(rm)); return true; }   // undocumented alias
            if (m >= 0xC8 && m < 0xD0) { insn.rawName = "fxch"; addOp(insn, st(rm)); return true; }
            if (m >= 0xD0 && m < 0xE0) { insn.rawName = "fstp"; addOp(insn, st(rm)); return true; }   // D0-D7 + D8-DF undocumented alias
            if (m == 0xE0) { insn.rawName = "fnstsw"; addOp(insn, regOp(makeGpr(0, 2, p.rex))); return true; }
            if (m >= 0xE8 && m < 0xF0) { insn.rawName = "fucomip"; addOp(insn, st(0)); addOp(insn, st(rm)); return true; }
            if (m >= 0xF0 && m < 0xF8) { insn.rawName = "fcomip"; addOp(insn, st(0)); addOp(insn, st(rm)); return true; }
            return false;
    }
    return false;
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
            int as = p.addrsize ? 4 : 8;   // moffs width follows the address size, not the operand size
            Operand mo; mo.kind = OperandKind::Mem; mo.sizeBytes = uint8_t(s);
            mo.mem.dispOffset = uint8_t(r.pos); mo.mem.dispSize = uint8_t(as);
            mo.mem.disp = as == 4 ? int64_t(uint32_t(r.imm(4))) : int64_t(r.u64());
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
        case 0xC6: {
            uint8_t mb = r.peek();
            if (((mb >> 3) & 7) == 7) { if (mb == 0xF8) { r.u8(); insn.rawName = "xabort"; addOp(insn, immOp(r, 1)); return true; } return false; }
            Operand e; int reg = decodeModRM(r, p, 1, e); if ((reg & 7) != 0) return false; insn.mnemonic = M::Mov; addOp(insn, e); addOp(insn, immOp(r, 1)); return true;
        }
        case 0xC7: {
            uint8_t mb = r.peek();
            if (((mb >> 3) & 7) == 7) { if (mb == 0xF8) { r.u8(); insn.rawName = "xbegin"; addOp(insn, relOp(r, SZz(p))); return true; } return false; }
            int s = SZv(p); Operand e; int reg = decodeModRM(r, p, s, e); if ((reg & 7) != 0) return false; insn.mnemonic = M::Mov; addOp(insn, e); addOp(insn, immOp(r, SZz(p))); return true;
        }
        case 0xC9: insn.mnemonic = M::Leave; return true;
        case 0xCC: insn.mnemonic = M::Int3; return true;
        case 0xCD: insn.mnemonic = M::Int; addOp(insn, immOp(r, 1)); return true;
        case 0xD0: { Operand e; int reg = decodeModRM(r, p, 1, e); insn.mnemonic = kGrp2[reg & 7]; addOp(insn, e); addOp(insn, oneOp()); return true; }
        case 0xD1: { int s = SZv(p); Operand e; int reg = decodeModRM(r, p, s, e); insn.mnemonic = kGrp2[reg & 7]; addOp(insn, e); addOp(insn, oneOp()); return true; }
        case 0xD2: { Operand e; int reg = decodeModRM(r, p, 1, e); insn.mnemonic = kGrp2[reg & 7]; addOp(insn, e); addOp(insn, clOp(p)); return true; }
        case 0xD3: { int s = SZv(p); Operand e; int reg = decodeModRM(r, p, s, e); insn.mnemonic = kGrp2[reg & 7]; addOp(insn, e); addOp(insn, clOp(p)); return true; }
        case 0xE8: insn.mnemonic = M::Call; addOp(insn, relOp(r, 4)); return true;   // near branch: rel32, 0x66 ignored in 64-bit
        case 0xE9: insn.mnemonic = M::Jmp; addOp(insn, relOp(r, 4)); return true;
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
                case 3: if (e.kind != OperandKind::Mem) return false; insn.rawName = "callf"; break;
                case 4: insn.mnemonic = M::Jmp; break;
                case 5: if (e.kind != OperandKind::Mem) return false; insn.rawName = "jmpf"; break;
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
        case 0x6C: insn.rawName = "insb"; return true;
        case 0x6D: insn.rawName = p.opsize ? "insw" : "insd"; return true;
        case 0x6E: insn.rawName = "outsb"; return true;
        case 0x6F: insn.rawName = p.opsize ? "outsw" : "outsd"; return true;
        case 0xE4: insn.rawName = "in"; addOp(insn, regOp(makeGpr(0, 1, p.rex))); addOp(insn, immOp(r, 1)); return true;
        case 0xE5: insn.rawName = "in"; addOp(insn, regOp(makeGpr(0, p.opsize ? 2 : 4, p.rex))); addOp(insn, immOp(r, 1)); return true;
        case 0xE6: insn.rawName = "out"; addOp(insn, immOp(r, 1)); addOp(insn, regOp(makeGpr(0, 1, p.rex))); return true;
        case 0xE7: insn.rawName = "out"; addOp(insn, immOp(r, 1)); addOp(insn, regOp(makeGpr(0, p.opsize ? 2 : 4, p.rex))); return true;
        case 0xEC: insn.rawName = "in"; addOp(insn, regOp(makeGpr(0, 1, p.rex))); addOp(insn, regOp(makeGpr(2, 2, p.rex))); return true;
        case 0xED: insn.rawName = "in"; addOp(insn, regOp(makeGpr(0, p.opsize ? 2 : 4, p.rex))); addOp(insn, regOp(makeGpr(2, 2, p.rex))); return true;
        case 0xEE: insn.rawName = "out"; addOp(insn, regOp(makeGpr(2, 2, p.rex))); addOp(insn, regOp(makeGpr(0, 1, p.rex))); return true;
        case 0xEF: insn.rawName = "out"; addOp(insn, regOp(makeGpr(2, 2, p.rex))); addOp(insn, regOp(makeGpr(0, p.opsize ? 2 : 4, p.rex))); return true;
        case 0xE0: insn.rawName = "loopne"; addOp(insn, relOp(r, 1)); return true;
        case 0xE1: insn.rawName = "loope"; addOp(insn, relOp(r, 1)); return true;
        case 0xE2: insn.rawName = "loop"; addOp(insn, relOp(r, 1)); return true;
        case 0xE3: insn.rawName = p.addrsize ? "jecxz" : "jrcxz"; addOp(insn, relOp(r, 1)); return true;
        case 0xC8: insn.rawName = "enter"; addOp(insn, immOp(r, 2)); addOp(insn, immOp(r, 1)); return true;
        case 0xCA: insn.rawName = "retf"; addOp(insn, immOp(r, 2)); return true;
        case 0xCB: insn.rawName = "retf"; return true;
        case 0xCF: insn.rawName = p.rexW ? "iretq" : (p.opsize ? "iret" : "iretd"); return true;
        case 0xD7: insn.rawName = "xlat"; return true;
        case 0x9B: insn.rawName = "fwait"; return true;
        case 0x9E: insn.rawName = "sahf"; return true;
        case 0x9F: insn.rawName = "lahf"; return true;
        case 0xF1: insn.rawName = "int1"; return true;
        case 0x8C: { Operand e; int reg = decodeModRM(r, p, 2, e); if ((reg & 7) > 5) return false; Operand s; s.kind = OperandKind::Reg; s.reg.cls = RegClass::Sreg; s.reg.idx = uint8_t(reg & 7); s.sizeBytes = 2; insn.mnemonic = M::Mov; addOp(insn, e); addOp(insn, s); return true; }
        case 0x8E: { Operand e; int reg = decodeModRM(r, p, 2, e); if ((reg & 7) > 5 || (reg & 7) == 1) return false; Operand s; s.kind = OperandKind::Reg; s.reg.cls = RegClass::Sreg; s.reg.idx = uint8_t(reg & 7); s.sizeBytes = 2; insn.mnemonic = M::Mov; addOp(insn, s); addOp(insn, e); return true; }
        default: return false;
    }
    return false;
}

bool decodeVex(Reader& r, Instruction& insn) {
    const Prefixes& p = insn.prefixes;
    if (p.vexMap < 1 || p.vexMap > 3) return false;
    uint8_t op = r.u8();
    const int pp = p.vexPP;            // 0 none 1=66 2=F3 3=F2
    const RegClass vc = p.vexL ? RegClass::Ymm : RegClass::Xmm;
    const int vsz = p.vexL ? 32 : 16;
    auto vreg = [&](int idx) { Operand o; o.kind = OperandKind::Reg; o.reg.cls = vc; o.reg.idx = uint8_t(idx); o.sizeBytes = uint8_t(vsz); return o; };
    auto rmVec = [&](int memSz, Operand& rm) { int reg = decodeModRM(r, p, memSz, rm, vc); if (rm.kind == OperandKind::Reg) rm.sizeBytes = uint8_t(vsz); return reg; };
    auto three = [&](M base, int memSz) { Operand rm; int reg = rmVec(memSz, rm); insn.mnemonic = base; addOp(insn, vreg(reg)); addOp(insn, vreg(p.vexVVVV)); addOp(insn, rm); };
    auto two = [&](M m, int memSz, bool store) { Operand rm; int reg = rmVec(memSz, rm); insn.mnemonic = m; if (store) { addOp(insn, rm); addOp(insn, vreg(reg)); } else { addOp(insn, vreg(reg)); addOp(insn, rm); } };
    auto twoImm = [&](M m, int memSz) { Operand rm; int reg = rmVec(memSz, rm); insn.mnemonic = m; addOp(insn, vreg(reg)); addOp(insn, rm); addOp(insn, immOp(r, 1)); };
    auto threeImm = [&](M m, int memSz) { Operand rm; int reg = rmVec(memSz, rm); insn.mnemonic = m; addOp(insn, vreg(reg)); addOp(insn, vreg(p.vexVVVV)); addOp(insn, rm); addOp(insn, immOp(r, 1)); };
    auto gprDst = [&](M m, int memSz, int gsz) { Operand rm; int reg = rmVec(memSz, rm); insn.mnemonic = m; addOp(insn, regOp(makeGpr(reg, gsz, p.rex))); addOp(insn, rm); };
    auto twoRaw = [&](const char* nm) { Operand rm; int reg = rmVec(vsz, rm); insn.rawName = nm; addOp(insn, vreg(reg)); addOp(insn, rm); };
    auto threeRaw = [&](const char* nm) { Operand rm; int reg = rmVec(vsz, rm); insn.rawName = nm; addOp(insn, vreg(reg)); addOp(insn, vreg(p.vexVVVV)); addOp(insn, rm); };
    auto twoRawImm = [&](const char* nm) { Operand rm; int reg = rmVec(vsz, rm); insn.rawName = nm; addOp(insn, vreg(reg)); addOp(insn, rm); addOp(insn, immOp(r, 1)); };
    auto threeRawImm = [&](const char* nm) { Operand rm; int reg = rmVec(vsz, rm); insn.rawName = nm; addOp(insn, vreg(reg)); addOp(insn, vreg(p.vexVVVV)); addOp(insn, rm); addOp(insn, immOp(r, 1)); };
    const int sc = (pp == 2) ? 4 : (pp == 3) ? 8 : vsz;   // scalar/packed mem size

    if (p.vexMap == 2) {                               // VEX 0F38
        if (pp != 1) return false;
        if (op == 0x17) { twoRaw("ptest"); return true; }
        if (op == 0x41) { twoRaw("phminposuw"); return true; }
        if (op >= 0x1C && op <= 0x1E) { static const char* n[] = {"pabsb","pabsw","pabsd"}; twoRaw(n[op - 0x1C]); return true; }
        if ((op >= 0x20 && op <= 0x25) || (op >= 0x30 && op <= 0x35)) {
            static const char* nz[] = {"pmovzxbw","pmovzxbd","pmovzxbq","pmovzxwd","pmovzxwq","pmovzxdq"};
            static const char* ns[] = {"pmovsxbw","pmovsxbd","pmovsxbq","pmovsxwd","pmovsxwq","pmovsxdq"};
            twoRaw((op >= 0x30 ? nz : ns)[op & 0x0F]); return true;
        }
        static const struct { uint8_t o; const char* n; } t[] = {
            {0x00,"pshufb"},{0x01,"phaddw"},{0x02,"phaddd"},{0x03,"phaddsw"},{0x04,"pmaddubsw"},{0x05,"phsubw"},
            {0x06,"phsubd"},{0x07,"phsubsw"},{0x08,"psignb"},{0x09,"psignw"},{0x0A,"psignd"},{0x0B,"pmulhrsw"},
            {0x28,"pmuldq"},{0x29,"pcmpeqq"},{0x2B,"packusdw"},{0x37,"pcmpgtq"},{0x38,"pminsb"},{0x39,"pminsd"},
            {0x3A,"pminuw"},{0x3B,"pminud"},{0x3C,"pmaxsb"},{0x3D,"pmaxsd"},{0x3E,"pmaxuw"},{0x3F,"pmaxud"},{0x40,"pmulld"},
        };
        for (auto& e : t) if (e.o == op) { threeRaw(e.n); return true; }
        return false;
    }
    if (p.vexMap == 3) {                               // VEX 0F3A
        if (pp != 1) return false;
        if (op == 0x08) { twoRawImm("roundps"); return true; }
        if (op == 0x09) { twoRawImm("roundpd"); return true; }
        if (op >= 0x60 && op <= 0x63) { static const char* n[] = {"pcmpestrm","pcmpestri","pcmpistrm","pcmpistri"}; twoRawImm(n[op - 0x60]); return true; }
        static const struct { uint8_t o; const char* n; } t[] = {
            {0x0A,"roundss"},{0x0B,"roundsd"},{0x0C,"blendps"},{0x0D,"blendpd"},{0x0E,"pblendw"},{0x0F,"palignr"},
            {0x21,"insertps"},{0x40,"dpps"},{0x41,"dppd"},{0x42,"mpsadbw"},{0x44,"pclmulqdq"},
        };
        for (auto& e : t) if (e.o == op) { threeRawImm(e.n); return true; }
        return false;
    }

    if (pp == 1) { const char* nm = findSse(kPackedInt, kPackedIntN, op); if (nm) { threeRaw(nm); return true; } }
    if (pp == 1 && (op == 0x71 || op == 0x72 || op == 0x73)) {
        int reg = (r.peek() >> 3) & 7; const char* nm = pshiftName(op, reg); if (!nm) return false;
        Operand rm; rmVec(vsz, rm); insn.rawName = nm; addOp(insn, vreg(p.vexVVVV)); addOp(insn, rm); addOp(insn, immOp(r, 1)); return true;
    }
    switch (op) {
        case 0x10: case 0x11: { if (pp < 2 && p.vexVVVV) return false; M m = pp == 0 ? M::Movups : pp == 1 ? M::Movupd : pp == 2 ? M::Movss : M::Movsd; two(m, sc, op == 0x11); return true; }
        case 0x28: case 0x29: if (pp >= 2 || p.vexVVVV) return false; two(pp == 1 ? M::Movapd : M::Movaps, vsz, op == 0x29); return true;
        case 0x6F: case 0x7F: if ((pp != 1 && pp != 2) || p.vexVVVV) return false; two(pp == 1 ? M::Movdqa : M::Movdqu, vsz, op == 0x7F); return true;
        case 0x54: if (pp >= 2) return false; three(M(int(M::Andps) + pp), vsz); return true;
        case 0x55: if (pp >= 2) return false; three(M(int(M::Andnps) + pp), vsz); return true;
        case 0x56: if (pp >= 2) return false; three(M(int(M::Orps) + pp), vsz); return true;
        case 0x57: if (pp >= 2) return false; three(pp == 1 ? M::Xorpd : M::Xorps, vsz); return true;
        case 0xDB: if (pp != 1) return false; three(M::Pand, vsz); return true;
        case 0xDF: if (pp != 1) return false; three(M::Pandn, vsz); return true;
        case 0xEB: if (pp != 1) return false; three(M::Por, vsz); return true;
        case 0xEF: if (pp != 1) return false; three(M::Pxor, vsz); return true;
        case 0x58: three(M(int(M::Addps) + pp), sc); return true;
        case 0x59: three(M(int(M::Mulps) + pp), sc); return true;
        case 0x5C: three(M(int(M::Subps) + pp), sc); return true;
        case 0x5E: three(M(int(M::Divps) + pp), sc); return true;
        case 0x2E: if (pp >= 2 || p.vexVVVV) return false; two(M(int(M::Ucomiss) + pp), pp == 1 ? 8 : 4, false); return true;
        case 0x2F: if (pp >= 2 || p.vexVVVV) return false; two(M(int(M::Comiss) + pp), pp == 1 ? 8 : 4, false); return true;
        case 0x6E: { if (pp != 1 || p.vexVVVV) return false; int gs = p.rexW ? 8 : 4; Operand rm; int reg = decodeModRM(r, p, gs, rm); insn.mnemonic = p.rexW ? M::Movq : M::Movd; addOp(insn, vreg(reg)); addOp(insn, rm); return true; }
        case 0x7E: {
            if (p.vexVVVV) return false;
            if (pp == 2) { two(M::Movq, 8, false); return true; }
            if (pp == 1) { int gs = p.rexW ? 8 : 4; Operand rm; int reg = decodeModRM(r, p, gs, rm); insn.mnemonic = p.rexW ? M::Movq : M::Movd; addOp(insn, rm); addOp(insn, vreg(reg)); return true; }
            return false;
        }
        case 0x14: if (pp >= 2) return false; three(pp == 1 ? M::Unpcklpd : M::Unpcklps, vsz); return true;
        case 0x15: if (pp >= 2) return false; three(pp == 1 ? M::Unpckhpd : M::Unpckhps, vsz); return true;
        case 0x50: if (pp >= 2 || p.vexVVVV) return false; gprDst(pp == 1 ? M::Movmskpd : M::Movmskps, vsz, 4); return true;
        case 0xD7: if (pp != 1 || p.vexVVVV) return false; gprDst(M::Pmovmskb, vsz, 4); return true;
        case 0x70: if (pp == 0 || p.vexVVVV) return false; twoImm(pp == 1 ? M::Pshufd : pp == 2 ? M::Pshufhw : M::Pshuflw, vsz); return true;
        case 0xC6: if (pp >= 2) return false; threeImm(pp == 1 ? M::Shufpd : M::Shufps, vsz); return true;
        case 0x51: if (pp >= 2) { threeRaw(pp == 2 ? "vsqrtss" : "vsqrtsd"); } else { if (p.vexVVVV) return false; twoRaw(pp == 1 ? "vsqrtpd" : "vsqrtps"); } return true;
        case 0x52: if (pp == 1 || pp == 3) return false; if (pp == 2) { threeRaw("vrsqrtss"); } else { if (p.vexVVVV) return false; twoRaw("vrsqrtps"); } return true;
        case 0x53: if (pp == 1 || pp == 3) return false; if (pp == 2) { threeRaw("vrcpss"); } else { if (p.vexVVVV) return false; twoRaw("vrcpps"); } return true;
        case 0x5D: three(M(int(M::Minps) + pp), sc); return true;
        case 0x5F: three(M(int(M::Maxps) + pp), sc); return true;
        case 0xC2: threeImm(M(int(M::Cmpps) + pp), sc); return true;
        case 0x5B: if (pp == 3 || p.vexVVVV) return false; two(pp == 0 ? M::Cvtdq2ps : pp == 1 ? M::Cvtps2dq : M::Cvttps2dq, vsz, false); return true;
        case 0x5A: if (pp >= 2) three(pp == 2 ? M::Cvtss2sd : M::Cvtsd2ss, sc); else { if (p.vexVVVV) return false; two(pp == 1 ? M::Cvtpd2ps : M::Cvtps2pd, vsz, false); } return true;
        case 0x2A: { if (pp != 2 && pp != 3) return false; int gs = p.rexW ? 8 : 4; Operand rm; int reg = decodeModRM(r, p, gs, rm); insn.mnemonic = pp == 2 ? M::Cvtsi2ss : M::Cvtsi2sd; addOp(insn, vreg(reg)); addOp(insn, vreg(p.vexVVVV)); addOp(insn, rm); return true; }
        case 0x2C: case 0x2D: { if ((pp != 2 && pp != 3) || p.vexVVVV) return false; int ms = pp == 2 ? 4 : 8; int gs = p.rexW ? 8 : 4; bool tr = op == 0x2C; gprDst(tr ? (pp == 2 ? M::Cvttss2si : M::Cvttsd2si) : (pp == 2 ? M::Cvtss2si : M::Cvtsd2si), ms, gs); return true; }
        case 0xFC: if (pp != 1) return false; three(M::Paddb, vsz); return true;
        case 0xFD: if (pp != 1) return false; three(M::Paddw, vsz); return true;
        case 0xFE: if (pp != 1) return false; three(M::Paddd, vsz); return true;
        case 0xD4: if (pp != 1) return false; three(M::Paddq, vsz); return true;
        case 0xF8: if (pp != 1) return false; three(M::Psubb, vsz); return true;
        case 0xF9: if (pp != 1) return false; three(M::Psubw, vsz); return true;
        case 0xFA: if (pp != 1) return false; three(M::Psubd, vsz); return true;
        case 0xFB: if (pp != 1) return false; three(M::Psubq, vsz); return true;
        case 0x74: if (pp != 1) return false; three(M::Pcmpeqb, vsz); return true;
        case 0x75: if (pp != 1) return false; three(M::Pcmpeqw, vsz); return true;
        case 0x76: if (pp != 1) return false; three(M::Pcmpeqd, vsz); return true;
        case 0x64: if (pp != 1) return false; three(M::Pcmpgtb, vsz); return true;
        case 0x65: if (pp != 1) return false; three(M::Pcmpgtw, vsz); return true;
        case 0x66: if (pp != 1) return false; three(M::Pcmpgtd, vsz); return true;
        case 0x7C: if (pp != 1 && pp != 3) return false; threeRaw(pp == 1 ? "vhaddpd" : "vhaddps"); return true;
        case 0x7D: if (pp != 1 && pp != 3) return false; threeRaw(pp == 1 ? "vhsubpd" : "vhsubps"); return true;
        case 0xD0: if (pp != 1 && pp != 3) return false; threeRaw(pp == 1 ? "vaddsubpd" : "vaddsubps"); return true;
        default: return false;
    }
}

uint8_t ccFlags(uint8_t cc) {
    switch (cc & 0xE) {
        case 0x0: return EF_OF;
        case 0x2: return EF_CF;
        case 0x4: return EF_ZF;
        case 0x6: return EF_CF | EF_ZF;
        case 0x8: return EF_SF;
        case 0xA: return EF_PF;
        case 0xC: return EF_SF | EF_OF;
        case 0xE: return EF_ZF | EF_SF | EF_OF;
    }
    return 0;
}

void setFlags(Instruction& in) {
    const uint8_t ARITH = EF_CF | EF_PF | EF_AF | EF_ZF | EF_SF | EF_OF;
    switch (in.mnemonic) {
        case M::Add: case M::Sub: case M::Cmp: case M::Neg: in.flagsWritten = ARITH; break;
        case M::Adc: case M::Sbb: in.flagsWritten = ARITH; in.flagsRead = EF_CF; break;
        case M::And: case M::Or: case M::Xor: case M::Test: in.flagsWritten = EF_CF | EF_OF | EF_PF | EF_ZF | EF_SF; break;
        case M::Inc: case M::Dec: in.flagsWritten = EF_PF | EF_AF | EF_ZF | EF_SF | EF_OF; break;
        case M::Shl: case M::Shr: case M::Sar: case M::Rol: case M::Ror: case M::Rcl: case M::Rcr: in.flagsWritten = EF_CF | EF_OF | EF_PF | EF_ZF | EF_SF; break;
        case M::Imul: case M::Mul: case M::Idiv: case M::Div: in.flagsWritten = EF_CF | EF_OF; break;
        case M::Jcc: case M::Setcc: case M::Cmovcc: in.flagsRead = ccFlags(in.cc); break;
        case M::Cmc: case M::Clc: case M::Stc: in.flagsWritten = EF_CF; break;
        case M::Cld: case M::Std: in.flagsWritten = EF_DF; break;
        case M::Bt: case M::Bts: case M::Btr: case M::Btc: in.flagsWritten = EF_CF; break;
        case M::Ucomiss: case M::Ucomisd: case M::Comiss: case M::Comisd: in.flagsWritten = EF_ZF | EF_PF | EF_CF; break;
        default: break;
    }
    if (in.rawName) {
        const char* r = in.rawName;
        if (!std::strcmp(r, "bsf") || !std::strcmp(r, "bsr") || !std::strcmp(r, "popcnt") || !std::strcmp(r, "tzcnt") || !std::strcmp(r, "lzcnt")) in.flagsWritten = EF_ZF | EF_CF | EF_PF | EF_SF | EF_OF;
        else if (!std::strcmp(r, "ptest")) in.flagsWritten = EF_ZF | EF_CF;
    }
}

bool lockLegal(const Instruction& in) {   // LOCK needs a memory destination and a lockable op
    if (in.operandCount == 0 || in.operands[0].kind != OperandKind::Mem) return false;
    switch (in.mnemonic) {
        case M::Add: case M::Adc: case M::And: case M::Or: case M::Sbb: case M::Sub: case M::Xor:
        case M::Inc: case M::Dec: case M::Neg: case M::Not: case M::Xadd: case M::Xchg:
        case M::Cmpxchg: case M::Bts: case M::Btr: case M::Btc:
            return true;
        default: break;
    }
    if (in.rawName && (!std::strcmp(in.rawName, "cmpxchg16b") || !std::strcmp(in.rawName, "cmpxchg8b"))) return true;
    return false;
}

void finalize(Reader& r, Instruction& insn) {
    insn.length = uint8_t(r.pos > 255 ? 255 : r.pos);
    for (int i = 0; i < insn.operandCount; ++i) {
        Operand& o = insn.operands[i];
        if (o.kind == OperandKind::Rel) { o.relTarget = insn.address + insn.length + uint64_t(o.imm); insn.positionDependent = true; }
        else if (o.kind == OperandKind::Mem && o.mem.ripRelative) { o.mem.ripTarget = insn.address + insn.length + uint64_t(o.mem.disp); insn.positionDependent = true; }
    }
    setFlags(insn);
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

    bool handled;
    if (insn.prefixes.vex) handled = decodeVex(r, insn);
    else { uint8_t op = r.u8(); handled = (op == 0x0F) ? decode0F(r, insn) : (op >= 0xD8 && op <= 0xDF) ? decodeX87(r, insn, op) : decodeOne(r, insn, op); }

    if (r.overflow) { res.status = DecodeStatus::Truncated; return res; }
    if (!handled || (insn.mnemonic == M::Invalid && insn.rawName == nullptr)) { insn.length = uint8_t(r.pos); res.status = DecodeStatus::Invalid; return res; }
    if (insn.prefixes.lock && !lockLegal(insn)) { insn.length = uint8_t(r.pos); res.status = DecodeStatus::Invalid; return res; }

    finalize(r, insn);
    res.status = DecodeStatus::Ok;
    return res;
}

} // namespace disasm64
