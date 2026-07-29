#include "disasm64/disasm64.h"
#include "fmt.h"
#include <string>
#include <cstdio>

namespace disasm64 {
namespace {

const char* kGpr64[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
const char* kGpr32[16] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
const char* kGpr16[16] = {"ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
const char* kGpr8[16]  = {"al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
const char* kGpr8Hi[8] = {"al","cl","dl","bl","ah","ch","dh","bh"};
const char* kSeg[6]    = {"es","cs","ss","ds","fs","gs"};
const char* kCC[16]    = {"o","no","b","ae","e","ne","be","a","s","ns","p","np","l","ge","le","g"};

std::string hex(uint64_t v) {
    char b[19]; std::snprintf(b, sizeof b, "0x%llx", (unsigned long long)v); return b;
}

std::string regName(const Reg& r) {
    switch (r.cls) {
        case RegClass::Gpr64: return kGpr64[r.idx & 15];
        case RegClass::Gpr32: return kGpr32[r.idx & 15];
        case RegClass::Gpr16: return kGpr16[r.idx & 15];
        case RegClass::Gpr8:  return kGpr8[r.idx & 15];
        case RegClass::Gpr8Hi: return kGpr8Hi[r.idx & 7];
        case RegClass::Xmm:   return "xmm" + std::to_string(r.idx);
        case RegClass::Ymm:   return "ymm" + std::to_string(r.idx);
        case RegClass::Rip:   return "rip";
        default: return "?";
    }
}

const char* ptrKind(uint8_t sz) {
    switch (sz) {
        case 1: return "byte ptr ";
        case 2: return "word ptr ";
        case 4: return "dword ptr ";
        case 8: return "qword ptr ";
        case 16: return "xmmword ptr ";
        case 32: return "ymmword ptr ";
        default: return "";
    }
}

std::string memStr(const MemOperand& m, uint8_t sizeBytes) {
    std::string s = ptrKind(sizeBytes);
    if (m.segment != 0xFF && m.segment < 6) s += std::string(kSeg[m.segment]) + ":";
    s += "[";
    bool has = false;
    if (m.ripRelative) { s += "rip"; has = true; }
    else if (m.base.cls != RegClass::None) { s += regName(m.base); has = true; }
    if (m.index.cls != RegClass::None) {
        if (has) s += "+";
        s += regName(m.index);
        if (m.scale != 1) s += "*" + std::to_string(m.scale);
        has = true;
    }
    if (m.disp != 0 || !has || m.ripRelative) {
        if (has) s += (m.disp < 0 ? "-" : "+");
        int64_t d = m.disp;
        s += hex(uint64_t(has && d < 0 ? -d : d));
    }
    s += "]";
    return s;
}

std::string operandStr(const Operand& o) {
    switch (o.kind) {
        case OperandKind::Reg: return regName(o.reg);
        case OperandKind::Mem: return memStr(o.mem, o.sizeBytes);
        case OperandKind::Imm: {
            uint64_t mask = (o.sizeBytes == 0 || o.sizeBytes >= 8) ? ~0ull : ((1ull << (8 * o.sizeBytes)) - 1);
            return hex(uint64_t(o.imm) & mask);
        }
        case OperandKind::Rel: return hex(o.relTarget);
        default: return "";
    }
}

std::string mnemStr(const Instruction& insn) {
    if (insn.rawName) return insn.rawName;
    switch (insn.mnemonic) {
        case Mnemonic::Add: return "add";   case Mnemonic::Or: return "or";    case Mnemonic::Adc: return "adc";
        case Mnemonic::Sbb: return "sbb";   case Mnemonic::And: return "and";  case Mnemonic::Sub: return "sub";
        case Mnemonic::Xor: return "xor";   case Mnemonic::Cmp: return "cmp";  case Mnemonic::Push: return "push";
        case Mnemonic::Pop: return "pop";   case Mnemonic::Mov: return "mov";  case Mnemonic::Lea: return "lea";
        case Mnemonic::Nop: return "nop";   case Mnemonic::Xchg: return "xchg";case Mnemonic::Test: return "test";
        case Mnemonic::Inc: return "inc";   case Mnemonic::Dec: return "dec";  case Mnemonic::Neg: return "neg";
        case Mnemonic::Not: return "not";   case Mnemonic::Mul: return "mul";  case Mnemonic::Imul: return "imul";
        case Mnemonic::Div: return "div";   case Mnemonic::Idiv: return "idiv";case Mnemonic::Shl: return "shl";
        case Mnemonic::Shr: return "shr";   case Mnemonic::Sar: return "sar";  case Mnemonic::Rol: return "rol";
        case Mnemonic::Ror: return "ror";   case Mnemonic::Rcl: return "rcl";  case Mnemonic::Rcr: return "rcr";
        case Mnemonic::Movzx: return "movzx"; case Mnemonic::Movsx: return "movsx"; case Mnemonic::Movsxd: return "movsxd";
        case Mnemonic::Cwde: return "cwde"; case Mnemonic::Cdqe: return "cdqe";case Mnemonic::Cdq: return "cdq";
        case Mnemonic::Cqo: return "cqo";   case Mnemonic::Jmp: return "jmp";  case Mnemonic::Call: return "call";
        case Mnemonic::Ret: return "ret";   case Mnemonic::Leave: return "leave"; case Mnemonic::Int3: return "int3";
        case Mnemonic::Int: return "int";   case Mnemonic::Hlt: return "hlt";  case Mnemonic::Cpuid: return "cpuid";
        case Mnemonic::Rdtsc: return "rdtsc";
        case Mnemonic::Jcc: return std::string("j") + kCC[insn.cc & 15];
        case Mnemonic::Setcc: return std::string("set") + kCC[insn.cc & 15];
        case Mnemonic::Cmovcc: return std::string("cmov") + kCC[insn.cc & 15];
        case Mnemonic::Syscall: return "syscall"; case Mnemonic::Ud2: return "ud2";
        case Mnemonic::Cmc: return "cmc"; case Mnemonic::Clc: return "clc"; case Mnemonic::Stc: return "stc";
        case Mnemonic::Cld: return "cld"; case Mnemonic::Std: return "std"; case Mnemonic::Cli: return "cli";
        case Mnemonic::Sti: return "sti"; case Mnemonic::Pushf: return "pushf"; case Mnemonic::Popf: return "popf";
        case Mnemonic::Bswap: return "bswap"; case Mnemonic::Xadd: return "xadd"; case Mnemonic::Cmpxchg: return "cmpxchg";
        case Mnemonic::Bt: return "bt"; case Mnemonic::Bts: return "bts"; case Mnemonic::Btr: return "btr"; case Mnemonic::Btc: return "btc";
        case Mnemonic::Endbr64: return "endbr64"; case Mnemonic::Endbr32: return "endbr32";
        case Mnemonic::Movs: case Mnemonic::Stos: case Mnemonic::Lods: case Mnemonic::Scas: case Mnemonic::Cmps: {
            const char* base = insn.mnemonic == Mnemonic::Movs ? "movs" : insn.mnemonic == Mnemonic::Stos ? "stos" :
                               insn.mnemonic == Mnemonic::Lods ? "lods" : insn.mnemonic == Mnemonic::Scas ? "scas" : "cmps";
            const char* sfx = insn.suffix == 1 ? "b" : insn.suffix == 2 ? "w" : insn.suffix == 8 ? "q" : "d";
            return std::string(base) + sfx;
        }
        case Mnemonic::Movups: return "movups"; case Mnemonic::Movupd: return "movupd";
        case Mnemonic::Movss: return "movss"; case Mnemonic::Movsd: return "movsd";
        case Mnemonic::Movaps: return "movaps"; case Mnemonic::Movapd: return "movapd";
        case Mnemonic::Movdqa: return "movdqa"; case Mnemonic::Movdqu: return "movdqu";
        case Mnemonic::Movd: return "movd"; case Mnemonic::Movq: return "movq";
        case Mnemonic::Pxor: return "pxor"; case Mnemonic::Xorps: return "xorps"; case Mnemonic::Xorpd: return "xorpd";
        case Mnemonic::Andps: return "andps"; case Mnemonic::Andpd: return "andpd"; case Mnemonic::Andnps: return "andnps";
        case Mnemonic::Andnpd: return "andnpd"; case Mnemonic::Orps: return "orps"; case Mnemonic::Orpd: return "orpd";
        case Mnemonic::Pand: return "pand"; case Mnemonic::Por: return "por"; case Mnemonic::Pandn: return "pandn";
        default: {
            Mnemonic m = insn.mnemonic;
            if (m >= Mnemonic::Addps && m <= Mnemonic::Sqrtsd) {
                static const char* base[] = {"add", "mul", "sub", "div", "sqrt"};
                static const char* sfx[]  = {"ps", "pd", "ss", "sd"};
                int i = int(m) - int(Mnemonic::Addps);
                return std::string(base[i / 4]) + sfx[i % 4];
            }
            if (m >= Mnemonic::Ucomiss && m <= Mnemonic::Comisd) {
                static const char* n[] = {"ucomiss", "ucomisd", "comiss", "comisd"};
                return n[int(m) - int(Mnemonic::Ucomiss)];
            }
            if (m >= Mnemonic::Cvtsi2ss && m <= Mnemonic::Cvttps2dq) {
                static const char* n[] = {"cvtsi2ss", "cvtsi2sd", "cvttss2si", "cvttsd2si", "cvtss2si", "cvtsd2si",
                                          "cvtss2sd", "cvtsd2ss", "cvtps2pd", "cvtpd2ps", "cvtdq2ps", "cvtps2dq", "cvttps2dq"};
                return n[int(m) - int(Mnemonic::Cvtsi2ss)];
            }
            if (m >= Mnemonic::Paddb && m <= Mnemonic::Pcmpgtd) {
                static const char* n[] = {"paddb", "paddw", "paddd", "paddq", "psubb", "psubw", "psubd", "psubq",
                                          "pcmpeqb", "pcmpeqw", "pcmpeqd", "pcmpgtb", "pcmpgtw", "pcmpgtd"};
                return n[int(m) - int(Mnemonic::Paddb)];
            }
            if (m >= Mnemonic::Pshufd && m <= Mnemonic::Unpckhpd) {
                static const char* n[] = {"pshufd", "pshuflw", "pshufhw", "shufps", "shufpd", "movmskps", "movmskpd",
                                          "pmovmskb", "unpcklps", "unpcklpd", "unpckhps", "unpckhpd"};
                return n[int(m) - int(Mnemonic::Pshufd)];
            }
            if (m >= Mnemonic::Minps && m <= Mnemonic::Maxsd) {
                static const char* base[] = {"min", "max"};
                static const char* sfx[] = {"ps", "pd", "ss", "sd"};
                int i = int(m) - int(Mnemonic::Minps);
                return std::string(base[i / 4]) + sfx[i % 4];
            }
            if (m >= Mnemonic::Cmpps && m <= Mnemonic::Cmpsd) {
                static const char* n[] = {"cmpps", "cmppd", "cmpss", "cmpsd"};
                return n[int(m) - int(Mnemonic::Cmpps)];
            }
            return "(bad)";
        }
    }
}

} // namespace

std::string formatIntel(const Instruction& insn) {
    std::string s;
    if (insn.prefixes.lock) s += "lock ";
    const Mnemonic m = insn.mnemonic;   // rep/repne only prints on string ops (F3/F2 are mandatory on SSE)
    const bool strOp = m == Mnemonic::Movs || m == Mnemonic::Stos || m == Mnemonic::Lods ||
                       m == Mnemonic::Scas || m == Mnemonic::Cmps;
    if (strOp && insn.prefixes.rep == 0xF3) s += "rep ";
    else if (strOp && insn.prefixes.rep == 0xF2) s += "repne ";
    if (insn.prefixes.vex) s += "v";
    s += mnemStr(insn);
    for (int i = 0; i < insn.operandCount; ++i) {
        s += (i == 0) ? " " : ", ";
        s += operandStr(insn.operands[i]);
    }
    return s;
}

std::string mnemonicName(const Instruction& insn) { return mnemStr(insn); }
std::string registerName(const Reg& reg) { return regName(reg); }

} // namespace disasm64
