#pragma once
#include <cstdint>
#include <cstddef>

namespace disasm64 {

enum class RegClass : uint8_t {
    None, Gpr8, Gpr8Hi, Gpr16, Gpr32, Gpr64, Xmm, Ymm, Sreg, Rip, St
};

struct Reg {
    RegClass cls = RegClass::None;
    uint8_t idx = 0;
    bool valid() const { return cls != RegClass::None; }
};

enum class OperandKind : uint8_t { None, Reg, Mem, Imm, Rel };

struct MemOperand {
    Reg base;
    Reg index;
    uint8_t scale = 1;        // 1,2,4,8
    int64_t disp = 0;
    bool ripRelative = false;
    uint8_t segment = 0xFF;   // 0xFF none; else Sreg index
    uint64_t ripTarget = 0;
    uint8_t dispOffset = 0;   // disp field offset within the instruction
    uint8_t dispSize = 0;     // encoded disp width: 0, 1, 4
};

struct Operand {
    OperandKind kind = OperandKind::None;
    uint8_t sizeBytes = 0;    // 1,2,4,8,16,32; 0 = n/a
    Reg reg;
    MemOperand mem;
    int64_t imm = 0;
    bool immSigned = true;
    uint64_t relTarget = 0;
    uint8_t relSize = 0;      // 1 or 4
};

struct Prefixes {
    bool lock = false;
    uint8_t rep = 0;          // 0, 0xF2, 0xF3
    uint8_t segment = 0xFF;   // 0xFF none; else ES CS SS DS FS GS = 0..5
    bool opsize = false;      // 0x66
    bool addrsize = false;    // 0x67
    bool rex = false;
    bool rexW = false, rexR = false, rexX = false, rexB = false;
    bool vex = false;
    uint8_t vexMap = 0;       // 1=0F 2=0F38 3=0F3A
    uint8_t vexPP = 0;        // 0=none 1=66 2=F3 3=F2
    uint8_t vexVVVV = 0;
    bool vexL = false;        // 0=xmm 1=ymm
    bool vexW = false;
};

enum class Mnemonic : uint16_t {
    Invalid = 0,
    Add, Or, Adc, Sbb, And, Sub, Xor, Cmp,
    Push, Pop, Mov, Lea, Nop, Xchg, Test,
    Inc, Dec, Neg, Not, Mul, Imul, Div, Idiv,
    Shl, Shr, Sar, Rol, Ror, Rcl, Rcr,
    Movzx, Movsx, Movsxd, Cwde, Cdqe, Cdq, Cqo,
    Jmp, Jcc, Call, Ret, Leave, Int3, Int, Hlt, Cpuid, Rdtsc,
    Setcc, Cmovcc,
    Syscall, Ud2, Cmc, Clc, Stc, Cld, Std, Cli, Sti, Pushf, Popf,
    Movs, Stos, Lods, Scas, Cmps,
    Bswap, Xadd, Cmpxchg, Bt, Bts, Btr, Btc, Endbr64, Endbr32,
    Movups, Movupd, Movss, Movsd, Movaps, Movapd, Movdqa, Movdqu,
    Movd, Movq, Pxor, Xorps, Xorpd,
    Andps, Andpd, Andnps, Andnpd, Orps, Orpd, Pand, Por, Pandn,
    // ps,pd,ss,sd per op -> mnemonic = base + pp
    Addps, Addpd, Addss, Addsd, Mulps, Mulpd, Mulss, Mulsd,
    Subps, Subpd, Subss, Subsd, Divps, Divpd, Divss, Divsd,
    Sqrtps, Sqrtpd, Sqrtss, Sqrtsd, Ucomiss, Ucomisd, Comiss, Comisd,
    Cvtsi2ss, Cvtsi2sd, Cvttss2si, Cvttsd2si, Cvtss2si, Cvtsd2si,
    Cvtss2sd, Cvtsd2ss, Cvtps2pd, Cvtpd2ps, Cvtdq2ps, Cvtps2dq, Cvttps2dq,
    Paddb, Paddw, Paddd, Paddq, Psubb, Psubw, Psubd, Psubq,
    Pcmpeqb, Pcmpeqw, Pcmpeqd, Pcmpgtb, Pcmpgtw, Pcmpgtd,
    Pshufd, Pshuflw, Pshufhw, Shufps, Shufpd, Movmskps, Movmskpd, Pmovmskb,
    Unpcklps, Unpcklpd, Unpckhps, Unpckhpd,
    Minps, Minpd, Minss, Minsd, Maxps, Maxpd, Maxss, Maxsd,
    Cmpps, Cmppd, Cmpss, Cmpsd,
    Count
};

enum EFlag : uint8_t { EF_CF = 1, EF_PF = 2, EF_AF = 4, EF_ZF = 8, EF_SF = 16, EF_OF = 32, EF_DF = 64 };

enum class DecodeStatus : uint8_t { Ok, Invalid, Truncated };

struct Instruction {
    uint64_t address = 0;
    uint8_t length = 0;
    Mnemonic mnemonic = Mnemonic::Invalid;
    uint8_t cc = 0;                 // Jcc/Setcc/Cmovcc condition nibble
    uint8_t suffix = 0;             // string-op size: 1,2,4,8
    Operand operands[4];
    uint8_t operandCount = 0;
    Prefixes prefixes;
    bool positionDependent = false;
    const char* rawName = nullptr;   // SIMD leaf ops set this instead of a Mnemonic
    uint8_t flagsRead = 0;           // EFlag bitmask
    uint8_t flagsWritten = 0;
};

struct DecodeResult {
    DecodeStatus status = DecodeStatus::Invalid;
    Instruction insn;
};

} // namespace disasm64
