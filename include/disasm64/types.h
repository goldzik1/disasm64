#pragma once
#include <cstdint>
#include <cstddef>

namespace disasm64 {

// Register classes. Numeric index within a class is the x86 register number 0..15
// (or 0..7 for segment / x87). Formatting maps (class,index) -> a name.
enum class RegClass : uint8_t {
    None, Gpr8, Gpr8Hi, Gpr16, Gpr32, Gpr64, Xmm, Ymm, Sreg, Rip
};

struct Reg {
    RegClass cls = RegClass::None;
    uint8_t idx = 0;
    bool valid() const { return cls != RegClass::None; }
};

enum class OperandKind : uint8_t { None, Reg, Mem, Imm, Rel };

// Memory operand: seg:[base + index*scale + disp]. base/index == Reg with
// cls==None means "absent". ripRelative resolves disp against the next-insn address.
struct MemOperand {
    Reg base;
    Reg index;
    uint8_t scale = 1;        // 1,2,4,8
    int64_t disp = 0;
    bool ripRelative = false;
    uint8_t segment = 0xFF;   // 0xFF == default segment; else Sreg index
    uint64_t ripTarget = 0;   // resolved absolute target when ripRelative
    uint8_t dispOffset = 0;   // byte offset of the disp field within the instruction
};

struct Operand {
    OperandKind kind = OperandKind::None;
    uint8_t sizeBytes = 0;    // operand/access width: 1,2,4,8,16,32 (0 = n/a)
    Reg reg;                  // kind == Reg
    MemOperand mem;           // kind == Mem
    int64_t imm = 0;          // kind == Imm (sign-extended value)
    bool immSigned = true;
    uint64_t relTarget = 0;   // kind == Rel (absolute target)
    uint8_t relSize = 0;      // 1 or 4 (rel8/rel32) — original displacement width
};

struct Prefixes {
    bool lock = false;
    uint8_t rep = 0;          // 0, 0xF2, or 0xF3
    uint8_t segment = 0xFF;   // 0xFF none; else Sreg index (ES CS SS DS FS GS = 0..5)
    bool opsize = false;      // 0x66
    bool addrsize = false;    // 0x67
    // REX
    bool rex = false;
    bool rexW = false, rexR = false, rexX = false, rexB = false;
    // VEX (filled by later coverage)
    bool vex = false;
    uint8_t vexMap = 0;       // implied opcode map (1=0F, 2=0F38, 3=0F3A)
    uint8_t vexPP = 0;        // implied prefix (0=none,1=66,2=F3,3=F2)
    uint8_t vexVVVV = 0;      // additional source register (inverted in encoding)
    bool vexL = false;        // 0 = xmm/128, 1 = ymm/256
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
    // SSE (curated)
    Movups, Movupd, Movss, Movsd, Movaps, Movapd, Movdqa, Movdqu,
    Movd, Movq, Pxor, Xorps, Xorpd,
    Andps, Andpd, Andnps, Andnpd, Orps, Orpd, Pand, Por, Pandn,
    // SSE arithmetic — laid out ps,pd,ss,sd per op so mnemonic = base + pp
    Addps, Addpd, Addss, Addsd, Mulps, Mulpd, Mulss, Mulsd,
    Subps, Subpd, Subss, Subsd, Divps, Divpd, Divss, Divsd,
    Sqrtps, Sqrtpd, Sqrtss, Sqrtsd, Ucomiss, Ucomisd, Comiss, Comisd,
    Count
};

enum class DecodeStatus : uint8_t { Ok, Invalid, Truncated };

struct Instruction {
    uint64_t address = 0;
    uint8_t length = 0;
    Mnemonic mnemonic = Mnemonic::Invalid;
    uint8_t cc = 0;                 // condition code nibble for Jcc/Setcc/Cmovcc
    uint8_t suffix = 0;             // size (1/2/4/8) for a size-suffixed mnemonic (string ops)
    Operand operands[4];
    uint8_t operandCount = 0;
    Prefixes prefixes;
    bool positionDependent = false; // has RIP-relative or relative-branch operand
};

struct DecodeResult {
    DecodeStatus status = DecodeStatus::Invalid;
    Instruction insn;
};

} // namespace disasm64
