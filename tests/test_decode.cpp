#include "check.h"
#include "disasm64/disasm64.h"
using namespace disasm64;

static Instruction dec(std::initializer_list<uint8_t> bytes, uint64_t addr = 0) {
    static uint8_t buf[16];
    size_t n = 0; for (uint8_t b : bytes) buf[n++] = b;
    DecodeResult r = decode(buf, n, addr);
    CHECK(r.status == DecodeStatus::Ok);
    return r.insn;
}

TEST_MAIN({
    { Instruction i = dec({0x90}); CHECK(i.mnemonic == Mnemonic::Nop); CHECK_EQ(int(i.length), 1); }
    { Instruction i = dec({0xC3}); CHECK(i.mnemonic == Mnemonic::Ret); CHECK_EQ(int(i.length), 1); }
    { Instruction i = dec({0x48, 0x89, 0xE5}); CHECK(i.mnemonic == Mnemonic::Mov); CHECK_EQ(int(i.length), 3);
      CHECK(i.operands[0].kind == OperandKind::Reg); CHECK_EQ(int(i.operands[0].reg.idx), 5);   // rbp
      CHECK(i.operands[0].reg.cls == RegClass::Gpr64); CHECK_EQ(int(i.operands[1].reg.idx), 4); } // rsp
    { Instruction i = dec({0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00}, 0x1000);
      CHECK(i.mnemonic == Mnemonic::Mov); CHECK_EQ(int(i.length), 7);
      CHECK(i.operands[1].kind == OperandKind::Mem); CHECK(i.operands[1].mem.ripRelative);
      CHECK_EQ(i.operands[1].mem.ripTarget, uint64_t(0x1000 + 7 + 0x10)); CHECK(i.positionDependent); }
    { Instruction i = dec({0xE8, 0x00, 0x00, 0x00, 0x00}, 0x2000);
      CHECK(i.mnemonic == Mnemonic::Call); CHECK(i.operands[0].kind == OperandKind::Rel);
      CHECK_EQ(i.operands[0].relTarget, uint64_t(0x2005)); }
    { Instruction i = dec({0x48, 0x83, 0xEC, 0x20}); CHECK(i.mnemonic == Mnemonic::Sub); CHECK_EQ(int(i.length), 4);
      CHECK_EQ(int(i.operands[0].reg.idx), 4); CHECK(i.operands[1].kind == OperandKind::Imm); CHECK_EQ(i.operands[1].imm, int64_t(0x20)); }
    { Instruction i = dec({0xFF, 0xD0}); CHECK(i.mnemonic == Mnemonic::Call); CHECK(i.operands[0].reg.cls == RegClass::Gpr64); }
    { Instruction i = dec({0x0F, 0xB6, 0xC1}); CHECK(i.mnemonic == Mnemonic::Movzx); CHECK_EQ(int(i.length), 3);
      CHECK(i.operands[0].reg.cls == RegClass::Gpr32); CHECK(i.operands[1].reg.cls == RegClass::Gpr8); }
    // invalid / truncated
    { DecodeResult r = decode((const uint8_t*)"\x48", 1, 0); CHECK(r.status == DecodeStatus::Truncated); }
})
