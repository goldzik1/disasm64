#include "check.h"
#include "disasm64/c_api.h"
#include <cstring>
#include <string>

TEST_MAIN({
    uint8_t code[] = {0x48, 0x89, 0xE5};       // mov rbp, rsp
    char buf[64];

    uint8_t len = d64_format(code, sizeof code, 0x1000, 0, buf, sizeof buf);
    CHECK_EQ(int(len), 3);
    CHECK_STR(std::string(buf), "mov rbp, rsp");

    d64_format(code, sizeof code, 0x1000, 1, buf, sizeof buf);   // AT&T
    CHECK_STR(std::string(buf), "mov %rsp, %rbp");

    d64_insn in;
    uint8_t l = d64_decode(code, sizeof code, 0x1000, &in);
    CHECK_EQ(int(l), 3);
    CHECK_EQ(int(in.status), D64_OK);
    CHECK_EQ(int(in.operand_count), 2);
    CHECK_EQ(int(in.operands[0].kind), D64_OP_REG);
    CHECK_EQ(int(in.operands[0].reg_index), 5);   // rbp

    uint8_t call[] = {0xE8, 0x00, 0x10, 0x00, 0x00};
    d64_decode(call, sizeof call, 0x401000, &in);
    CHECK_EQ(int(in.operands[0].kind), D64_OP_REL);
    CHECK_EQ((unsigned long long)in.operands[0].rel_target, 0x401000ull + 5 + 0x1000);

    uint8_t out[16];
    uint8_t rl = d64_relocate(call, sizeof call, 0x401000, 0x800000, out, sizeof out);
    CHECK(rl > 0);
    d64_insn in2; d64_decode(out, rl, 0x800000, &in2);
    CHECK_EQ((unsigned long long)in2.operands[0].rel_target, 0x401000ull + 5 + 0x1000);   // target preserved

    uint8_t bad[] = {0x0F, 0x0F};
    d64_insn bi; uint8_t bl = d64_decode(bad, sizeof bad, 0, &bi);
    CHECK_EQ(int(bl), 0);
    CHECK_EQ(int(bi.status), D64_INVALID);

    CHECK_STR(std::string(d64_reg_class_name(5)), "gpr64");
    CHECK(std::strlen(d64_version()) > 0);

    // semantic metadata: per-operand access + category
    uint8_t add[] = {0x48, 0x01, 0xD8};                 // add rax, rbx
    d64_decode(add, sizeof add, 0, &in);
    CHECK_STR(std::string(d64_category_name(in.category)), "gpr");
    CHECK_EQ(int(in.operands[0].access), 3);            // rax: read+write
    CHECK_EQ(int(in.operands[1].access), 1);            // rbx: read

    d64_decode(code, sizeof code, 0, &in);              // mov rbp, rsp
    CHECK_EQ(int(in.operands[0].access), 2);            // write
    CHECK_EQ(int(in.operands[1].access), 1);            // read

    d64_decode(call, sizeof call, 0x401000, &in);
    CHECK_STR(std::string(d64_category_name(in.category)), "branch");

    uint8_t vadd[] = {0x62, 0xF1, 0x6C, 0x48, 0x58, 0xCB};   // vaddps zmm1, zmm2, zmm3
    d64_decode(vadd, sizeof vadd, 0, &in);
    CHECK_STR(std::string(d64_category_name(in.category)), "avx512");
    CHECK_EQ(int(in.operands[0].access), 2);            // dest write
    CHECK_EQ(int(in.operands[1].access), 1);            // source read
})
