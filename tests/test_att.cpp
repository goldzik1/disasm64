#include "check.h"
#include "disasm64/disasm64.h"
#include <string>
using namespace disasm64;

static std::string att(std::initializer_list<uint8_t> bytes, uint64_t addr = 0) {
    static uint8_t buf[16];
    size_t n = 0; for (uint8_t b : bytes) buf[n++] = b;
    DecodeResult r = decode(buf, n, addr);
    if (r.status != DecodeStatus::Ok) return "<invalid>";
    return formatAtt(r.insn);
}

TEST_MAIN({
    CHECK_STR(att({0x48, 0x89, 0xE5}), "mov %rsp, %rbp");
    CHECK_STR(att({0x48, 0x83, 0xEC, 0x20}), "sub $0x20, %rsp");
    CHECK_STR(att({0xC6, 0x00, 0xFF}), "movb $0xff, (%rax)");
    CHECK_STR(att({0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00}), "mov 0x10(%rip), %rax");
    CHECK_STR(att({0x48, 0x8B, 0x04, 0x08}), "mov (%rax,%rcx,1), %rax");
    CHECK_STR(att({0x0F, 0x28, 0xC1}), "movaps %xmm1, %xmm0");
    CHECK_STR(att({0xE8, 0x00, 0x00, 0x00, 0x00}), "call 0x5");
})
