#include "check.h"
#include "disasm64/disasm64.h"
#include <vector>
using namespace disasm64;

// A RIP-relative load and a rel32 call keep the same effective target after being
// moved to a new address; a rel8 branch that no longer reaches fails cleanly.
TEST_MAIN({
    // mov rax, [rip+0x10] at 0x1000 -> target 0x1017; move to 0x2000, target must hold.
    {
        const uint8_t b[] = {0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00};
        std::vector<uint8_t> out;
        CHECK(relocate(b, sizeof b, 0x1000, 0x2000, out));
        DecodeResult r = decode(out.data(), out.size(), 0x2000);
        CHECK(r.status == DecodeStatus::Ok);
        CHECK_EQ(r.insn.operands[1].mem.ripTarget, uint64_t(0x1017));
    }
    // call rel32 (target 0x1005) moved to 0x2000 keeps target 0x1005.
    {
        const uint8_t b[] = {0xE8, 0x00, 0x00, 0x00, 0x00};
        std::vector<uint8_t> out;
        CHECK(relocate(b, sizeof b, 0x1000, 0x2000, out));
        DecodeResult r = decode(out.data(), out.size(), 0x2000);
        CHECK_EQ(r.insn.operands[0].relTarget, uint64_t(0x1005));
    }
    // position-independent instruction: bytes unchanged.
    {
        const uint8_t b[] = {0x48, 0x89, 0xE5};
        std::vector<uint8_t> out;
        CHECK(relocate(b, sizeof b, 0x1000, 0x9999, out));
        CHECK_EQ(out.size(), size_t(3));
        CHECK(out[0] == 0x48 && out[1] == 0x89 && out[2] == 0xE5);
    }
    // rel8 that no longer fits -> relocate fails cleanly.
    {
        const uint8_t b[] = {0xEB, 0x05};   // jmp short, target 0x1007
        std::vector<uint8_t> out;
        CHECK(!relocate(b, sizeof b, 0x1000, 0x40000000, out));
    }
})
