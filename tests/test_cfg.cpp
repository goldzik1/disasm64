#include "check.h"
#include "disasm64/cfg.h"
#include <cstdint>
#include <vector>
using namespace disasm64;

static bool hasSucc(const BasicBlock& b, uint64_t s) {
    for (uint64_t x : b.succs) if (x == s) return true;
    return false;
}

TEST_MAIN({
    // test rax,rax ; jz +3 ; inc rax ; ret     (a diamond of three blocks)
    std::vector<uint8_t> code = {0x48, 0x85, 0xC0, 0x74, 0x03, 0x48, 0xFF, 0xC0, 0xC3};
    Cfg cfg = buildCfg(code.data(), code.size(), 0x1000, 0x1000);

    CHECK_EQ(int(cfg.blocks.size()), 3);
    CHECK_EQ((unsigned long long)cfg.entry, 0x1000ull);
    if (cfg.blocks.size() == 3) {
        // block 0: 0x1000..0x1005, branches to 0x1008 (taken) and 0x1005 (fall-through)
        CHECK_EQ((unsigned long long)cfg.blocks[0].start, 0x1000ull);
        CHECK_EQ((unsigned long long)cfg.blocks[0].end, 0x1005ull);
        CHECK(hasSucc(cfg.blocks[0], 0x1008));
        CHECK(hasSucc(cfg.blocks[0], 0x1005));
        // block 1: 0x1005..0x1008, falls through to 0x1008
        CHECK_EQ((unsigned long long)cfg.blocks[1].start, 0x1005ull);
        CHECK(hasSucc(cfg.blocks[1], 0x1008));
        // block 2: 0x1008 ret, no successors
        CHECK_EQ((unsigned long long)cfg.blocks[2].start, 0x1008ull);
        CHECK_EQ(int(cfg.blocks[2].succs.size()), 0);
    }

    // a direct call is recorded, and does not split the block
    std::vector<uint8_t> c2 = {0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3};   // call +0 ; ret
    Cfg cfg2 = buildCfg(c2.data(), c2.size(), 0x2000, 0x2000);
    CHECK_EQ(int(cfg2.blocks.size()), 1);
    CHECK_EQ(int(cfg2.calls.size()), 1);
    if (!cfg2.calls.empty()) CHECK_EQ((unsigned long long)cfg2.calls[0], 0x2005ull);   // 0x2000+5+0
})
