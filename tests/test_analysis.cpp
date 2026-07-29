#include "check.h"
#include "disasm64/analysis.h"
#include <cstring>
using namespace disasm64;

static bool has(const std::vector<const char*>& v, const char* s) {
    for (const char* x : v) if (!std::strcmp(x, s)) return true;
    return false;
}

TEST_MAIN({
    // encoding quirks
    { const uint8_t b[] = {0x66, 0x66, 0x90}; auto v = analyzeEncoding(b, sizeof b, 0); CHECK(has(v, "duplicate prefix")); }
    { const uint8_t b[] = {0x48, 0x8B, 0x80, 0x05, 0x00, 0x00, 0x00}; auto v = analyzeEncoding(b, sizeof b, 0); CHECK(has(v, "over-long disp32 (fits in disp8)")); }
    { const uint8_t b[] = {0x48, 0x8B, 0x40, 0x00}; auto v = analyzeEncoding(b, sizeof b, 0); CHECK(has(v, "redundant disp8 = 0")); }
    { const uint8_t b[] = {0x48, 0x89, 0xE5}; auto v = analyzeEncoding(b, sizeof b, 0); CHECK_EQ(v.size(), size_t(0)); }  // clean

    // hook planner: push rbp; mov rbp,rsp; call rel32  (steal >=5 -> 9 bytes, relocatable)
    {
        const uint8_t b[] = {0x55, 0x48, 0x89, 0xE5, 0xE8, 0x00, 0x00, 0x00, 0x00};
        HookPlan hp = planHook(b, sizeof b, 0x1000, 0x5000, 5);
        CHECK(hp.ok); CHECK_EQ(int(hp.stolenBytes), 9); CHECK(hp.relocatable); CHECK_EQ(hp.relocated.size(), size_t(9));
    }

    // anti-disasm: jmp +1 lands inside the next instruction
    {
        const uint8_t b[] = {0xEB, 0x01, 0x48, 0x90};
        auto v = antiDisasmScan(b, sizeof b, 0);
        CHECK_EQ(v.size(), size_t(1));
        if (!v.empty()) CHECK_EQ(v[0].address, uint64_t(0));
    }
})
