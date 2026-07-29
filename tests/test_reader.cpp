#include "check.h"
#include "disasm64/reader.h"
using namespace disasm64;

TEST_MAIN({
    const uint8_t b[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    Reader r(b, sizeof b);
    CHECK_EQ(int(r.peek()), 1);
    CHECK_EQ(int(r.u8()), 1);
    CHECK_EQ(int(r.u16()), 0x0302);
    CHECK_EQ(r.u32(), uint32_t(0x07060504));
    CHECK_EQ(int(r.remaining()), 1);
    CHECK(r.ok());
    r.u16();                    // reads past end
    CHECK(r.overflow);
    CHECK_EQ(int(r.imm(1) & 0xff), 0);   // returns 0 on overflow
})
