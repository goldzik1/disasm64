#include "check.h"
#include "prefix.h"
using namespace disasm64;

TEST_MAIN({
    { const uint8_t b[] = {0x48, 0x89}; Reader r(b, sizeof b); Prefixes p; decodePrefixes(r, p);
      CHECK(p.rex); CHECK(p.rexW); CHECK(!p.rexR); CHECK_EQ(int(r.pos), 1); }
    { const uint8_t b[] = {0xF0, 0x66, 0x44, 0x01}; Reader r(b, sizeof b); Prefixes p; decodePrefixes(r, p);
      CHECK(p.lock); CHECK(p.opsize); CHECK(p.rex); CHECK(p.rexR); CHECK(!p.rexB); CHECK_EQ(int(r.pos), 3); }
    { const uint8_t b[] = {0x64, 0x8B}; Reader r(b, sizeof b); Prefixes p; decodePrefixes(r, p);
      CHECK_EQ(int(p.segment), 4); CHECK_EQ(int(r.pos), 1); }   // FS
})
