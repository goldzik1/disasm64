#include "check.h"
#include "disasm64/image.h"
#include <string>
using namespace disasm64;

TEST_MAIN({
    // a synthetic image with one data section
    LoadedImage im;
    im.file = {'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0,   // 0..11
               0x48, 0x8B, 0x05, 0xC0,                                     // 12..15  pattern
               'H', 0, 'i', 0, '!', 0, '?', 0, 0};                         // 16..  wide "Hi!?"
    im.sections.push_back({".data", 0x1000, uint32_t(im.file.size()), 0, uint32_t(im.file.size()), false});

    // vaToOffset
    CHECK_EQ(int(vaToOffset(im, 0x100C)), 12);
    CHECK_EQ(int(vaToOffset(im, 0x1000)), 0);
    CHECK(vaToOffset(im, 0x9999) == SIZE_MAX);

    // strings (ASCII + UTF-16LE)
    auto ss = findStrings(im, 4);
    bool foundAscii = false, foundWide = false;
    for (const FoundString& s : ss) {
        if (s.text == "Hello world" && !s.wide && s.va == 0x1000) foundAscii = true;
        if (s.text == "Hi!?" && s.wide) foundWide = true;
    }
    CHECK(foundAscii);
    CHECK(foundWide);

    // pattern search with a wildcard byte
    auto m = patternSearch(im, "48 8B ?? C0");
    CHECK_EQ(int(m.size()), 1);
    if (!m.empty()) CHECK_EQ((unsigned long long)m[0].va, 0x100Cull);

    // no match
    CHECK_EQ(int(patternSearch(im, "de ad be ef").size()), 0);
})
