#pragma once
#include <cstdint>
#include <cstddef>

namespace disasm64 {

struct Reader {
    const uint8_t* p;
    size_t n;
    size_t pos = 0;
    bool overflow = false;

    Reader(const uint8_t* data, size_t len) : p(data), n(len) {}

    size_t remaining() const { return pos < n ? n - pos : 0; }
    bool ok() const { return !overflow; }

    uint8_t peek() { if (pos >= n) { overflow = true; return 0; } return p[pos]; }
    uint8_t u8()   { if (pos >= n) { overflow = true; return 0; } return p[pos++]; }
    uint16_t u16() { uint16_t v = 0; for (int i = 0; i < 2; ++i) v |= uint16_t(u8()) << (8 * i); return v; }
    uint32_t u32() { uint32_t v = 0; for (int i = 0; i < 4; ++i) v |= uint32_t(u8()) << (8 * i); return v; }
    uint64_t u64() { uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= uint64_t(u8()) << (8 * i); return v; }

    int64_t imm(int width) {   // sign-extended, width 1/2/4/8
        switch (width) {
            case 1: return int8_t(u8());
            case 2: return int16_t(u16());
            case 4: return int32_t(u32());
            case 8: return int64_t(u64());
            default: return 0;
        }
    }
};

} // namespace disasm64
