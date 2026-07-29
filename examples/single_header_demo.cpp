#define DISASM64_IMPLEMENTATION
#include "disasm64.h"
#include <cstdio>

int main() {
    const uint8_t code[] = {0x48, 0x89, 0xE5, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3};
    size_t pos = 0;
    while (pos < sizeof code) {
        disasm64::DecodeResult r = disasm64::decode(code + pos, sizeof code - pos, 0x1000 + pos);
        if (r.status != disasm64::DecodeStatus::Ok) break;
        std::printf("%s\n", disasm64::formatIntel(r.insn).c_str());
        pos += r.insn.length;
    }
    return 0;
}
