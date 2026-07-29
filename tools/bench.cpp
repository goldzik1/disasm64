// Decode/format/encode throughput. Fills a buffer with a realistic instruction mix and
// times a linear sweep over it.  usage: bench [--mb N]
#include "disasm64/disasm64.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
using namespace disasm64;

int main(int argc, char** argv) {
    size_t targetMB = 64;
    for (int i = 1; i < argc; ++i)
        if (!std::strcmp(argv[i], "--mb") && i + 1 < argc) targetMB = std::strtoul(argv[++i], nullptr, 10);

    // a representative prologue/body mix (push/mov/sub/lea/call/test/jcc/ret/SSE/AVX)
    static const uint8_t seed[] = {
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x05, 0xE8, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x10, 0x44, 0x24, 0x10, 0xC5, 0xF8, 0x58, 0xC1, 0x48, 0x01, 0xD8, 0x83, 0xC0, 0x01,
        0x88, 0x08, 0x0F, 0xB6, 0xC0, 0xFF, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3,
    };
    std::vector<uint8_t> code;
    code.reserve(targetMB * 1024 * 1024 + 64);
    while (code.size() < targetMB * 1024 * 1024) code.insert(code.end(), seed, seed + sizeof seed);
    const size_t total = code.size();

    auto sweep = [&](int mode) -> size_t {
        size_t pos = 0, count = 0; char buf[64]; uint8_t enc[16];
        while (pos + 16 <= total) {
            DecodeResult r = decode(code.data() + pos, total - pos, pos);
            size_t len = r.status == DecodeStatus::Ok ? r.insn.length : 1;
            if (r.status == DecodeStatus::Ok) {
                if (mode == 1) { std::string s = formatIntel(r.insn); (void)s; }
                else if (mode == 2) { EncodeResult e = encode(r.insn, enc, sizeof enc); (void)e; }
            }
            (void)buf;
            pos += len; ++count;
        }
        return count;
    };

    struct { const char* name; int mode; } passes[] = {{"decode", 0}, {"decode+format", 1}, {"decode+encode", 2}};
    std::printf("disasm64 bench  (%zu MB buffer)\n\n", targetMB);
    for (auto& p : passes) {
        sweep(p.mode);   // warm
        auto t0 = std::chrono::steady_clock::now();
        size_t n = sweep(p.mode);
        auto t1 = std::chrono::steady_clock::now();
        double sec = std::chrono::duration<double>(t1 - t0).count();
        double insns = double(n) / sec;
        double mbps = double(total) / (1024.0 * 1024.0) / sec;
        std::printf("  %-16s %8.1f M insn/s   %7.1f MB/s   %5.1f ns/insn\n",
                    p.name, insns / 1e6, mbps, 1e9 / insns);
    }
    return 0;
}
