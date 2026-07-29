#include "disasm64/disasm64.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
using namespace disasm64;

struct Rng { uint64_t s; explicit Rng(uint64_t x) : s(x ? x : 1) {}
    uint64_t next() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; } };

int main(int argc, char** argv) {
    long count = 2000000;
    uint64_t seed = 1;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--count") && i + 1 < argc) count = std::atol(argv[++i]);
        else if (!std::strcmp(argv[i], "--seed") && i + 1 < argc) seed = std::strtoull(argv[++i], nullptr, 0);
    }
    Rng rng(seed);
    long ok = 0, invalid = 0, trunc = 0, bad = 0;

    uint8_t win[16];
    for (long i = 0; i < count; ++i) {
        for (int k = 0; k < 16; ++k) win[k] = uint8_t(rng.next());
        DecodeResult r = decode(win, 16, 0x140000000ull);
        if (r.status == DecodeStatus::Ok) {
            ++ok;
            if (r.insn.length < 1 || r.insn.length > 15) { ++bad; if (bad <= 5) std::printf("bad length %d\n", r.insn.length); }
        } else if (r.status == DecodeStatus::Invalid) ++invalid;
        else ++trunc;
    }

    uint8_t buf[4096];   // linear sweep
    for (int rounds = 0; rounds < 200; ++rounds) {
        for (int k = 0; k < 4096; ++k) buf[k] = uint8_t(rng.next());
        size_t pos = 0; long steps = 0;
        while (pos < 4096) {
            DecodeResult r = decode(buf + pos, 4096 - pos, 0x1000 + pos);
            size_t adv = (r.status == DecodeStatus::Truncated) ? (4096 - pos) : (r.insn.length ? r.insn.length : 1);
            if (adv == 0) { ++bad; break; }
            pos += adv;
            if (++steps > 8192) { ++bad; std::printf("sweep did not terminate\n"); break; }
        }
    }

    std::printf("robust: %ld ok, %ld invalid, %ld truncated, %ld ANOMALIES\n", ok, invalid, trunc, bad);
    return bad == 0 ? 0 : 1;
}
