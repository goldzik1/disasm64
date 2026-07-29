// disasm64 [--base 0xADDR] <hex bytes...>
#include "disasm64/disasm64.h"
#include "disasm64/analysis.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
using namespace disasm64;

int main(int argc, char** argv) {
    uint64_t base = 0x1000;
    std::vector<uint8_t> code;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--base") && i + 1 < argc) { base = std::strtoull(argv[++i], nullptr, 0); continue; }
        code.push_back(uint8_t(std::strtoul(argv[i], nullptr, 16)));
    }
    if (code.empty()) { std::printf("usage: disasm64 [--base 0xADDR] <hex bytes...>\n"); return 1; }

    size_t pos = 0;
    while (pos < code.size()) {
        DecodeResult r = decode(code.data() + pos, code.size() - pos, base + pos);
        std::printf("%016llx  ", (unsigned long long)(base + pos));
        size_t len = (r.status == DecodeStatus::Ok) ? r.insn.length : 1;
        for (size_t k = 0; k < len; ++k) std::printf("%02x ", code[pos + k]);
        for (size_t k = len; k < 8; ++k) std::printf("   ");
        if (r.status == DecodeStatus::Ok) std::printf(" %s\n", formatIntel(r.insn).c_str());
        else if (r.status == DecodeStatus::Truncated) { std::printf(" (truncated)\n"); break; }
        else std::printf(" (bad)\n");
        if (r.status == DecodeStatus::Ok)
            for (const char* q : analyzeEncoding(code.data() + pos, code.size() - pos, base + pos))
                std::printf("%18s  ! %s\n", "", q);
        pos += len;
    }
    for (const SweepIssue& s : antiDisasmScan(code.data(), code.size(), base))
        std::printf("%016llx  !! %s\n", (unsigned long long)s.address, s.what);
    return 0;
}
