// Emscripten entry point for the browser playground. Build with wasm/build.sh (needs emsdk).
#include "disasm64/disasm64.h"
#include "disasm64/analysis.h"
#include <emscripten.h>
#include <cstdio>
#include <string>
#include <vector>
using namespace disasm64;

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Disassemble a hex string. Returns a newline-separated listing (address, bytes, text,
// and any encoding-quirk / anti-disassembly annotations). The pointer stays valid until
// the next call.
extern "C" EMSCRIPTEN_KEEPALIVE const char* d64_disasm(const char* hex, double baseAddr, int att) {
    static std::string out;
    std::vector<uint8_t> code;
    int hi = -1;
    for (const char* p = hex; *p; ++p) {
        int v = hexv((unsigned char)*p);
        if (v < 0) { hi = -1; continue; }
        if (hi < 0) hi = v; else { code.push_back(uint8_t(hi * 16 + v)); hi = -1; }
    }
    out.clear();
    uint64_t base = uint64_t(baseAddr);
    size_t pos = 0;
    char line[160];
    while (pos < code.size()) {
        DecodeResult r = decode(code.data() + pos, code.size() - pos, base + pos);
        size_t len = r.status == DecodeStatus::Ok ? r.insn.length : 1;
        std::snprintf(line, sizeof line, "%016llx  ", (unsigned long long)(base + pos));
        out += line;
        for (size_t k = 0; k < len && k < 12; ++k) { std::snprintf(line, sizeof line, "%02x ", code[pos + k]); out += line; }
        for (size_t k = len; k < 8; ++k) out += "   ";
        if (r.status == DecodeStatus::Ok) out += " " + (att ? formatAtt(r.insn) : formatIntel(r.insn));
        else if (r.status == DecodeStatus::Truncated) { out += " (truncated)"; out += "\n"; break; }
        else out += " (bad)";
        out += "\n";
        if (r.status == DecodeStatus::Ok)
            for (const char* q : analyzeEncoding(code.data() + pos, code.size() - pos, base + pos)) {
                out += "                    ! "; out += q; out += "\n";
            }
        pos += len;
    }
    for (const SweepIssue& s : antiDisasmScan(code.data(), code.size(), base)) {
        std::snprintf(line, sizeof line, "%016llx  !! %s\n", (unsigned long long)s.address, s.what);
        out += line;
    }
    return out.c_str();
}
