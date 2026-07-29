// Reads hex byte lines on stdin, decodes one instruction at offset 0 per line,
// emits "STATUS\tLEN\tINTEL" for a differential harness (see tools/diff_iced.py).
#include "disasm64/disasm64.h"
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

int main() {
    std::string line;
    line.reserve(64);
    int ch;
    std::vector<uint8_t> b;
    auto flush = [&]() {
        if (line.empty()) return;
        b.clear();
        int hi = -1;
        for (char c : line) {
            int v = hexv((unsigned char)c);
            if (v < 0) { hi = -1; continue; }
            if (hi < 0) hi = v; else { b.push_back(uint8_t(hi * 16 + v)); hi = -1; }
        }
        if (b.empty()) { std::printf("EMPTY\t0\t\n"); line.clear(); return; }
        DecodeResult r = decode(b.data(), b.size(), 0);
        if (r.status == DecodeStatus::Ok) std::printf("OK\t%u\t%s\n", (unsigned)r.insn.length, formatIntel(r.insn).c_str());
        else if (r.status == DecodeStatus::Truncated) std::printf("TRUNC\t0\t\n");
        else std::printf("BAD\t0\t\n");
        line.clear();
    };
    while ((ch = std::getchar()) != EOF) {
        if (ch == '\n') flush();
        else if (ch != '\r') line.push_back(char(ch));
    }
    flush();
    return 0;
}
