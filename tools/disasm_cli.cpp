// disasm64 [--base 0xADDR] <hex bytes...>
#include "disasm64/disasm64.h"
#include "disasm64/analysis.h"
#include "disasm64/loader.h"
#include "disasm64/image.h"
#include "disasm64/cfg.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
using namespace disasm64;

static const char* catName(Category c) {
    static const char* n[] = {"unknown", "gpr", "branch", "stack", "string", "flags",
                              "sse", "avx", "avx512", "x87", "system", "nop"};
    return n[int(c)];
}
static const char* accName(OperandAccess a) {
    switch (a) { case OperandAccess::Read: return "r"; case OperandAccess::Write: return "w";
                 case OperandAccess::ReadWrite: return "rw"; default: return "-"; }
}

static void emit(const uint8_t* code, size_t n, uint64_t base, bool att, bool showFlags, bool showSem, size_t maxInsns) {
    size_t pos = 0, count = 0;
    while (pos < n && count < maxInsns) {
        DecodeResult r = decode(code + pos, n - pos, base + pos);
        std::printf("%016llx  ", (unsigned long long)(base + pos));
        size_t len = (r.status == DecodeStatus::Ok) ? r.insn.length : 1;
        for (size_t k = 0; k < len && k < 10; ++k) std::printf("%02x ", code[pos + k]);
        for (size_t k = len; k < 8; ++k) std::printf("   ");
        if (r.status == DecodeStatus::Ok) {
            std::printf(" %s", (att ? formatAtt(r.insn) : formatIntel(r.insn)).c_str());
            if (showFlags && (r.insn.flagsWritten || r.insn.flagsRead))
                std::printf("   [w:%s r:%s]", flagsToString(r.insn.flagsWritten).c_str(), flagsToString(r.insn.flagsRead).c_str());
            if (showSem) {
                std::printf("   [%s", catName(r.insn.category));
                for (int k = 0; k < r.insn.operandCount; ++k) std::printf(" op%d:%s", k, accName(r.insn.operands[k].access));
                std::printf("]");
            }
            std::printf("\n");
        }
        else if (r.status == DecodeStatus::Truncated) { std::printf(" (truncated)\n"); break; }
        else std::printf(" (bad)\n");
        if (r.status == DecodeStatus::Ok)
            for (const char* q : analyzeEncoding(code + pos, n - pos, base + pos))
                std::printf("%18s  ! %s\n", "", q);
        pos += len; ++count;
    }
    for (const SweepIssue& s : antiDisasmScan(code, n, base))
        std::printf("%016llx  !! %s\n", (unsigned long long)s.address, s.what);
}

int main(int argc, char** argv) {
    uint64_t base = 0x1000;
    bool showFlags = false, att = false, showSem = false;
    bool doImports = false, doExports = false, doStrings = false, doCfg = false;
    const char* filePath = nullptr;
    const char* pattern = nullptr;
    std::vector<uint8_t> code;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--base") && i + 1 < argc) { base = std::strtoull(argv[++i], nullptr, 0); continue; }
        if (!std::strcmp(argv[i], "--file") && i + 1 < argc) { filePath = argv[++i]; continue; }
        if (!std::strcmp(argv[i], "--pattern") && i + 1 < argc) { pattern = argv[++i]; continue; }
        if (!std::strcmp(argv[i], "--imports")) { doImports = true; continue; }
        if (!std::strcmp(argv[i], "--exports")) { doExports = true; continue; }
        if (!std::strcmp(argv[i], "--strings")) { doStrings = true; continue; }
        if (!std::strcmp(argv[i], "--cfg")) { doCfg = true; continue; }
        if (!std::strcmp(argv[i], "--flags")) { showFlags = true; continue; }
        if (!std::strcmp(argv[i], "--att")) { att = true; continue; }
        if (!std::strcmp(argv[i], "--sem")) { showSem = true; continue; }
        code.push_back(uint8_t(std::strtoul(argv[i], nullptr, 16)));
    }

    if (filePath) {
        FILE* f = std::fopen(filePath, "rb");
        if (!f) { std::printf("cannot open %s\n", filePath); return 1; }
        std::fseek(f, 0, SEEK_END); long sz = std::ftell(f); std::fseek(f, 0, SEEK_SET);
        std::vector<uint8_t> data(sz > 0 ? size_t(sz) : 0);
        if (!data.empty()) { size_t got = std::fread(data.data(), 1, data.size(), f); data.resize(got); }
        std::fclose(f);
        LoadedImage im = loadImage(std::move(data));
        std::printf("; %s  %s  imagebase %llx  entry %llx\n", im.format.c_str(),
                    im.machine.empty() ? "?" : im.machine.c_str(),
                    (unsigned long long)im.imageBase, (unsigned long long)im.entry);
        if (doImports) {
            for (const Import& ip : parseImports(im))
                if (ip.name.empty()) std::printf("%016llx  %s : #%u\n", (unsigned long long)ip.iatVa, ip.dll.c_str(), ip.ordinal);
                else std::printf("%016llx  %s : %s\n", (unsigned long long)ip.iatVa, ip.dll.c_str(), ip.name.c_str());
            return 0;
        }
        if (doExports) {
            for (const Export& e : parseExports(im)) std::printf("%016llx  #%u  %s\n", (unsigned long long)e.va, e.ordinal, e.name.c_str());
            return 0;
        }
        if (doStrings) {
            for (const FoundString& s : findStrings(im)) std::printf("%016llx  %s%s\n", (unsigned long long)s.va, s.wide ? "L" : "", s.text.c_str());
            return 0;
        }
        if (pattern) {
            for (const Match& m : patternSearch(im, pattern)) std::printf("%016llx\n", (unsigned long long)m.va);
            return 0;
        }
        if (doCfg) {
            for (const CodeRegion& rg : im.code) {
                if (im.entry < rg.vaddr || im.entry >= rg.vaddr + rg.size) continue;
                Cfg cfg = buildCfg(regionData(im, rg), rg.size, rg.vaddr, im.entry);
                std::printf("; %zu basic blocks, %zu call targets from entry %llx\n",
                            cfg.blocks.size(), cfg.calls.size(), (unsigned long long)im.entry);
                for (const BasicBlock& b : cfg.blocks) {
                    std::printf("%016llx - %016llx  ->", (unsigned long long)b.start, (unsigned long long)b.end);
                    for (uint64_t s : b.succs) std::printf(" %llx", (unsigned long long)s);
                    std::printf("\n");
                }
                break;
            }
            return 0;
        }
        for (const CodeRegion& rg : im.code) {
            std::printf("\n; section %s  va %llx  size %llx\n", rg.name.c_str(),
                        (unsigned long long)rg.vaddr, (unsigned long long)rg.size);
            emit(regionData(im, rg), rg.size, rg.vaddr, att, showFlags, showSem, 100000);
        }
        return 0;
    }

    if (code.empty()) { std::printf("usage: disasm64 [--base 0xADDR] [--file PATH] [--att] [--flags] [--sem] <hex bytes...>\n"); return 1; }
    emit(code.data(), code.size(), base, att, showFlags, showSem, 1000000);
    return 0;
}
