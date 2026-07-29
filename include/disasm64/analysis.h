#pragma once
#include "types.h"
#include <vector>
#include <string>
#include <cstdint>

namespace disasm64 {

// EFLAGS bitmask -> letters (cpazso d).
std::string flagsToString(uint8_t flags);

// Encoding quirks of one instruction: redundant prefixes, over-long forms — signals of
// obfuscation, watermarking, or hand-crafted code that a plain disassembler won't show.
std::vector<const char*> analyzeEncoding(const uint8_t* p, size_t n, uint64_t address);

// Steal whole instructions until at least minBytes are covered, then relocate them to
// run correctly at newAddress — the primitive a trampoline hook needs. ok=false if a
// stolen instruction fails to decode; relocatable=false if one can't be moved cleanly.
struct HookPlan {
    bool ok = false;
    uint8_t stolenBytes = 0;
    bool relocatable = false;
    std::vector<uint8_t> relocated;
};
HookPlan planHook(const uint8_t* p, size_t n, uint64_t address, uint64_t newAddress, unsigned minBytes);

// Linear-sweep a range and flag anti-disassembly: relative branches whose target lands
// inside another decoded instruction (hidden / overlapping code).
struct SweepIssue { uint64_t address; const char* what; };
std::vector<SweepIssue> antiDisasmScan(const uint8_t* p, size_t n, uint64_t baseAddress);

} // namespace disasm64
