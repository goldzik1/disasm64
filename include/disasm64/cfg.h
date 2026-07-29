#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace disasm64 {

struct BasicBlock {
    uint64_t start = 0;              // first instruction VA
    uint64_t end = 0;               // one past the last instruction (VA)
    std::vector<uint64_t> succs;    // successor block start VAs
};

struct Cfg {
    uint64_t entry = 0;
    std::vector<BasicBlock> blocks; // sorted by start
    std::vector<uint64_t> calls;    // statically-resolved call targets (function starts)
};

// Recursive-descent control-flow recovery over a flat code buffer mapped at `base`. Follows
// conditional and unconditional branches, splits into basic blocks, and records direct call
// targets separately (calls do not break a block).
Cfg buildCfg(const uint8_t* code, size_t n, uint64_t base, uint64_t entry);

} // namespace disasm64
