#pragma once
#include "types.h"
#include <cstddef>

namespace disasm64 {

enum class EncodeStatus : uint8_t { Ok, Unsupported, Buffer };

struct EncodeResult {
    EncodeStatus status = EncodeStatus::Unsupported;
    uint8_t length = 0;
};

// Re-emit an Instruction (as produced by decode) to machine code. Covers the
// general-purpose integer core; SIMD/x87 report Unsupported. The output is a
// canonical encoding that decodes back to the same instruction, which is what
// the relocation / rewriting paths rely on.
EncodeResult encode(const Instruction& insn, uint8_t* out, size_t cap);

} // namespace disasm64
