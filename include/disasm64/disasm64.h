#pragma once
#include "types.h"
#include <string>

namespace disasm64 {

// Decode one instruction from p[0..n) as if it lived at `address`.
DecodeResult decode(const uint8_t* p, size_t n, uint64_t address);

// Format a decoded instruction as Intel syntax.
std::string formatIntel(const Instruction& insn);

} // namespace disasm64
