#pragma once
#include "types.h"
#include <string>
#include <vector>

namespace disasm64 {

// Decode one instruction from p[0..n) as if it lived at `address`.
DecodeResult decode(const uint8_t* p, size_t n, uint64_t address);

// Format a decoded instruction as Intel syntax.
std::string formatIntel(const Instruction& insn);

// Re-emit the instruction at oldAddress so it behaves identically at newAddress.
// Position-independent instructions come back byte-for-byte. RIP-relative and
// rel32 displacements are fixed up so the effective target is preserved. Returns
// no value if the instruction can't decode, or if a rel8 target no longer fits in
// 8 bits (widening rel8->rel32 needs the encoder and is left for a later cycle).
bool relocate(const uint8_t* bytes, size_t n, uint64_t oldAddress, uint64_t newAddress,
              std::vector<uint8_t>& out);

} // namespace disasm64
