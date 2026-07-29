#pragma once
#include "types.h"
#include <string>
#include <vector>

namespace disasm64 {

DecodeResult decode(const uint8_t* p, size_t n, uint64_t address);

std::string formatIntel(const Instruction& insn);
std::string formatAtt(const Instruction& insn);

// Re-emit at newAddress with RIP-relative / rel32 fixed up; false on undecodable
// input or a rel8 target that no longer fits.
bool relocate(const uint8_t* bytes, size_t n, uint64_t oldAddress, uint64_t newAddress,
              std::vector<uint8_t>& out);

} // namespace disasm64
