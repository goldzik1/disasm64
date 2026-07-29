#pragma once
#include "disasm64/types.h"
#include <string>

namespace disasm64 {
std::string mnemonicName(const Instruction& insn);   // base mnemonic incl. cc/SIMD, no prefixes
std::string registerName(const Reg& reg);
}
