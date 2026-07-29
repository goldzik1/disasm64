#pragma once
#include "disasm64/types.h"
#include "disasm64/reader.h"

namespace disasm64 {

// Build a general-purpose register operand of the given byte size. `rexPresent`
// selects SPL/BPL/SIL/DIL vs AH/CH/DH/BH for 8-bit registers 4..7.
Reg makeGpr(int num, int sizeBytes, bool rexPresent);

// Read a ModRM byte (and SIB/displacement if the r/m is memory) from `r`, filling
// `rm` as an operand of `rmSizeBytes`. Returns the reg field (0..15, REX.R applied)
// so the caller can build the register operand separately. RIP-relative memory
// leaves disp in place; the caller resolves ripTarget once the length is known.
int decodeModRM(Reader& r, const Prefixes& pfx, int rmSizeBytes, Operand& rm);

} // namespace disasm64
