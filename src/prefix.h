#pragma once
#include "disasm64/types.h"
#include "disasm64/reader.h"

namespace disasm64 {

// Consume legacy prefixes and REX from `r` into `pfx`, leaving `r` at the opcode.
// VEX (C4/C5) is detected and parsed into pfx (map/pp/L/W/vvvv) but the opcode
// itself is left for the decoder. Returns false only on truncation.
bool decodePrefixes(Reader& r, Prefixes& pfx);

} // namespace disasm64
