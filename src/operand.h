#pragma once
#include "disasm64/types.h"
#include "disasm64/reader.h"

namespace disasm64 {

Reg makeGpr(int num, int sizeBytes, bool rexPresent);

// Reads ModRM (+SIB/disp); returns the reg field (REX.R applied). rmRegClass
// overrides the r/m register class (e.g. Xmm) when mod==3.
int decodeModRM(Reader& r, const Prefixes& pfx, int rmSizeBytes, Operand& rm,
                RegClass rmRegClass = RegClass::None);

} // namespace disasm64
