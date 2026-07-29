#pragma once
#include "disasm64/types.h"
#include "disasm64/reader.h"

namespace disasm64 {

bool decodePrefixes(Reader& r, Prefixes& pfx);

} // namespace disasm64
