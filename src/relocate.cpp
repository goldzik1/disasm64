#include "disasm64/disasm64.h"
#include <cstring>

namespace disasm64 {

static void put32(std::vector<uint8_t>& b, size_t off, int32_t v) {
    for (int i = 0; i < 4; ++i) b[off + i] = uint8_t(uint32_t(v) >> (8 * i));
}

bool relocate(const uint8_t* bytes, size_t n, uint64_t oldAddress, uint64_t newAddress,
              std::vector<uint8_t>& out) {
    DecodeResult dr = decode(bytes, n, oldAddress);
    if (dr.status != DecodeStatus::Ok) return false;
    const Instruction& in = dr.insn;
    out.assign(bytes, bytes + in.length);
    if (!in.positionDependent) return true;

    for (int i = 0; i < in.operandCount; ++i) {
        const Operand& o = in.operands[i];
        if (o.kind == OperandKind::Rel) {
            int64_t d = int64_t(o.relTarget) - int64_t(newAddress + in.length);
            if (o.relSize == 1) {
                if (d < -128 || d > 127) return false;   // would need to widen rel8 -> rel32
                out[in.length - 1] = uint8_t(int8_t(d));
            } else {
                if (d < INT32_MIN || d > INT32_MAX) return false;
                put32(out, in.length - 4, int32_t(d));
            }
            return true;
        }
        if (o.kind == OperandKind::Mem && o.mem.ripRelative) {
            int64_t d = int64_t(o.mem.ripTarget) - int64_t(newAddress + in.length);
            if (d < INT32_MIN || d > INT32_MAX) return false;
            put32(out, o.mem.dispOffset, int32_t(d));
            return true;
        }
    }
    return true;
}

} // namespace disasm64
