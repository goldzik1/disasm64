#define D64_BUILD
#include "disasm64/c_api.h"
#include "disasm64/disasm64.h"
#include <cstring>
#include <vector>

using namespace disasm64;

namespace {

void fillOperand(d64_operand& d, const Operand& o) {
    std::memset(&d, 0, sizeof d);
    d.kind = uint8_t(o.kind);
    d.size = o.sizeBytes;
    d.reg_class = uint8_t(o.reg.cls);
    d.reg_index = o.reg.idx;
    d.base_class = uint8_t(o.mem.base.cls);
    d.base_index = o.mem.base.idx;
    d.index_class = uint8_t(o.mem.index.cls);
    d.index_index = o.mem.index.idx;
    d.scale = o.mem.scale;
    d.segment = o.mem.segment;
    d.rip_relative = o.mem.ripRelative ? 1 : 0;
    d.disp = o.mem.disp;
    d.imm = o.imm;
    d.rel_target = o.kind == OperandKind::Rel ? o.relTarget : o.mem.ripTarget;
    d.access = uint8_t(o.access);
}

void fillInsn(d64_insn& d, const DecodeResult& r) {
    std::memset(&d, 0, sizeof d);
    const Instruction& in = r.insn;
    d.address = in.address;
    d.status = uint8_t(r.status);
    d.length = in.length;
    d.mnemonic = uint16_t(in.mnemonic);
    d.operand_count = in.operandCount;
    d.flags_read = in.flagsRead;
    d.flags_written = in.flagsWritten;
    d.category = uint8_t(in.category);
    d.lock = in.prefixes.lock ? 1 : 0;
    d.rep = in.prefixes.rep;
    d.opsize = in.prefixes.opsize ? 1 : 0;
    d.addrsize = in.prefixes.addrsize ? 1 : 0;
    d.rex = in.prefixes.rex ? 1 : 0;
    d.vex = in.prefixes.vex ? 1 : 0;
    d.evex = in.prefixes.evex ? 1 : 0;
    for (int i = 0; i < in.operandCount && i < 4; ++i) fillOperand(d.operands[i], in.operands[i]);
}

} // namespace

extern "C" {

uint8_t d64_decode(const uint8_t* code, size_t n, uint64_t address, d64_insn* out) {
    DecodeResult r = decode(code, n, address);
    if (out) fillInsn(*out, r);
    return r.status == DecodeStatus::Ok ? r.insn.length : 0;
}

uint8_t d64_format(const uint8_t* code, size_t n, uint64_t address, int att, char* buf, size_t cap) {
    DecodeResult r = decode(code, n, address);
    std::string text = r.status == DecodeStatus::Ok
        ? (att ? formatAtt(r.insn) : formatIntel(r.insn))
        : (r.status == DecodeStatus::Truncated ? "(truncated)" : "(bad)");
    if (buf && cap) {
        size_t k = text.size() < cap - 1 ? text.size() : cap - 1;
        std::memcpy(buf, text.data(), k);
        buf[k] = '\0';
    }
    return r.status == DecodeStatus::Ok ? r.insn.length : 0;
}

uint8_t d64_relocate(const uint8_t* code, size_t n, uint64_t address, uint64_t new_address, uint8_t* out, size_t cap) {
    std::vector<uint8_t> bytes;
    if (!relocate(code, n, address, new_address, bytes)) return 0;
    if (bytes.size() > cap) return 0;
    if (out) std::memcpy(out, bytes.data(), bytes.size());
    return uint8_t(bytes.size());
}

const char* d64_reg_class_name(uint8_t reg_class) {
    static const char* names[] = {"none", "gpr8", "gpr8hi", "gpr16", "gpr32", "gpr64",
                                  "xmm", "ymm", "sreg", "rip", "st", "cr", "dr", "zmm", "k"};
    return reg_class < (sizeof names / sizeof names[0]) ? names[reg_class] : "?";
}

const char* d64_category_name(uint8_t category) {
    static const char* names[] = {"unknown", "gpr", "branch", "stack", "string", "flags",
                                  "sse", "avx", "avx512", "x87", "system", "nop"};
    return category < (sizeof names / sizeof names[0]) ? names[category] : "?";
}

const char* d64_version(void) { return "1.0"; }

} // extern "C"
