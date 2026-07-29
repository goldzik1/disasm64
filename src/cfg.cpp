#include "disasm64/cfg.h"
#include "disasm64/disasm64.h"
#include <algorithm>
#include <cstring>
#include <map>
#include <set>

namespace disasm64 {
namespace {

using M = Mnemonic;
enum Kind : uint8_t { Normal, Cond, Uncond, Ret };

struct Info {
    uint8_t len;
    Kind kind;
    uint64_t target;      // branch target (only for Cond/Uncond with a rel operand)
    bool hasTarget;
};

bool isReturn(const Instruction& in) {
    if (in.mnemonic == M::Ret || in.mnemonic == M::Hlt || in.mnemonic == M::Ud2) return true;
    if (in.rawName && (!std::strcmp(in.rawName, "retf") || !std::strcmp(in.rawName, "iretd") ||
                       !std::strcmp(in.rawName, "iretq") || !std::strcmp(in.rawName, "iret") ||
                       !std::strcmp(in.rawName, "sysret") || !std::strcmp(in.rawName, "sysexit"))) return true;
    return false;
}

bool isLoop(const char* r) {
    return r && (!std::strcmp(r, "loop") || !std::strcmp(r, "loopne") || !std::strcmp(r, "loope") ||
                 !std::strcmp(r, "jrcxz") || !std::strcmp(r, "jecxz"));
}

} // namespace

Cfg buildCfg(const uint8_t* code, size_t n, uint64_t base, uint64_t entry) {
    Cfg cfg;
    cfg.entry = entry;
    auto inRange = [&](uint64_t va) { return va >= base && va < base + n; };
    if (!inRange(entry)) return cfg;

    std::map<uint64_t, Info> insn;
    std::set<uint64_t> leaders{entry};
    std::set<uint64_t> callTargets;
    std::vector<uint64_t> work{entry};

    while (!work.empty()) {
        uint64_t a = work.back();
        work.pop_back();
        while (inRange(a) && !insn.count(a)) {
            DecodeResult r = decode(code + (a - base), n - (a - base), a);
            if (r.status != DecodeStatus::Ok) { insn[a] = {1, Ret, 0, false}; break; }
            const Instruction& in = r.insn;
            uint8_t len = in.length;
            bool relOp = in.operandCount && in.operands[0].kind == OperandKind::Rel;
            uint64_t tgt = relOp ? in.operands[0].relTarget : 0;

            if (in.mnemonic == M::Jcc || isLoop(in.rawName)) {
                insn[a] = {len, Cond, tgt, relOp};
                if (relOp && inRange(tgt)) work.push_back(tgt);
                leaders.insert(a + len);
                if (relOp) leaders.insert(tgt);
                a += len;                                  // fall through to the next instruction
                continue;
            }
            if (in.mnemonic == M::Jmp) {
                insn[a] = {len, Uncond, tgt, relOp};
                if (relOp) { leaders.insert(tgt); if (inRange(tgt)) work.push_back(tgt); }
                break;                                     // no fall-through
            }
            if (isReturn(in)) { insn[a] = {len, Ret, 0, false}; break; }
            if (in.mnemonic == M::Call) {
                if (relOp) callTargets.insert(tgt);
                insn[a] = {len, Normal, 0, false};         // a call returns; keep going
                a += len;
                continue;
            }
            insn[a] = {len, Normal, 0, false};
            a += len;
        }
    }

    for (uint64_t l : leaders) {
        if (!insn.count(l)) continue;
        BasicBlock b;
        b.start = l;
        uint64_t a = l;
        for (;;) {
            auto it = insn.find(a);
            if (it == insn.end()) { b.end = a; break; }
            uint64_t next = a + it->second.len;
            const Info& info = it->second;
            if (info.kind == Ret) { b.end = next; break; }
            if (info.kind == Uncond) { b.end = next; if (info.hasTarget) b.succs.push_back(info.target); break; }
            if (info.kind == Cond) {
                b.end = next;
                if (info.hasTarget) b.succs.push_back(info.target);
                b.succs.push_back(next);
                break;
            }
            if (next != l && leaders.count(next)) { b.end = next; b.succs.push_back(next); break; }
            if (!insn.count(next)) { b.end = next; break; }
            a = next;
        }
        cfg.blocks.push_back(std::move(b));
    }
    std::sort(cfg.blocks.begin(), cfg.blocks.end(),
              [](const BasicBlock& x, const BasicBlock& y) { return x.start < y.start; });
    cfg.calls.assign(callTargets.begin(), callTargets.end());
    return cfg;
}

} // namespace disasm64
