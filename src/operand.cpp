#include "operand.h"

namespace disasm64 {

Reg makeGpr(int num, int sizeBytes, bool rexPresent) {
    Reg reg;
    reg.idx = uint8_t(num);
    switch (sizeBytes) {
        case 1:
            if (!rexPresent && num >= 4 && num <= 7) { reg.cls = RegClass::Gpr8Hi; reg.idx = uint8_t(num); }
            else reg.cls = RegClass::Gpr8;
            break;
        case 2: reg.cls = RegClass::Gpr16; break;
        case 4: reg.cls = RegClass::Gpr32; break;
        case 8: reg.cls = RegClass::Gpr64; break;
        default: reg.cls = RegClass::Gpr64; break;
    }
    return reg;
}

int decodeModRM(Reader& r, const Prefixes& pfx, int rmSizeBytes, Operand& rm, RegClass rmRegClass) {
    uint8_t modrm = r.u8();
    int mod = modrm >> 6;
    int reg = ((modrm >> 3) & 7) | (pfx.rexR ? 8 : 0);
    int rmf = modrm & 7;
    const RegClass addrCls = pfx.addrsize ? RegClass::Gpr32 : RegClass::Gpr64;

    if (mod == 3) {                       // register direct
        rm.kind = OperandKind::Reg;
        rm.sizeBytes = uint8_t(rmSizeBytes);
        if (rmRegClass != RegClass::None) { rm.reg.cls = rmRegClass; rm.reg.idx = uint8_t(rmf | (pfx.rexB ? 8 : 0)); }
        else rm.reg = makeGpr(rmf | (pfx.rexB ? 8 : 0), rmSizeBytes, pfx.rex);
        return reg;
    }

    // memory
    rm.kind = OperandKind::Mem;
    rm.sizeBytes = uint8_t(rmSizeBytes);
    MemOperand m;
    m.segment = pfx.segment;

    if (rmf == 4) {                       // SIB
        uint8_t sib = r.u8();
        int scale = 1 << (sib >> 6);
        int index = ((sib >> 3) & 7) | (pfx.rexX ? 8 : 0);
        int base = (sib & 7) | (pfx.rexB ? 8 : 0);
        if (((sib >> 3) & 7) == 4 && !pfx.rexX) {
            m.index.cls = RegClass::None;         // no index (rsp slot); scale is then meaningless
            m.scale = 1;
        } else {
            m.index.cls = addrCls; m.index.idx = uint8_t(index);
            m.scale = uint8_t(scale);
        }
        if ((sib & 7) == 5 && mod == 0) {
            m.base.cls = RegClass::None;          // no base, disp32
            m.dispOffset = uint8_t(r.pos); m.dispSize = 4; m.disp = r.imm(4);
        } else {
            m.base.cls = addrCls; m.base.idx = uint8_t(base);
            if (mod == 1) { m.dispOffset = uint8_t(r.pos); m.dispSize = 1; m.disp = r.imm(1); }
            else if (mod == 2) { m.dispOffset = uint8_t(r.pos); m.dispSize = 4; m.disp = r.imm(4); }
        }
    } else if (rmf == 5 && mod == 0) {    // RIP-relative
        m.ripRelative = true;
        m.base.cls = RegClass::Rip;
        m.dispOffset = uint8_t(r.pos); m.dispSize = 4; m.disp = r.imm(4);
    } else {
        m.base.cls = addrCls; m.base.idx = uint8_t(rmf | (pfx.rexB ? 8 : 0));
        if (mod == 1) { m.dispOffset = uint8_t(r.pos); m.dispSize = 1; m.disp = r.imm(1); }
        else if (mod == 2) { m.dispOffset = uint8_t(r.pos); m.dispSize = 4; m.disp = r.imm(4); }
    }

    rm.mem = m;
    return reg;
}

} // namespace disasm64
