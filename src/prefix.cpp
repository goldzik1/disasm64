#include "prefix.h"

namespace disasm64 {

bool decodePrefixes(Reader& r, Prefixes& pfx) {
    // A REX byte is effective only when it is the last prefix before the opcode;
    // any legacy prefix that follows it cancels it, and a later REX overrides.
    uint8_t rexByte = 0; bool haveRex = false;
    for (;;) {
        if (r.remaining() == 0) return false;
        uint8_t b = r.peek();
        switch (b) {
            case 0xF0: pfx.lock = true; haveRex = false; r.u8(); continue;
            case 0xF2: pfx.rep = 0xF2; haveRex = false; r.u8(); continue;
            case 0xF3: pfx.rep = 0xF3; haveRex = false; r.u8(); continue;
            case 0x2E: pfx.segment = 1; haveRex = false; r.u8(); continue;   // CS
            case 0x36: pfx.segment = 2; haveRex = false; r.u8(); continue;   // SS
            case 0x3E: pfx.segment = 3; haveRex = false; r.u8(); continue;   // DS
            case 0x26: pfx.segment = 0; haveRex = false; r.u8(); continue;   // ES
            case 0x64: pfx.segment = 4; haveRex = false; r.u8(); continue;   // FS
            case 0x65: pfx.segment = 5; haveRex = false; r.u8(); continue;   // GS
            case 0x66: pfx.opsize = true; haveRex = false; r.u8(); continue;
            case 0x67: pfx.addrsize = true; haveRex = false; r.u8(); continue;
            default: break;
        }
        if (b >= 0x40 && b <= 0x4F) { rexByte = b; haveRex = true; r.u8(); continue; }
        break;
    }

    uint8_t b = r.peek();
    // VEX may not be preceded by REX or a 66/F2/F3/F0 prefix (those make it #UD).
    if (!haveRex && !pfx.opsize && pfx.rep == 0 && !pfx.lock && (b == 0xC5 || b == 0xC4)) {
        pfx.vex = true;
        r.u8();
        if (b == 0xC5) {          // 2-byte VEX
            uint8_t v = r.u8();
            pfx.rexR = !(v & 0x80);
            pfx.vexVVVV = (~(v >> 3)) & 0x0F;
            pfx.vexL = (v >> 2) & 1;
            pfx.vexPP = v & 3;
            pfx.vexMap = 1;       // implied 0F
        } else {                  // 3-byte VEX
            uint8_t v1 = r.u8(), v2 = r.u8();
            pfx.rexR = !(v1 & 0x80);
            pfx.rexX = !(v1 & 0x40);
            pfx.rexB = !(v1 & 0x20);
            pfx.vexMap = v1 & 0x1F;      // 1=0F 2=0F38 3=0F3A
            pfx.vexW = (v2 >> 7) & 1;
            pfx.rexW = pfx.vexW;
            pfx.vexVVVV = (~(v2 >> 3)) & 0x0F;
            pfx.vexL = (v2 >> 2) & 1;
            pfx.vexPP = v2 & 3;
        }
        pfx.rex = true;
        return r.ok();
    }

    if (haveRex) {
        pfx.rex = true;
        pfx.rexW = (rexByte >> 3) & 1;
        pfx.rexR = (rexByte >> 2) & 1;
        pfx.rexX = (rexByte >> 1) & 1;
        pfx.rexB = rexByte & 1;
    }
    return r.ok();
}

} // namespace disasm64
