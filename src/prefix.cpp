#include "prefix.h"

namespace disasm64 {

bool decodePrefixes(Reader& r, Prefixes& pfx) {
    for (;;) {
        if (r.remaining() == 0) return false;
        uint8_t b = r.peek();
        switch (b) {
            case 0xF0: pfx.lock = true; r.u8(); continue;
            case 0xF2: pfx.rep = 0xF2; r.u8(); continue;
            case 0xF3: pfx.rep = 0xF3; r.u8(); continue;
            case 0x2E: pfx.segment = 1; r.u8(); continue;   // CS
            case 0x36: pfx.segment = 2; r.u8(); continue;   // SS
            case 0x3E: pfx.segment = 3; r.u8(); continue;   // DS
            case 0x26: pfx.segment = 0; r.u8(); continue;   // ES
            case 0x64: pfx.segment = 4; r.u8(); continue;   // FS
            case 0x65: pfx.segment = 5; r.u8(); continue;   // GS
            case 0x66: pfx.opsize = true; r.u8(); continue;
            case 0x67: pfx.addrsize = true; r.u8(); continue;
            default: break;
        }
        break;
    }

    // VEX must come before REX and is mutually exclusive with it.
    uint8_t b = r.peek();
    if (b == 0xC5 || b == 0xC4) {
        // Only a VEX if the following byte's top bits look like VEX (in 64-bit the
        // legacy LDS/LES forms don't exist, so C4/C5 are always VEX here).
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
        pfx.rex = true;           // VEX carries REX-equivalent bits
        return r.ok();
    }

    if (b >= 0x40 && b <= 0x4F) {
        pfx.rex = true;
        pfx.rexW = (b >> 3) & 1;
        pfx.rexR = (b >> 2) & 1;
        pfx.rexX = (b >> 1) & 1;
        pfx.rexB = b & 1;
        r.u8();
    }
    return r.ok();
}

} // namespace disasm64
