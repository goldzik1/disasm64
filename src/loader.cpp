#include "disasm64/loader.h"
#include <cstring>

namespace disasm64 {
namespace {

// Bounds-checked little-endian reads over an untrusted file buffer.
struct View {
    const uint8_t* p;
    size_t n;
    bool ok = true;
    uint16_t u16(size_t off) { if (off + 2 > n) { ok = false; return 0; } return uint16_t(p[off] | (p[off + 1] << 8)); }
    uint32_t u32(size_t off) {
        if (off + 4 > n) { ok = false; return 0; }
        return uint32_t(p[off]) | (uint32_t(p[off + 1]) << 8) | (uint32_t(p[off + 2]) << 16) | (uint32_t(p[off + 3]) << 24);
    }
    uint64_t u64(size_t off) { if (off + 8 > n) { ok = false; return 0; } return uint64_t(u32(off)) | (uint64_t(u32(off + 4)) << 32); }
};

} // namespace

LoadedImage loadImage(std::vector<uint8_t> fileBytes) {
    LoadedImage im;
    im.file = std::move(fileBytes);
    View v{im.file.data(), im.file.size()};

    // Not a PE -> treat the whole thing as raw code.
    if (im.file.size() < 0x40 || v.u16(0) != 0x5A4D /* 'MZ' */) {
        im.format = "raw";
        im.code.push_back({0, im.file.size(), 0, "raw"});
        return im;
    }
    uint32_t peOff = v.u32(0x3C);
    if (!v.ok || peOff + 24 > im.file.size() || v.u32(peOff) != 0x00004550 /* 'PE\0\0' */) {
        im.format = "raw";
        im.code.push_back({0, im.file.size(), 0, "raw"});
        return im;
    }

    im.isPE = true;
    uint16_t machine = v.u16(peOff + 4);
    im.machine = machine == 0x8664 ? "x86-64" : machine == 0x14C ? "x86" : "";
    uint16_t numSections = v.u16(peOff + 6);
    uint16_t optSize = v.u16(peOff + 20);
    size_t opt = peOff + 24;
    uint16_t magic = v.u16(opt);
    uint32_t entryRva = v.u32(opt + 16);
    if (magic == 0x20B) { im.format = "PE32+"; im.imageBase = v.u64(opt + 24); }
    else { im.format = "PE32"; im.imageBase = v.u32(opt + 28); }
    im.entry = entryRva ? im.imageBase + entryRva : 0;

    size_t sec = opt + optSize;
    for (uint16_t i = 0; i < numSections && v.ok; ++i, sec += 40) {
        char name[9] = {};
        if (sec + 40 > im.file.size()) break;
        std::memcpy(name, im.file.data() + sec, 8);
        uint32_t vsize = v.u32(sec + 8);
        uint32_t rva   = v.u32(sec + 12);
        uint32_t rawSz = v.u32(sec + 16);
        uint32_t rawPtr = v.u32(sec + 20);
        uint32_t chars = v.u32(sec + 36);
        bool exec = (chars & 0x20000000u) || (chars & 0x00000020u);   // MEM_EXECUTE | CNT_CODE
        if (!exec || !rawPtr || !rawSz) continue;
        size_t size = rawSz;
        if (vsize && vsize < size) size = vsize;               // trim to the mapped size
        if (rawPtr >= im.file.size()) continue;
        if (rawPtr + size > im.file.size()) size = im.file.size() - rawPtr;
        im.code.push_back({rawPtr, size, im.imageBase + rva, name[0] ? name : "sect"});
    }

    if (im.code.empty())   // no executable section found -> fall back to the whole file
        im.code.push_back({0, im.file.size(), im.imageBase, "image"});
    return im;
}

} // namespace disasm64
