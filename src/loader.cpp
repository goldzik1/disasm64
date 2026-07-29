#include "disasm64/loader.h"
#include <cstring>

namespace disasm64 {
namespace {

// Bounds-checked little-endian reads over an untrusted file buffer.
struct View {
    const uint8_t* p;
    size_t n;
    bool ok = true;
    uint16_t u16(size_t o) { if (o + 2 > n) { ok = false; return 0; } return uint16_t(p[o] | (p[o + 1] << 8)); }
    uint32_t u32(size_t o) {
        if (o + 4 > n) { ok = false; return 0; }
        return uint32_t(p[o]) | (uint32_t(p[o + 1]) << 8) | (uint32_t(p[o + 2]) << 16) | (uint32_t(p[o + 3]) << 24);
    }
    uint64_t u64(size_t o) { if (o + 8 > n) { ok = false; return 0; } return uint64_t(u32(o)) | (uint64_t(u32(o + 4)) << 32); }
};

void deriveCode(LoadedImage& im) {
    for (const Section& s : im.sections)
        if (s.exec && s.rawSize) im.code.push_back({s.fileOffset, s.rawSize, s.vaddr, s.name});
    if (im.code.empty() && !im.sections.empty())
        im.code.push_back({im.sections[0].fileOffset, im.sections[0].rawSize, im.sections[0].vaddr, im.sections[0].name});
}

LoadedImage raw(std::vector<uint8_t> file) {
    LoadedImage im;
    im.file = std::move(file);
    im.format = "raw";
    im.sections.push_back({"raw", 0, uint32_t(im.file.size()), 0, uint32_t(im.file.size()), true});
    im.code.push_back({0, im.file.size(), 0, "raw"});
    return im;
}

LoadedImage loadPE(std::vector<uint8_t> file, uint32_t peOff) {
    LoadedImage im;
    im.file = std::move(file);
    im.isPE = true;
    View v{im.file.data(), im.file.size()};

    uint16_t machine = v.u16(peOff + 4);
    im.machine = machine == 0x8664 ? "x86-64" : machine == 0x14C ? "x86" : "";
    uint16_t numSections = v.u16(peOff + 6);
    uint16_t optSize = v.u16(peOff + 20);
    size_t opt = peOff + 24;
    uint16_t magic = v.u16(opt);
    uint32_t entryRva = v.u32(opt + 16);
    size_t dd;
    if (magic == 0x20B) { im.format = "PE32+"; im.imageBase = v.u64(opt + 24); dd = opt + 112; }
    else { im.format = "PE32"; im.imageBase = v.u32(opt + 28); dd = opt + 96; }
    im.entry = entryRva ? im.imageBase + entryRva : 0;
    im.exportRva = v.u32(dd);      im.exportSize = v.u32(dd + 4);
    im.importRva = v.u32(dd + 8);  im.importSize = v.u32(dd + 12);

    size_t sec = opt + optSize;
    for (uint16_t i = 0; i < numSections && v.ok; ++i, sec += 40) {
        if (sec + 40 > im.file.size()) break;
        char name[9] = {};
        std::memcpy(name, im.file.data() + sec, 8);
        uint32_t vsize = v.u32(sec + 8), rva = v.u32(sec + 12);
        uint32_t rawSz = v.u32(sec + 16), rawPtr = v.u32(sec + 20), chars = v.u32(sec + 36);
        bool exec = (chars & 0x20000000u) || (chars & 0x00000020u);
        size_t size = rawSz;
        if (rawPtr >= im.file.size()) { rawPtr = 0; size = 0; }
        else if (rawPtr + size > im.file.size()) size = im.file.size() - rawPtr;
        im.sections.push_back({name[0] ? name : "sect", im.imageBase + rva, vsize, rawPtr, uint32_t(size), exec});
    }
    deriveCode(im);
    return im;
}

LoadedImage loadELF(std::vector<uint8_t> file) {
    LoadedImage im;
    im.file = std::move(file);
    im.isELF = true;
    im.format = "ELF64";
    View v{im.file.data(), im.file.size()};

    uint16_t machine = v.u16(0x12);
    im.machine = machine == 0x3E ? "x86-64" : machine == 0x03 ? "x86" : "";
    im.entry = v.u64(0x18);
    uint64_t shoff = v.u64(0x28);
    uint16_t shentsize = v.u16(0x3A), shnum = v.u16(0x3C), shstrndx = v.u16(0x3E);

    size_t strtabOff = 0;
    if (shstrndx < shnum) {
        size_t sh = size_t(shoff) + size_t(shstrndx) * shentsize;
        strtabOff = size_t(v.u64(sh + 24));
    }
    for (uint16_t i = 0; i < shnum && v.ok; ++i) {
        size_t sh = size_t(shoff) + size_t(i) * shentsize;
        if (sh + 64 > im.file.size()) break;
        uint32_t nameOff = v.u32(sh);
        uint64_t flags = v.u64(sh + 8);
        uint64_t addr = v.u64(sh + 16);
        uint64_t off = v.u64(sh + 24);
        uint64_t size = v.u64(sh + 32);
        if (!(flags & 0x2 /*SHF_ALLOC*/) || !addr || !size) continue;
        std::string name = "sect";
        if (strtabOff && strtabOff + nameOff < im.file.size()) {
            const char* s = reinterpret_cast<const char*>(im.file.data() + strtabOff + nameOff);
            size_t maxLen = im.file.size() - (strtabOff + nameOff);
            name.assign(s, strnlen(s, maxLen));
        }
        size_t rawPtr = size_t(off), rawSz = size_t(size);
        if (rawPtr > im.file.size()) rawSz = 0;
        else if (rawPtr + rawSz > im.file.size()) rawSz = im.file.size() - rawPtr;
        im.sections.push_back({name, addr, uint32_t(size), rawPtr, uint32_t(rawSz), (flags & 0x4 /*SHF_EXECINSTR*/) != 0});
    }
    deriveCode(im);
    return im;
}

} // namespace

LoadedImage loadImage(std::vector<uint8_t> fileBytes) {
    View v{fileBytes.data(), fileBytes.size()};
    if (fileBytes.size() >= 0x40 && v.u16(0) == 0x5A4D) {          // 'MZ'
        uint32_t peOff = v.u32(0x3C);
        if (v.ok && peOff + 24 <= fileBytes.size() && v.u32(peOff) == 0x00004550)  // 'PE\0\0'
            return loadPE(std::move(fileBytes), peOff);
    }
    if (fileBytes.size() >= 64 && fileBytes[0] == 0x7F && fileBytes[1] == 'E' &&
        fileBytes[2] == 'L' && fileBytes[3] == 'F' && fileBytes[4] == 2 /*ELFCLASS64*/)
        return loadELF(std::move(fileBytes));
    return raw(std::move(fileBytes));
}

size_t vaToOffset(const LoadedImage& im, uint64_t va) {
    for (const Section& s : im.sections) {
        uint64_t span = s.vsize > s.rawSize ? s.vsize : s.rawSize;
        if (va >= s.vaddr && va < s.vaddr + span) {
            uint64_t d = va - s.vaddr;
            if (d < s.rawSize) return s.fileOffset + size_t(d);
        }
    }
    return SIZE_MAX;
}

} // namespace disasm64
