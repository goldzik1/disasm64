#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace disasm64 {

// One executable region to disassemble, with the virtual address it lives at.
struct CodeRegion {
    size_t   fileOffset = 0;   // offset of the bytes within LoadedImage::file
    size_t   size = 0;
    uint64_t vaddr = 0;        // virtual address to decode at
    std::string name;         // section name, or "raw"
};

struct LoadedImage {
    std::vector<uint8_t> file;
    std::vector<CodeRegion> code;   // executable sections (or the whole file for raw input)
    uint64_t imageBase = 0;
    uint64_t entry = 0;             // entry-point virtual address (0 if unknown)
    bool isPE = false;
    std::string format;             // "PE32+", "PE32", "raw"
    std::string machine;            // "x86-64", "x86", or ""
};

// Parse a file image. Recognises PE (MZ/PE) and pulls out its executable sections at the
// right virtual addresses; anything else is treated as a raw code blob at address 0.
LoadedImage loadImage(std::vector<uint8_t> fileBytes);

inline const uint8_t* regionData(const LoadedImage& im, const CodeRegion& r) {
    return im.file.data() + r.fileOffset;
}

} // namespace disasm64
