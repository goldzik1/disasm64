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

// Every section of the mapped image (used for RVA translation and data scans).
struct Section {
    std::string name;
    uint64_t vaddr = 0;
    uint32_t vsize = 0;
    size_t   fileOffset = 0;
    uint32_t rawSize = 0;
    bool     exec = false;
};

struct LoadedImage {
    std::vector<uint8_t> file;
    std::vector<Section> sections;   // all sections
    std::vector<CodeRegion> code;    // executable subset, ready to disassemble
    uint64_t imageBase = 0;
    uint64_t entry = 0;              // entry-point virtual address (0 if unknown)
    bool isPE = false;
    bool isELF = false;
    std::string format;             // "PE32+", "PE32", "ELF64", "raw"
    std::string machine;            // "x86-64", "x86", or ""
    uint32_t importRva = 0, importSize = 0;   // PE import directory
    uint32_t exportRva = 0, exportSize = 0;   // PE export directory
};

// Parse a file image. Recognises PE (MZ/PE) and ELF64, pulling out executable sections at
// their virtual addresses; anything else is treated as a raw code blob at address 0.
LoadedImage loadImage(std::vector<uint8_t> fileBytes);

inline const uint8_t* regionData(const LoadedImage& im, const CodeRegion& r) {
    return im.file.data() + r.fileOffset;
}

// Translate a virtual address to a file offset (SIZE_MAX if it maps to no section's raw data).
size_t vaToOffset(const LoadedImage& im, uint64_t va);

} // namespace disasm64
