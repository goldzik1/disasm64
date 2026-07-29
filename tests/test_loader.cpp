#include "check.h"
#include "disasm64/loader.h"
#include <cstdint>
#include <vector>
using namespace disasm64;

static void put16(std::vector<uint8_t>& b, size_t o, uint16_t v) { b[o] = uint8_t(v); b[o + 1] = uint8_t(v >> 8); }
static void put32(std::vector<uint8_t>& b, size_t o, uint32_t v) { for (int i = 0; i < 4; ++i) b[o + i] = uint8_t(v >> (8 * i)); }
static void put64(std::vector<uint8_t>& b, size_t o, uint64_t v) { for (int i = 0; i < 8; ++i) b[o + i] = uint8_t(v >> (8 * i)); }

TEST_MAIN({
    // raw blob (no MZ) -> one region at address 0
    {
        std::vector<uint8_t> raw = {0x90, 0x90, 0xC3};
        LoadedImage im = loadImage(raw);
        CHECK(!im.isPE);
        CHECK_STR(im.format, "raw");
        CHECK_EQ(int(im.code.size()), 1);
        CHECK_EQ((unsigned long long)im.code[0].vaddr, 0ull);
        CHECK_EQ(int(im.code[0].size), 3);
    }

    // hand-built minimal PE32+
    {
        std::vector<uint8_t> pe(0x210, 0);
        pe[0] = 'M'; pe[1] = 'Z';
        put32(pe, 0x3C, 0x40);                    // e_lfanew
        pe[0x40] = 'P'; pe[0x41] = 'E';           // PE\0\0
        put16(pe, 0x44, 0x8664);                  // machine = AMD64
        put16(pe, 0x46, 1);                       // 1 section
        put16(pe, 0x54, 0xF0);                    // SizeOfOptionalHeader
        put16(pe, 0x58, 0x20B);                   // PE32+ magic
        put32(pe, 0x68, 0x1000);                  // AddressOfEntryPoint
        put64(pe, 0x70, 0x140000000ull);          // ImageBase
        pe[0x148] = '.'; pe[0x149] = 't'; pe[0x14A] = 'e'; pe[0x14B] = 'x'; pe[0x14C] = 't';
        put32(pe, 0x150, 0x10);                   // VirtualSize
        put32(pe, 0x154, 0x1000);                 // VirtualAddress
        put32(pe, 0x158, 0x10);                   // SizeOfRawData
        put32(pe, 0x15C, 0x200);                  // PointerToRawData
        put32(pe, 0x16C, 0x60000020);             // CODE | EXECUTE | READ
        pe[0x200] = 0x55; pe[0x201] = 0xC3;       // push rbp; ret

        LoadedImage im = loadImage(pe);
        CHECK(im.isPE);
        CHECK_STR(im.format, "PE32+");
        CHECK_STR(im.machine, "x86-64");
        CHECK_EQ((unsigned long long)im.imageBase, 0x140000000ull);
        CHECK_EQ((unsigned long long)im.entry, 0x140001000ull);
        CHECK_EQ(int(im.code.size()), 1);
        CHECK_STR(im.code[0].name, ".text");
        CHECK_EQ((unsigned long long)im.code[0].vaddr, 0x140001000ull);
        CHECK_EQ(int(im.code[0].size), 0x10);
        CHECK_EQ(int(regionData(im, im.code[0])[0]), 0x55);
    }

    // hand-built minimal ELF64
    {
        std::vector<uint8_t> e(0x210, 0);
        e[0] = 0x7F; e[1] = 'E'; e[2] = 'L'; e[3] = 'F'; e[4] = 2; e[5] = 1;   // magic, ELFCLASS64, LE
        put16(e, 0x12, 0x3E);                     // e_machine = x86-64
        put64(e, 0x18, 0x401000);                 // e_entry
        put64(e, 0x28, 0x40);                     // e_shoff
        put16(e, 0x3A, 64);                       // e_shentsize
        put16(e, 0x3C, 3);                        // e_shnum
        put16(e, 0x3E, 2);                        // e_shstrndx
        // section 1 (.text) at 0x40 + 64
        size_t s1 = 0x80;
        put32(e, s1 + 0, 1);                      // sh_name -> ".text"
        put32(e, s1 + 4, 1);                      // PROGBITS
        put64(e, s1 + 8, 0x6);                    // ALLOC | EXECINSTR
        put64(e, s1 + 16, 0x401000);              // sh_addr
        put64(e, s1 + 24, 0x200);                 // sh_offset
        put64(e, s1 + 32, 4);                     // sh_size
        // section 2 (.shstrtab) at 0xC0
        size_t s2 = 0xC0;
        put32(e, s2 + 0, 7);                      // sh_name -> ".shstrtab"
        put32(e, s2 + 4, 3);                      // STRTAB
        put64(e, s2 + 24, 0x100);                 // sh_offset (string table)
        put64(e, s2 + 32, 0x11);                  // sh_size
        const char* strtab = "\0.text\0.shstrtab\0";
        for (int i = 0; i < 0x11; ++i) e[0x100 + i] = uint8_t(strtab[i]);
        e[0x200] = 0x55; e[0x201] = 0x48; e[0x202] = 0x89; e[0x203] = 0xE5;

        LoadedImage im = loadImage(e);
        CHECK(im.isELF);
        CHECK_STR(im.format, "ELF64");
        CHECK_STR(im.machine, "x86-64");
        CHECK_EQ((unsigned long long)im.entry, 0x401000ull);
        CHECK_EQ(int(im.code.size()), 1);
        CHECK_STR(im.code[0].name, ".text");
        CHECK_EQ((unsigned long long)im.code[0].vaddr, 0x401000ull);
        CHECK_EQ(int(regionData(im, im.code[0])[0]), 0x55);
    }
})
