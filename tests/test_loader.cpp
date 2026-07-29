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
})
