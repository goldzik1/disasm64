// disasm64 C ABI -- a flat, extern "C" surface for FFI (Rust, Go, C#, Python, ...).
#ifndef DISASM64_C_API_H
#define DISASM64_C_API_H

#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32)
  #if defined(D64_BUILD)
    #define D64_API __declspec(dllexport)
  #else
    #define D64_API __declspec(dllimport)
  #endif
#else
  #define D64_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Operand kinds
enum { D64_OP_NONE = 0, D64_OP_REG = 1, D64_OP_MEM = 2, D64_OP_IMM = 3, D64_OP_REL = 4 };
// Decode status
enum { D64_OK = 0, D64_INVALID = 1, D64_TRUNCATED = 2 };

typedef struct d64_operand {
    uint8_t  kind;          // D64_OP_*
    uint8_t  size;          // bytes: 1,2,4,8,16,32,64
    uint8_t  reg_class;     // RegClass enum value (see reg_class_name)
    uint8_t  reg_index;
    uint8_t  base_class,  base_index;   // memory base register
    uint8_t  index_class, index_index;  // memory index register
    uint8_t  scale;         // 1,2,4,8
    uint8_t  segment;       // 0xFF none, else 0..5
    uint8_t  rip_relative;
    int64_t  disp;
    int64_t  imm;
    uint64_t rel_target;    // absolute target for REL/RIP operands
    uint8_t  access;        // 0 none, 1 read, 2 write, 3 read+write
} d64_operand;

typedef struct d64_insn {
    uint64_t address;
    uint8_t  status;        // D64_OK / D64_INVALID / D64_TRUNCATED
    uint8_t  length;
    uint16_t mnemonic;      // Mnemonic enum value (0 when a raw-name SIMD op)
    uint8_t  operand_count;
    uint8_t  flags_read, flags_written;   // EFLAGS bitmask (CF PF AF ZF SF OF DF = 1,2,4,8,16,32,64)
    uint8_t  category;      // Category enum (see category_name)
    uint8_t  lock, rep, opsize, addrsize, rex, vex, evex;
    d64_operand operands[4];
} d64_insn;

// Decode one instruction at `address`. Fills *out. Returns the instruction length
// (0 when not D64_OK). `out->status` carries the detailed status.
D64_API uint8_t d64_decode(const uint8_t* code, size_t n, uint64_t address, d64_insn* out);

// Decode and format into `buf` (NUL-terminated, truncated to `cap`). `att` selects AT&T
// syntax. Returns the instruction length (0 on failure).
D64_API uint8_t d64_format(const uint8_t* code, size_t n, uint64_t address, int att, char* buf, size_t cap);

// Re-emit the instruction at `new_address`, fixing up RIP-relative and rel32 targets.
// Returns the encoded length, or 0 if it could not be relocated.
D64_API uint8_t d64_relocate(const uint8_t* code, size_t n, uint64_t address, uint64_t new_address, uint8_t* out, size_t cap);

// Human-readable name for a register class value (RegClass enum).
D64_API const char* d64_reg_class_name(uint8_t reg_class);

// Human-readable name for a Category value.
D64_API const char* d64_category_name(uint8_t category);

// Library version string, e.g. "1.0".
D64_API const char* d64_version(void);

#ifdef __cplusplus
}
#endif

#endif // DISASM64_C_API_H
