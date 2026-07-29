# disasm64

[![ci](https://github.com/goldzik1/disasm64/actions/workflows/ci.yml/badge.svg)](https://github.com/goldzik1/disasm64/actions/workflows/ci.yml)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)
![deps](https://img.shields.io/badge/dependencies-none-brightgreen)

A from-scratch x86-64 instruction decoder in C++17. No Capstone, no Zydis, no
dependencies — drop the headers and `src/` into a project and you have a disassembler.
It decodes a byte stream into a structured instruction (mnemonic, typed operands with
sizes, prefixes, length), resolves RIP-relative addressing, and prints Intel or AT&T syntax.

But decoding is table stakes. What this does that a plain disassembler doesn't:

- **flags obfuscation** — redundant prefixes, over-long encodings, and other
  non-canonical forms that are the fingerprints of packers, watermarking, and
  hand-crafted code;
- **catches anti-disassembly** — branches that jump into the middle of another
  instruction (hidden / overlapping code), the classic linear-sweep trap;
- **relocates instructions** — moves an instruction to a new address with RIP-relative
  and rel32 fixed up, which is exactly the primitive a trampoline hook needs, so it also
  **plans hooks** (how many bytes to steal, relocated and ready to place).

```
$ disasm64 --base 0x401000 66 66 90 48 8b 80 05 00 00 00 eb 01 48 90
0000000000401000  66 66 90                 nop
                    ! duplicate prefix
0000000000401003  48 8b 80 05 00 00 00     mov rax, qword ptr [rax+0x5]
                    ! over-long disp32 (fits in disp8)
000000000040100a  eb 01                    jmp 0x40100d
000000000040100c  48 90                    nop
000000000040100a  !! branch target inside another instruction (anti-disassembly)
```

## Coverage

The general-purpose integer ISA — the legacy one/two-byte maps and REX: the arithmetic
group, mov/lea/push/pop, the shift and group encodings, test, imul, movzx/movsx/movsxd,
jcc/setcc/cmovcc, call/jmp/ret, string ops, bit ops, bswap/xadd/cmpxchg, bsf/bsr,
popcnt/lzcnt/tzcnt, crc32, the fences, movbe, endbr64 — with full ModRM / SIB /
displacement / RIP-relative addressing, byte-exact length.

The vector ISA — **SSE through SSE4.2 and AVX/AVX2**: moves, logic, arithmetic,
min/max, compares, conversions, the packed-integer set (padd/psub/pmul/pcmp/pack/punpck/
pavg/psad/pmin/pmax and the shift families), shuffles, blends, `ptest`, `pmovzx/sx`,
`palignr`, `roundps`, `dpps`, `pclmulqdq`, the `pcmp*str*` string ops — across the one-,
two-, and three-byte (`0F38`/`0F3A`) maps. Every one of these has its **AVX (VEX)** form
too: three-operand `vaddss xmm0, xmm1, xmm2`, `vpshufb ymm0, ymm0, ymm1`, ymm operands,
2- and 3-byte VEX.

The **x87 FPU** — the full `D8`–`DF` map, both the memory forms (`fld`/`fst`/`fadd`/
`fild`/`fbld` sized down to `tbyte ptr`) and the `mod == 3` register forms: the `st(i)`
arithmetic, `fcmov*`, `fucomi`/`fcomi`, the load-constant and transcendental group
(`fld1`/`fldpi`/`fsin`/`fpatan`/`f2xm1`…), `fnstsw ax`, and the `fsub`/`fsubr` reg-form
swap handled per the SDM.

The decoder is fuzzed to never crash, hang, or return a nonsense length on arbitrary
input — millions of random decodes, zero anomalies.

## The RE layer

```cpp
#include "disasm64/analysis.h"

// what a trampoline hook needs: steal >= 5 bytes of whole instructions, relocated
disasm64::HookPlan hp = disasm64::planHook(code, n, addr, trampolineAddr, 5);
// hp.stolenBytes, hp.relocatable, hp.relocated  (valid at trampolineAddr)

// obfuscation / hand-crafted-code signals for one instruction
for (const char* issue : disasm64::analyzeEncoding(code, n, addr)) puts(issue);

// hidden / overlapping code across a range
for (auto& f : disasm64::antiDisasmScan(code, n, base)) /* f.address, f.what */;
```

`relocate` underpins the hook planner and is exposed on its own — position-independent
instructions come back byte-for-byte, RIP-relative and rel32 displacements are fixed up
so the effective target is preserved.

## Building

Drop `include/` and `src/` into your project, or take the **single header** — one file,
STB-style:

```cpp
#define DISASM64_IMPLEMENTATION   // in exactly one translation unit
#include "disasm64.h"             // from single_include/
```

Or build the tests, examples, and CLI with CMake:

```
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

C++17, no dependencies, builds with MSVC or gcc/clang. Regenerate the single header with
`tools/amalgamate.sh` after editing the split sources.

## The model

`decode(bytes, n, address)` returns a `DecodeResult` with a status and an
`Instruction`: mnemonic, up to four typed `Operand`s (register / memory / immediate /
relative, each with a size), the prefixes, the length, and a `positionDependent` flag.
The **Intel and AT&T** formatters are thin layers over that model — the structured decode
is the point, so the same output feeds an analyzer or a lifter, not just a printer.
Per-instruction EFLAGS read/written are already on the model (`flagsRead`/`flagsWritten`);
the CLI surfaces them with `--flags`, and `--att` switches syntax.

## Roadmap

- Richer semantic metadata: implicit operands, per-operand read/write access,
  ISA-set / category.
- AVX-512 / EVEX, emitted from a permissive open ISA dataset and committed so the build
  stays dependency-free.
- External differential validation against `llvm-mc` over a large corpus.

## Scope

x86-64 long mode, Intel and AT&T syntax. AVX-512 / EVEX is out of scope for now.
