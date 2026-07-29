# disasm64

A from-scratch x86-64 instruction decoder in C++17. No Capstone, no Zydis, no
dependencies — you drop the headers and the `src/` files into a project and you have a
disassembler. It decodes a byte stream into a structured instruction (mnemonic, typed
operands with sizes, prefixes, length), resolves RIP-relative addressing, and prints
Intel syntax.

It's the decode counterpart to a small x64 *encoder* I wrote earlier, and having both
sides in hand buys features a plain disassembler can't give you — the first of which,
`relocate`, is already here.

## What works today

The general-purpose integer ISA: the legacy one/two-byte maps and REX — the arithmetic
group, mov/lea/push/pop, the shift and group-1/2/3/4/5 encodings, test, imul,
movzx/movsx/movsxd, the jcc/setcc/cmovcc families, call/jmp/ret, string ops, bit ops
(bt/bts/btr/btc), bswap/xadd/cmpxchg, and the full ModRM / SIB / displacement /
RIP-relative addressing that goes with them — plus `endbr64` and friends.

A curated slice of SSE is in too: the move and logic family
(movups/movaps/movdqa/movdqu, movss/movsd, movd/movq, pxor, xorps), scalar and packed
arithmetic (add/mul/sub/div/sqrt in ps/pd/ss/sd), and ucomiss/comisd — with xmm
operands and the right scalar-vs-packed memory sizes. Their **AVX (VEX)** forms decode
too — the three-operand `vaddss xmm0, xmm1, xmm2`, ymm operands, the lot.

Instruction length is byte-exact, and the decoder is fuzzed to never crash, hang, or
return a nonsense length on arbitrary input (millions of random decodes, zero anomalies).

```
$ disasm64 --base 0x401000 55 48 89 e5 48 83 ec 20 e8 00 00 00 00 0f b6 c1 c3
0000000000401000  55                       push rbp
0000000000401001  48 89 e5                 mov rbp, rsp
0000000000401004  48 83 ec 20              sub rsp, 0x20
0000000000401008  e8 00 00 00 00           call 0x40100d
000000000040100d  0f b6 c1                 movzx eax, cl
0000000000401010  c3                       ret
```

## relocate

Every instruction reports whether its bytes depend on where it lives (RIP-relative
memory, rel8/rel32 branches). `relocate` re-emits an instruction so it behaves
identically at a new address: position-independent instructions come back untouched,
and RIP-relative / rel32 displacements are fixed up so the effective target is
preserved. That's the primitive a trampoline or a hot-patcher needs, and no
disassembler I know of hands it to you directly.

```cpp
std::vector<uint8_t> out;
if (disasm64::relocate(bytes, n, oldAddr, newAddr, out)) {
    // `out` is the same instruction, valid at newAddr
}
```

## Building

```
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

C++17, no dependencies. Builds with MSVC or gcc/clang.

## The model

`decode(bytes, n, address)` returns a `DecodeResult` with a status and an
`Instruction`: mnemonic, up to four typed `Operand`s (register / memory /
immediate / relative, each with a size), the decoded prefixes, the length, and a
`positionDependent` flag. The Intel formatter is a thin layer over that model — the
structured decode is the point, so the same output feeds an analyzer or a lifter, not
just a printer.

## Roadmap

Being built in stages; the general-purpose core plus the SSE slice above is the
foundation.

- **Broaden SSE + AVX.** VEX decoding works for the covered opcodes; the rest of the
  SSE/AVX maps (shuffles, conversions, the FMA/AVX2 integer ops) come next, emitted
  from a permissive open ISA dataset and committed so the build stays dependency-free —
  the engine, operand model, and formatter stay hand-written.
- **Semantic metadata.** Per-instruction flags read/written, implicit operands,
  per-operand read/write access, and ISA-set / category.
- **RE layer.** A full hook/trampoline helper on top of `relocate`, an anti-disassembly
  annotator (overlapping instructions, junk prefixes, non-canonical encodings), and a
  redundant-encoding detector that uses the encoder to compute the canonical form.

## Scope

x86-64 long mode. AVX-512 / EVEX is out of scope. Intel syntax only for now (the
formatter is separate from the decoder, so AT&T can be added without touching decode).
