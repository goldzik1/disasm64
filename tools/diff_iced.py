#!/usr/bin/env python3
# Differential validator: compares disasm64 against iced-x86 (reference decoder).
# Generates random + structured byte streams, decodes one instruction at offset 0
# with both, and buckets disagreements. High-signal checks: validity agreement and
# instruction length. Mnemonic/operand text is reported informationally.
#
#   pip install iced-x86
#   python tools/diff_iced.py --tool build/difftool.exe --count 2000000
import argparse, random, subprocess, sys
from collections import Counter

import iced_x86 as I

ENC_OUT_OF_SCOPE = {2, 3, 4, 5}  # EVEX, XOP, D3NOW, MVEX -- intentionally unimplemented
MMX_LO, MMX_HI = int(I.Register.MM0), int(I.Register.MM7)
NO_MORE_BYTES = int(I.DecoderError.NO_MORE_BYTES)
PAD = 0x90

# Mnemonics disasm64 does not implement on purpose -- MMX and its xmm<->mm converts
# (whose memory forms don't expose an mm register, so the MMX register filter misses them).
UNSUPPORTED = {
    "cvtpi2ps", "cvtpi2pd", "cvtps2pi", "cvtpd2pi", "cvttps2pi", "cvttpd2pi",
    "movdq2q", "movq2dq", "maskmovq", "emms",
    # SSE4a (AMD) and VIA PadLock -- vendor extensions out of scope
    "extrq", "insertq", "movntsd", "movntss",
    "xstore", "xcryptecb", "xcryptcbc", "xcryptctr", "xcryptcfb", "xcryptofb",
    "montmul", "xsha1", "xsha256", "xstore-rng",
}

MODRMS = [0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x40, 0x44, 0x45, 0x48,
          0x80, 0x84, 0x85, 0xC0, 0xC1, 0xC8, 0xD0, 0xE0, 0xF8]


def pad15(b):
    b = bytes(b)[:15]
    return (b + bytes([PAD]) * (15 - len(b))).hex()


def gen_random(n, seed):
    r = random.Random(seed)
    for _ in range(n):
        ln = r.randint(1, 15)
        yield bytes(r.getrandbits(8) for _ in range(ln))


def gen_structured():
    out = []
    add = out.append
    small = [0xC0, 0x04, 0x05, 0x44, 0x00, 0x40]
    # 1-byte legacy
    for pfx in (b"", b"\x66", b"\xf2", b"\xf3"):
        for rex in (b"", b"\x48", b"\x4c", b"\x44"):
            for op in range(256):
                if op == 0x0F:
                    continue
                for m in MODRMS:
                    add(pfx + rex + bytes([op, m, 0x11, 0x22, 0x33, 0x44]))
    # 0F two-byte
    for pfx in (b"", b"\x66", b"\xf2", b"\xf3"):
        for op in range(256):
            for m in small:
                add(pfx + bytes([0x0F, op, m, 0x11, 0x22, 0x33, 0x44]))
    # 0F38 / 0F3A three-byte
    for mapb in (0x38, 0x3A):
        for pfx in (b"", b"\x66", b"\xf2", b"\xf3"):
            for op in range(256):
                for m in (0xC1, 0x04, 0x00):
                    add(pfx + bytes([0x0F, mapb, op, m, 0x11, 0x22, 0x33]))
    # VEX 2-byte (C5)
    for L in (0, 1):
        for pp in range(4):
            b2 = 0x80 | (0b1111 << 3) | (L << 2) | pp
            for op in range(256):
                for m in (0xC1, 0x04):
                    add(bytes([0xC5, b2, op, m, 0x11, 0x22, 0x33]))
    # VEX 3-byte (C4)
    for mp in (1, 2, 3):
        b2 = 0xE0 | mp
        for W in (0, 1):
            for L in (0, 1):
                for pp in range(4):
                    b3 = (W << 7) | (0b1111 << 3) | (L << 2) | pp
                    for op in range(256):
                        for m in (0xC1, 0x04):
                            add(bytes([0xC4, b2, b3, op, m, 0x11, 0x22]))
    # x87
    for op in range(0xD8, 0xE0):
        for m in MODRMS:
            add(bytes([op, m, 0x11, 0x22, 0x33]))
    # EVEX (map 1) -- exercise the AVX-512 core: various length/W/pp/mask
    for W in (0, 1):
        for pp in range(4):
            for LL in (0, 1, 2):
                for z, aaa in ((0, 0), (1, 1)):
                    p1 = (W << 7) | 0x78 | 0x04 | pp        # vvvv=1111, fixed bit, pp
                    p2 = (z << 7) | (LL << 5) | 0x08 | aaa  # V'=1, no broadcast
                    for op in range(256):
                        for m in (0xC1, 0x04):
                            add(bytes([0x62, 0xF1, p1, p2, op, m, 0x02, 0x11, 0x22, 0x33]))
    return out


# conditional-code and other benign naming aliases -> canonical
_ALIAS_GROUPS = [
    {"jz", "je"}, {"jnz", "jne"}, {"jb", "jc", "jnae"}, {"jnb", "jae", "jnc"},
    {"jbe", "jna"}, {"ja", "jnbe"}, {"jp", "jpe"}, {"jnp", "jpo"},
    {"jl", "jnge"}, {"jge", "jnl"}, {"jle", "jng"}, {"jg", "jnle"},
    {"setz", "sete"}, {"setnz", "setne"}, {"setb", "setc", "setnae"}, {"setnb", "setae", "setnc"},
    {"setbe", "setna"}, {"seta", "setnbe"}, {"setl", "setnge"}, {"setge", "setnl"},
    {"setle", "setng"}, {"setg", "setnle"}, {"setp", "setpe"}, {"setnp", "setpo"},
    {"cmovz", "cmove"}, {"cmovnz", "cmovne"}, {"cmovb", "cmovc", "cmovnae"}, {"cmovnb", "cmovae", "cmovnc"},
    {"cmovbe", "cmovna"}, {"cmova", "cmovnbe"}, {"cmovl", "cmovnge"}, {"cmovge", "cmovnl"},
    {"cmovle", "cmovng"}, {"cmovg", "cmovnle"}, {"cmovp", "cmovpe"}, {"cmovnp", "cmovpo"},
    {"ret", "retn"}, {"movsxd", "movslq"}, {"cbw", "cbtw"}, {"cwde", "cwtl"}, {"cdqe", "cltq"},
    {"cwd", "cwtd"}, {"cdq", "cltd"}, {"cqo", "cqto"}, {"loadall", "loadalld"},
]
_ALIAS = {}
for _g in _ALIAS_GROUPS:
    _c = sorted(_g)[0]
    for _m in _g:
        _ALIAS[_m] = _c


def canon_mnem(m):
    m = m.strip().lower()
    for rep in ("rep ", "repe ", "repne ", "repz ", "repnz ", "lock ", "rex ", "rex.w "):
        if m.startswith(rep):
            m = m[len(rep):]
    # drop a trailing string-op size letter so movsb/movs etc collapse
    return _ALIAS.get(m, m)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", default="build/difftool.exe")
    ap.add_argument("--count", type=int, default=1_000_000, help="random samples")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--no-structured", action="store_true")
    ap.add_argument("--report", type=int, default=12, help="repros per bucket")
    ap.add_argument("--out", default=None, help="write repros to this file")
    args = ap.parse_args()

    samples = []
    if not args.no_structured:
        samples.extend(pad15(b) for b in gen_structured())
    samples.extend(pad15(b) for b in gen_random(args.count, args.seed))
    # dedup while preserving order
    seen = set()
    uniq = []
    for h in samples:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    samples = uniq
    print(f"[*] {len(samples)} unique samples -> {args.tool}", file=sys.stderr)

    proc = subprocess.run([args.tool], input="\n".join(samples) + "\n",
                          capture_output=True, text=True)
    ours = proc.stdout.splitlines()
    if len(ours) != len(samples):
        print(f"[!] tool returned {len(ours)} lines for {len(samples)} samples", file=sys.stderr)
        n = min(len(ours), len(samples))
        samples, ours = samples[:n], ours[:n]

    stats = Counter()
    len_bugs, we_accept, we_reject, mnem = [], [], [], []
    mnem_pairs = Counter()
    reject_mnem = Counter()

    for hexs, line in zip(samples, ours):
        parts = line.split("\t")
        status = parts[0]
        our_len = int(parts[1]) if len(parts) > 1 else 0
        our_txt = parts[2] if len(parts) > 2 else ""
        data = bytes.fromhex(hexs)

        dec = I.Decoder(64, data, ip=0)
        ins = dec.decode()
        if dec.last_error == NO_MORE_BYTES:
            stats["skip_trunc"] += 1
            continue
        ref_valid = not ins.is_invalid
        our_valid = status == "OK"
        if status == "TRUNC":
            stats["skip_trunc"] += 1
            continue

        if not our_valid and not ref_valid:
            stats["agree_invalid"] += 1
            continue

        if our_valid and ref_valid:
            if ins.len != our_len:
                stats["len_mismatch"] += 1
                if len(len_bugs) < args.report:
                    f = I.Formatter(I.FormatterSyntax.INTEL)
                    len_bugs.append((hexs, our_len, ins.len, our_txt, f.format(ins)))
                continue
            stats["agree_len"] += 1
            f = I.Formatter(I.FormatterSyntax.INTEL)
            rm = canon_mnem(f.format_mnemonic(ins))
            om = canon_mnem(our_txt.split()[0]) if our_txt else ""
            if rm != om:
                stats["mnem_mismatch"] += 1
                mnem_pairs[(om, rm)] += 1
                if len(mnem) < args.report:
                    mnem.append((hexs, our_txt, f.format(ins)))
            else:
                stats["agree_mnem"] += 1
            continue

        if our_valid and not ref_valid:
            stats["we_accept_ref_rejects"] += 1
            if len(we_accept) < args.report:
                we_accept.append((hexs, our_txt))
            continue

        # ref valid, we reject
        enc = int(ins.encoding)
        regs = [ins.op_register(i) for i in range(ins.op_count)]
        is_mmx = any(MMX_LO <= int(r) <= MMX_HI for r in regs)
        f = I.Formatter(I.FormatterSyntax.INTEL)
        rmn = f.format_mnemonic(ins)
        if enc in ENC_OUT_OF_SCOPE or is_mmx or canon_mnem(rmn) in UNSUPPORTED:
            stats["ref_out_of_scope"] += 1
            continue
        stats["we_reject_gap"] += 1
        reject_mnem[rmn.strip().lower()] += 1
        if len(we_reject) < args.report:
            we_reject.append((hexs, f.format(ins), enc))

    print("\n===== differential vs iced-x86 =====")
    for k in ("agree_invalid", "agree_len", "agree_mnem", "ref_out_of_scope",
              "skip_trunc", "len_mismatch", "mnem_mismatch",
              "we_accept_ref_rejects", "we_reject_gap"):
        print(f"  {k:24} {stats[k]}")

    def dump(title, rows, fmt):
        if not rows:
            return
        print(f"\n--- {title} ({len(rows)} shown) ---")
        for r in rows:
            print("  " + fmt(r))

    dump("LENGTH MISMATCH (hard bug)", len_bugs,
         lambda r: f"{r[0]}  ours_len={r[1]} ref_len={r[2]}  ours='{r[3]}' ref='{r[4]}'")
    dump("WE ACCEPT / iced REJECTS", we_accept, lambda r: f"{r[0]}  ours='{r[1]}'")
    dump("WE REJECT / iced ACCEPTS (in-scope gap)", we_reject,
         lambda r: f"{r[0]}  ref='{r[1]}' enc={r[2]}")
    dump("MNEMONIC MISMATCH (sample)", mnem, lambda r: f"{r[0]}  ours='{r[1]}' ref='{r[2]}'")

    if reject_mnem:
        print("\n--- top in-scope missing mnemonics ---")
        for m, c in reject_mnem.most_common(30):
            print(f"  {c:7} {m}")
    if mnem_pairs:
        print("\n--- top mnemonic (ours -> ref) mismatches ---")
        for (om, rm), c in mnem_pairs.most_common(30):
            print(f"  {c:7} {om!r:20} -> {rm!r}")

    hard = stats["len_mismatch"] + stats["we_accept_ref_rejects"] + stats["we_reject_gap"]
    if args.out:
        with open(args.out, "w") as fh:
            for r in len_bugs:
                fh.write(f"LEN {r[0]} ours={r[1]} ref={r[2]}\n")
            for r in we_accept:
                fh.write(f"ACCEPT {r[0]} {r[1]}\n")
            for r in we_reject:
                fh.write(f"REJECT {r[0]} {r[1]}\n")
    print(f"\n[*] hard disagreements: {hard}")
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main())
