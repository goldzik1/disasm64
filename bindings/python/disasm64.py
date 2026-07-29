"""Python bindings for disasm64 via its C ABI (ctypes).

Build the shared library first:

    cmake -S . -B build && cmake --build build --target disasm64_c

then point DISASM64_LIB at the built library, or drop it next to this file:

    from disasm64 import Disasm64
    d = Disasm64()
    print(d.format(bytes.fromhex("4889e5")))        # 'mov rbp, rsp'
    insn = d.decode(bytes.fromhex("e800100000"), address=0x401000)
    print(insn.length, insn.operands[0].rel_target) # 5 4202501
"""
import ctypes as C
import glob
import os

_REG_CLASSES = ["none", "gpr8", "gpr8hi", "gpr16", "gpr32", "gpr64",
                "xmm", "ymm", "sreg", "rip", "st", "cr", "dr", "zmm", "k"]
OP_NONE, OP_REG, OP_MEM, OP_IMM, OP_REL = range(5)
OK, INVALID, TRUNCATED = range(3)


class _Operand(C.Structure):
    _fields_ = [
        ("kind", C.c_uint8), ("size", C.c_uint8),
        ("reg_class", C.c_uint8), ("reg_index", C.c_uint8),
        ("base_class", C.c_uint8), ("base_index", C.c_uint8),
        ("index_class", C.c_uint8), ("index_index", C.c_uint8),
        ("scale", C.c_uint8), ("segment", C.c_uint8), ("rip_relative", C.c_uint8),
        ("disp", C.c_int64), ("imm", C.c_int64), ("rel_target", C.c_uint64),
    ]


class _Insn(C.Structure):
    _fields_ = [
        ("address", C.c_uint64), ("status", C.c_uint8), ("length", C.c_uint8),
        ("mnemonic", C.c_uint16), ("operand_count", C.c_uint8),
        ("flags_read", C.c_uint8), ("flags_written", C.c_uint8),
        ("lock", C.c_uint8), ("rep", C.c_uint8), ("opsize", C.c_uint8),
        ("addrsize", C.c_uint8), ("rex", C.c_uint8), ("vex", C.c_uint8), ("evex", C.c_uint8),
        ("operands", _Operand * 4),
    ]


def _find_library():
    if os.environ.get("DISASM64_LIB"):
        return os.environ["DISASM64_LIB"]
    here = os.path.dirname(os.path.abspath(__file__))
    roots = [here, os.path.join(here, "..", "..", "build")]
    names = ["disasm64_c.dll", "libdisasm64_c.so", "libdisasm64_c.dylib", "disasm64_c.so"]
    for root in roots:
        for name in names:
            for hit in glob.glob(os.path.join(root, "**", name), recursive=True):
                return hit
    raise FileNotFoundError("disasm64_c shared library not found; set DISASM64_LIB")


class Operand:
    def __init__(self, o: _Operand):
        self.kind = o.kind
        self.size = o.size
        self.reg_class = _REG_CLASSES[o.reg_class] if o.reg_class < len(_REG_CLASSES) else "?"
        self.reg_index = o.reg_index
        self.base = (_REG_CLASSES[o.base_class], o.base_index) if o.base_class else None
        self.index = (_REG_CLASSES[o.index_class], o.index_index) if o.index_class else None
        self.scale = o.scale
        self.disp = o.disp
        self.imm = o.imm
        self.rip_relative = bool(o.rip_relative)
        self.rel_target = o.rel_target


class Insn:
    def __init__(self, s: _Insn):
        self.address = s.address
        self.status = s.status
        self.length = s.length
        self.mnemonic = s.mnemonic
        self.flags_read = s.flags_read
        self.flags_written = s.flags_written
        self.vex, self.evex, self.rex = bool(s.vex), bool(s.evex), bool(s.rex)
        self.operands = [Operand(s.operands[i]) for i in range(s.operand_count)]

    @property
    def ok(self):
        return self.status == OK


class Disasm64:
    def __init__(self, path=None):
        self._lib = C.CDLL(path or _find_library())
        self._lib.d64_decode.restype = C.c_uint8
        self._lib.d64_decode.argtypes = [C.c_char_p, C.c_size_t, C.c_uint64, C.POINTER(_Insn)]
        self._lib.d64_format.restype = C.c_uint8
        self._lib.d64_format.argtypes = [C.c_char_p, C.c_size_t, C.c_uint64, C.c_int, C.c_char_p, C.c_size_t]
        self._lib.d64_relocate.restype = C.c_uint8
        self._lib.d64_relocate.argtypes = [C.c_char_p, C.c_size_t, C.c_uint64, C.c_uint64, C.c_char_p, C.c_size_t]
        self._lib.d64_version.restype = C.c_char_p

    def version(self):
        return self._lib.d64_version().decode()

    def decode(self, code: bytes, address=0):
        s = _Insn()
        self._lib.d64_decode(code, len(code), address, C.byref(s))
        return Insn(s)

    def format(self, code: bytes, address=0, att=False):
        buf = C.create_string_buffer(64)
        self._lib.d64_format(code, len(code), address, 1 if att else 0, buf, 64)
        return buf.value.decode()

    def relocate(self, code: bytes, old_address, new_address):
        out = C.create_string_buffer(16)
        n = self._lib.d64_relocate(code, len(code), old_address, new_address, out, 16)
        return out.raw[:n] if n else None


if __name__ == "__main__":
    d = Disasm64()
    print("disasm64", d.version())
    for hexs in ["4889e5", "e800100000", "62f16c4858cb"]:
        print(f"{hexs:16} -> {d.format(bytes.fromhex(hexs), 0x401000)}")
