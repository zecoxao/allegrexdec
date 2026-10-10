"""
allegrexdec -- a decompiler for the Sony PSP "Allegrex" CPU (MIPS II plus the
Allegrex integer extensions, the COP1 FPU and the VFPU vector unit) to readable
pseudo-C.

Part of zecoxao's decompiler family (spudec / startrekdec / f00ddec / rl78dec /
mechadec): a decoder produces instructions, a lifter turns them into a
machine-independent IR, and everything above is shared in design.

    decoder -> lifter -> cfg -> opt -> structure -> cgen

The decoder and VFPU tables follow the Allegrex Instruction/User manuals and
kotcrab's ghidra-allegrex SLEIGH.  It runs headless on a PSP ELF/PRX or as an
IDA plugin on a MIPS database.
"""

from . import decoder, cfg, opt, frame, structure, cgen, loader
from .names import Namer

__version__ = "0.1.0"

BANNER = [
    "/*",
    " * Decompiled by allegrexdec -- Sony PSP Allegrex (MIPS II + VFPU).",
    " * GPRs are the o32 ABI names (a0..a3, t0..t9, s0..s7, sp, ra ...); mem8/",
    " * mem16/mem32 index data memory (s8/s16 = sign-extending loads); hi/lo and",
    " * fcc are machine registers.  MIPS delay slots are folded into their branch.",
    " * VFPU and coprocessor ops that do not map onto C print as pseudo-calls;",
    " * register-indirect / cross-function jumps as JUMPOUT().",
    " */",
    "",
]


class Function:
    def __init__(self, entry, name, func, tree, lines):
        self.entry = entry
        self.name = name
        self.cfg = func
        self.tree = tree
        self.lines = lines


class Program:
    def __init__(self, image, base, insns, funcs, namer):
        self.image = image
        self.base = base
        self.insns = insns
        self.funcs = funcs
        self.namer = namer

    def listing(self, banner=True):
        out = list(BANNER) if banner else []
        for entry in sorted(self.funcs):
            out.extend(self.funcs[entry].lines)
            out.append("")
        return "\n".join(out)


def decompile_image(image, entries, base=0, code_names=None):
    insns, calls = decoder.decode(image, entries=entries, base=base)
    funcs = cfg.build_functions(insns, calls, extra_entries=entries)
    namer = Namer(code_names=code_names)
    out = {}
    for entry, f in funcs.items():
        opt.optimize(f)
        frame.rewrite(f)
        tree = structure.structure(f)
        out[entry] = Function(entry, namer.code(entry), f, tree,
                              cgen.generate(f, tree, namer))
    return Program(image, base, insns, out, namer)


def decompile_file(path, base=None, extra_entries=(), psplibdoc=None,
                   code_names=None, **kw):
    image, det_base, entries, names = loader.load_program(path, psplibdoc=psplibdoc)
    if base is None:
        base = det_base
    entries = list(entries) + list(extra_entries)
    if code_names:
        names = dict(names); names.update(code_names)
    return decompile_image(image, entries=entries, base=base, code_names=names, **kw)
