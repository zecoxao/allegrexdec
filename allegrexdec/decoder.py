"""
Standalone Allegrex (PSP MIPS) decoder -- little-endian, fixed 32-bit, no IDA.

Produces :class:`Insn` objects with a mnemonic and a typed :class:`Operand`
list.  Covers MIPS II + the Allegrex integer extensions (ext/ins/seb/seh/wsbh/
bitrev/clz/min/max/madd/mfic ...), the COP1 FPU, and the VFPU (register naming
and opcode table generated from kotcrab's ghidra-allegrex SLEIGH:
:mod:`allegrexdec.vtables` / :mod:`allegrexdec.vops`).

Operand ``mode`` values:
    reg     GPR                               (``reg`` = 0..31)
    imm     immediate                         (``value``, may be signed)
    near    code target                       (``addr``)
    displ   disp(base)                        (``base_reg``, ``disp``, ``width``, ``signed``)
    freg    FPU register                      (``reg`` 0..31, name f0..f31)
    name    a literal register/token string   (``text``)   -- cop0/fcr/vfpu regs
"""

from . import isa
from . import vtables as VT
from .vops import RULES as _VRULES


def _sx(x, b):
    m = 1 << (b - 1)
    x &= (1 << b) - 1
    return (x ^ m) - m


class Operand:
    __slots__ = ("mode", "reg", "value", "addr", "base_reg", "disp", "width",
                 "signed", "text")

    def __init__(self, mode, reg=0, value=0, addr=0, base_reg=0, disp=0,
                 width=4, signed=False, text=""):
        self.mode = mode
        self.reg = reg
        self.value = value
        self.addr = addr
        self.base_reg = base_reg
        self.disp = disp
        self.width = width
        self.signed = signed
        self.text = text


class Insn:
    __slots__ = ("ea", "size", "mnem", "ops", "word")

    def __init__(self, ea):
        self.ea = ea
        self.size = 4
        self.mnem = None
        self.ops = []
        self.word = 0

    def __repr__(self):
        return "<Insn %08X %s>" % (self.ea, self.mnem)


# operand constructors ------------------------------------------------------
def R(i):          return Operand("reg", reg=i)
def I(v):          return Operand("imm", value=v & 0xFFFFFFFF)
def N(t):          return Operand("near", addr=t & 0xFFFFFFFF)
def F(i):          return Operand("freg", reg=i)
def NAME(s):       return Operand("name", text=s)
def D(base, d, w=4, sg=False):
    return Operand("displ", base_reg=base, disp=d & 0xFFFFFFFF, width=w, signed=sg)


def decode_one(image, ea, base=0):
    off = ea - base
    if off < 0 or off + 4 > len(image):
        return None
    w = (image[off] | (image[off + 1] << 8) |
         (image[off + 2] << 16) | (image[off + 3] << 24))
    ins = Insn(ea)
    ins.word = w
    if not _decode(ins, w, ea):
        ins.mnem = ".word"
        ins.ops = [I(w)]
    return ins


# --- VFPU register naming ---------------------------------------------------
_VTAB = {"s": VT.VREG_S, "p": VT.VREG_P, "t": VT.VREG_T, "q": VT.VREG_Q,
         "m": VT.VREG_M, "e": VT.VREG_E, "tm": VT.VREG_TM, "te": VT.VREG_TE}


def _vfield(w, role):
    if role == "d":
        return w & 0x7F
    if role == "s":
        return (w >> 8) & 0x7F
    return (w >> 16) & 0x7F          # 't'


def _vreg_name(w, role, kind):
    return _VTAB[kind][_vfield(w, role)]


# evaluate a named field for the generated VFPU rule table
def _VF(w, name):
    f = {
        "prime": (w >> 26) & 0x3F, "vop3": (w >> 23) & 7, "vtop2": (w >> 21) & 3,
        "vop2": (w >> 24) & 3, "vtop4": (w >> 16) & 0xF, "vc0": (w >> 7) & 1,
        "vc1": (w >> 15) & 1, "vt": (w >> 16) & 0x7F, "vs": (w >> 8) & 0x7F,
        "vd": w & 0x7F, "vtimm5": (w >> 16) & 0x1F, "vcc": (w >> 18) & 7,
        "vndtf": (w >> 16) & 3, "vcmov_op": (w >> 19) & 7, "vcmov_cc": (w >> 16) & 7,
        "bit25": (w >> 25) & 1, "bit1": (w >> 1) & 1, "bit10": (w >> 10) & 1,
        "bit6": (w >> 6) & 1, "copop": (w >> 21) & 0x1F, "vtop4b": (w >> 16) & 0xF,
    }
    return f.get(name)


def _vtable_match(ins, w):
    for cons, mnem, operands in _VRULES:
        ok = True
        for fld, rel, val in cons:
            cur = _VF(w, fld)
            if cur is None or (cur == val) != (rel == "=="):
                ok = False
                break
        if not ok:
            continue
        ins.mnem = mnem
        ins.ops = [NAME(_vreg_name(w, role, kind)) for role, kind in operands]
        return True
    return False


def emit(ins, mnem, *ops):
    ins.mnem = mnem
    ins.ops = list(ops)
    return True


# ===========================================================================
def _decode(ins, w, ea):
    prime = (w >> 26) & 0x3F
    rs = (w >> 21) & 0x1F
    rt = (w >> 16) & 0x1F
    rd = (w >> 11) & 0x1F
    sa = (w >> 6) & 0x1F
    fct = w & 0x3F
    imm = w & 0xFFFF
    simm = _sx(imm, 16)
    off = w & 0x3FFFFFF

    def rel16():
        return (ea + 4 + (simm << 2)) & 0xFFFFFFFF

    def abs26():
        return ((ea + 4) & 0xF0000000) | (off << 2)

    if w == 0:
        return emit(ins, "nop")

    # --- SPECIAL (prime 0) --------------------------------------------------
    if prime == 0:
        return _special(ins, w, ea, rs, rt, rd, sa, fct)

    # --- REGIMM (prime 1) ---------------------------------------------------
    if prime == 1:
        cond = rt
        rel = N(rel16())
        m = {0: "bltz", 1: "bgez", 2: "bltzl", 3: "bgezl",
             16: "bltzal", 17: "bgezal", 18: "bltzall", 19: "bgezall"}.get(cond)
        if m:
            return emit(ins, m, R(rs), rel)
        tr = {8: "tgei", 9: "tgeiu", 10: "tlti", 11: "tltiu", 12: "teqi", 14: "tnei"}.get(cond)
        if tr:
            return emit(ins, tr, R(rs), I(simm & 0xFFFFFFFF))
        if cond == 31 and ((w >> 16) & 0x1F) == 31:    # synci
            return emit(ins, "synci", D(rs, simm, 4))
        return False

    # --- J / JAL ------------------------------------------------------------
    if prime == 2:
        return emit(ins, "j", N(abs26()))
    if prime == 3:
        return emit(ins, "jal", N(abs26()))

    # --- branches -----------------------------------------------------------
    if prime in (4, 5, 20, 21):
        m = {4: "beq", 5: "bne", 20: "beql", 21: "bnel"}[prime]
        if prime in (4, 20) and rs == rt:
            return emit(ins, "b" if prime == 4 else "bl", N(rel16()))
        return emit(ins, m, R(rs), R(rt), N(rel16()))
    if prime in (6, 7, 22, 23):
        m = {6: "blez", 7: "bgtz", 22: "blezl", 23: "bgtzl"}[prime]
        return emit(ins, m, R(rs), N(rel16()))

    # --- immediates ---------------------------------------------------------
    if prime == 8:
        return emit(ins, "addi", R(rt), R(rs), I(simm & 0xFFFFFFFF))
    if prime == 9:
        return emit(ins, "addiu", R(rt), R(rs), I(simm & 0xFFFFFFFF))
    if prime == 10:
        return emit(ins, "slti", R(rt), R(rs), I(simm & 0xFFFFFFFF))
    if prime == 11:
        return emit(ins, "sltiu", R(rt), R(rs), I(simm & 0xFFFFFFFF))
    if prime == 12:
        return emit(ins, "andi", R(rt), R(rs), I(imm))
    if prime == 13:
        return emit(ins, "ori", R(rt), R(rs), I(imm))
    if prime == 14:
        return emit(ins, "xori", R(rt), R(rs), I(imm))
    if prime == 15:
        return emit(ins, "lui", R(rt), I(imm))

    # --- coprocessors -------------------------------------------------------
    if prime == 16:
        return _cop0(ins, w, rt, rd, fct)
    if prime == 17:
        return _cop1(ins, w, ea, rt, rd, sa, fct, simm)
    if prime == 18:
        return _cop2(ins, w, ea, rt)

    # --- SPECIAL2 (prime 28) Allegrex -------------------------------------
    if prime == 28:
        if rs == 0 and rd == 0:
            if fct == 0 and rt == 0:
                return emit(ins, "halt")
            if fct == 36:
                return emit(ins, "mfic", R(rt))
            if fct == 38:
                return emit(ins, "mtic", R(rt))
        return False

    # --- SPECIAL3 (prime 31) ----------------------------------------------
    if prime == 31:
        return _special3(ins, w, rs, rt, rd, sa, fct)

    # --- loads / stores -----------------------------------------------------
    LS = {32: ("lb", 1, True), 33: ("lh", 2, True), 34: ("lwl", 4, False),
          35: ("lw", 4, False), 36: ("lbu", 1, False), 37: ("lhu", 2, False),
          38: ("lwr", 4, False), 40: ("sb", 1, False), 41: ("sh", 2, False),
          42: ("swl", 4, False), 43: ("sw", 4, False), 46: ("swr", 4, False),
          48: ("ll", 4, False), 56: ("sc", 4, False)}
    if prime in LS:
        m, wd, sg = LS[prime]
        return emit(ins, m, R(rt), D(rs, simm, wd, sg))
    if prime == 47:
        return emit(ins, "cache", I(rt), D(rs, simm, 1))
    if prime == 49:
        return emit(ins, "lwc1", F(rt), D(rs, simm, 4))
    if prime == 57:
        return emit(ins, "swc1", F(rt), D(rs, simm, 4))

    # --- VFPU memory / arithmetic ------------------------------------------
    if _vfpu(ins, w, ea, prime, simm):
        return True

    return False


# ---------------------------------------------------------------------------
def _special(ins, w, ea, rs, rt, rd, sa, fct):
    if fct == 0:
        return emit(ins, "sll", R(rd), R(rt), I(sa))
    if fct == 2:
        if ((w >> 21) & 1) == 1:                   # rotr
            return emit(ins, "rotr", R(rd), R(rt), I(sa))
        return emit(ins, "srl", R(rd), R(rt), I(sa))
    if fct == 3:
        return emit(ins, "sra", R(rd), R(rt), I(sa))
    if fct == 4:
        return emit(ins, "sllv", R(rd), R(rt), R(rs))
    if fct == 6:
        if ((w >> 6) & 1) == 1:                     # rotrv
            return emit(ins, "rotrv", R(rd), R(rt), R(rs))
        return emit(ins, "srlv", R(rd), R(rt), R(rs))
    if fct == 7:
        return emit(ins, "srav", R(rd), R(rt), R(rs))
    if fct == 8:
        if rs == 31:
            return emit(ins, "jr_ra")
        return emit(ins, "jr", R(rs))
    if fct == 9:
        return emit(ins, "jalr", R(rd), R(rs))
    if fct == 10:
        return emit(ins, "movz", R(rd), R(rs), R(rt))
    if fct == 11:
        return emit(ins, "movn", R(rd), R(rs), R(rt))
    if fct == 12:
        return emit(ins, "syscall", I((w >> 6) & 0xFFFFF))
    if fct == 13:
        return emit(ins, "break", I((w >> 6) & 0xFFFFF))
    if fct == 15:
        return emit(ins, "sync", I(sa))
    if fct == 16:
        return emit(ins, "mfhi", R(rd))
    if fct == 17:
        return emit(ins, "mthi", R(rs))
    if fct == 18:
        return emit(ins, "mflo", R(rd))
    if fct == 19:
        return emit(ins, "mtlo", R(rs))
    if fct == 22:
        return emit(ins, "clz", R(rd), R(rs))
    if fct == 23:
        return emit(ins, "clo", R(rd), R(rs))
    if fct == 24:
        return emit(ins, "mult", R(rs), R(rt))
    if fct == 25:
        return emit(ins, "multu", R(rs), R(rt))
    if fct == 26:
        return emit(ins, "div", R(rs), R(rt))
    if fct == 27:
        return emit(ins, "divu", R(rs), R(rt))
    if fct == 28:
        return emit(ins, "madd", R(rs), R(rt))
    if fct == 29:
        return emit(ins, "maddu", R(rs), R(rt))
    if fct == 46:
        return emit(ins, "msub", R(rs), R(rt))
    if fct == 47:
        return emit(ins, "msubu", R(rs), R(rt))
    ALU = {32: "add", 33: "addu", 34: "sub", 35: "subu", 36: "and",
           37: "or", 38: "xor", 39: "nor", 42: "slt", 43: "sltu",
           44: "max", 45: "min"}
    if fct in ALU:
        return emit(ins, ALU[fct], R(rd), R(rs), R(rt))
    TR = {48: "tge", 49: "tgeu", 50: "tlt", 51: "tltu", 52: "teq", 54: "tne"}
    if fct in TR:
        return emit(ins, TR[fct], R(rs), R(rt))
    return False


def _special3(ins, w, rs, rt, rd, sa, fct):
    msbd = rd
    lsb = sa
    if fct == 0:
        size = msbd + 1
        return emit(ins, "ext", R(rt), R(rs), I(lsb), I(size))
    if fct == 4:
        size = msbd - lsb + 1
        return emit(ins, "ins", R(rt), R(rs), I(lsb), I(size))
    if fct == 59:
        return emit(ins, "rdhwr", R(rt), R(rd))
    if fct in (32, 24):                 # BSHFL / allegrex misc, by fct2 = sa
        fct2 = sa
        sub = {2: "wsbh", 3: "wsbw", 16: "seb", 24: "seh", 20: "bitrev"}.get(fct2)
        if sub:
            return emit(ins, sub, R(rd), R(rt))
    return False


def _cop0(ins, w, rt, rd, fct):
    sub = (w >> 21) & 0x1F
    big = w & 0x7FF
    if big == 0:
        if sub == 0:
            return emit(ins, "mfc0", R(rt), NAME(isa.COP0D[rd]))
        if sub == 2:
            return emit(ins, "cfc0", R(rt), NAME(isa.COP0C[rd]))
        if sub == 4:
            return emit(ins, "mtc0", R(rt), NAME(isa.COP0D[rd]))
        if sub == 6:
            return emit(ins, "ctc0", R(rt), NAME(isa.COP0C[rd]))
        if sub == 10:
            return emit(ins, "rdpgpr", R(rd), R(rt))
        if sub == 14:
            return emit(ins, "wrpgpr", R(rd), R(rt))
    if ((w >> 25) & 1) == 1:
        if fct == 24:
            return emit(ins, "eret")
        if fct == 31:
            return emit(ins, "deret")
        if fct == 1:
            return emit(ins, "tlbr")
        if fct == 2:
            return emit(ins, "tlbwi")
        if fct == 6:
            return emit(ins, "tlbwr")
        if fct == 8:
            return emit(ins, "tlbp")
        if fct == 32:
            return emit(ins, "wait", I((w >> 6) & 0x7FFFF))
    # di/ei  (mfmc0)
    if sub == 0x0B and rd == 0x0C:
        return emit(ins, "ei" if ((w >> 5) & 1) else "di", R(rt))
    return False


_FMT = {0x10: "s", 0x11: "d", 0x14: "w", 0x15: "l", 0x16: "ps"}
_FPU_ARITH = {0: "add", 1: "sub", 2: "mul", 3: "div"}
_FPU_UN = {4: "sqrt", 5: "abs", 6: "mov", 7: "neg"}
_FPU_CVT = {12: "round.w", 13: "trunc.w", 14: "ceil.w", 15: "floor.w",
            0x20: "cvt.s", 0x21: "cvt.d", 0x24: "cvt.w"}
_FPU_CCOND = ("f", "un", "eq", "ueq", "olt", "ult", "ole", "ule",
              "sf", "ngle", "seq", "ngl", "lt", "nge", "le", "ngt")


def _cop1(ins, w, ea, rt, rd, sa, fct, simm):
    fmt = (w >> 21) & 0x1F     # also copop
    fs, ft, fd = rd, rt, sa
    if fmt == 0:
        return emit(ins, "mfc1", R(rt), F(fs))
    if fmt == 2:
        return emit(ins, "cfc1", R(rt), NAME(isa.FCR.get(fs, "fcr%d" % fs)))
    if fmt == 4:
        return emit(ins, "mtc1", R(rt), F(fs))
    if fmt == 6:
        return emit(ins, "ctc1", R(rt), NAME(isa.FCR.get(fs, "fcr%d" % fs)))
    if fmt == 8:                                   # BC1
        nd = (w >> 17) & 1
        tf = (w >> 16) & 1
        m = {(0, 0): "bc1f", (0, 1): "bc1t", (1, 0): "bc1fl", (1, 1): "bc1tl"}[(nd, tf)]
        return emit(ins, m, N((ea + 4 + (simm << 2)) & 0xFFFFFFFF))
    sfx = _FMT.get(fmt)
    if sfx is None:
        return False
    if fct in _FPU_ARITH:
        return emit(ins, "%s.%s" % (_FPU_ARITH[fct], sfx), F(fd), F(fs), F(ft))
    if fct in _FPU_UN:
        return emit(ins, "%s.%s" % (_FPU_UN[fct], sfx), F(fd), F(fs))
    if fct in _FPU_CVT:
        return emit(ins, "%s.%s" % (_FPU_CVT[fct], sfx), F(fd), F(fs))
    if 48 <= fct <= 63:
        return emit(ins, "c.%s.%s" % (_FPU_CCOND[fct - 48], sfx), F(fs), F(ft))
    return False


def _cop2(ins, w, ea, rt):
    copop = (w >> 21) & 0x1F
    vd = w & 0x7F
    simm = _sx(w & 0xFFFF, 16)
    if copop == 8:                                  # bvf/bvt/bvfl/bvtl
        vndtf = (w >> 16) & 3
        vcc = (w >> 18) & 7
        m = {0: "bvf", 1: "bvt", 2: "bvfl", 3: "bvtl"}[vndtf]
        return emit(ins, m, I(vcc), N((ea + 4 + (simm << 2)) & 0xFFFFFFFF))
    vc0 = (w >> 7) & 1
    if copop == 3:
        if vc0 == 0:
            return emit(ins, "mfv", R(rt), NAME(_vreg_name(w, "d", "s")))
        return emit(ins, "mfvc", R(rt), NAME(isa.VFPU_CTL[vd & 0xF]))
    if copop == 7:
        if vc0 == 0:
            return emit(ins, "mtv", R(rt), NAME(_vreg_name(w, "d", "s")))
        return emit(ins, "mtvc", R(rt), NAME(isa.VFPU_CTL[vd & 0xF]))
    return False


def _vfpu(ins, w, ea, prime, simm):
    # VFPU memory ops use OFF_VBASE = base + (vsimmed<<2), vsimmed = bits (2,15) signed
    vsimm = _sx((w >> 2) & 0x3FFF, 14)
    base = (w >> 21) & 0x1F
    voff = vsimm << 2
    vmem = ((w >> 16) & 0x1F) | (((w >> 0) & 1) << 5)    # vm_l + vms_h low bit
    # single-register memory operand name (S-table index via vm encoding)
    vt_mem = ((w >> 16) & 0x1F) | ((w & 1) << 5) | (((w >> 8) & 1) << 6)

    if prime == 50:     # lv.s
        return emit(ins, "lv.s", NAME(VT.VREG_S[vt_mem & 0x7F]), D(base, voff, 4))
    if prime == 58:     # sv.s
        return emit(ins, "sv.s", NAME(VT.VREG_S[vt_mem & 0x7F]), D(base, voff, 4))
    if prime == 54:     # lv.q
        return emit(ins, "lv.q", NAME(VT.VREG_Q[vt_mem & 0x7F]), D(base, voff, 16))
    if prime == 62:     # sv.q
        return emit(ins, "sv.q", NAME(VT.VREG_Q[vt_mem & 0x7F]), D(base, voff, 16))
    if prime == 53:     # lvl.q / lvr.q
        m = "lvr.q" if ((w >> 1) & 1) else "lvl.q"
        return emit(ins, m, NAME(VT.VREG_Q[vt_mem & 0x7F]), D(base, voff, 16))
    if prime == 61:     # svl.q / svr.q
        m = "svr.q" if ((w >> 1) & 1) else "svl.q"
        return emit(ins, m, NAME(VT.VREG_Q[vt_mem & 0x7F]), D(base, voff, 16))
    if prime == 63:
        return emit(ins, "vflush")

    if prime == 55:     # vpfxs / vpfxt / vpfxd / viim / vfim
        vop2 = (w >> 24) & 3
        vop3 = (w >> 23) & 7
        if vop3 == 6:
            return emit(ins, "viim.s", NAME(VT.VREG_S[(w >> 16) & 0x7F]),
                        I(_sx(w & 0xFFFF, 16) & 0xFFFFFFFF))
        if vop3 == 7:
            return emit(ins, "vfim.s", NAME(VT.VREG_S[(w >> 16) & 0x7F]), I(w & 0xFFFF))
        m = {0: "vpfxs", 1: "vpfxt", 2: "vpfxd"}.get(vop2)
        if m:
            return emit(ins, m, I(w & 0xFFFFF))

    if prime == 27:     # may be vcmp (vop3==0) else table (vmin/vmax...)
        if ((w >> 23) & 7) == 0:
            vd_cmp = w & 0xF
            vc0 = (w >> 7) & 1
            vc1 = (w >> 15) & 1
            sz = {(0, 0): "s", (0, 1): "p", (1, 0): "t", (1, 1): "q"}[(vc1, vc0)]
            return emit(ins, "vcmp.%s" % sz, NAME(VT.VCMP[vd_cmp]),
                        NAME(_vreg_name(w, "s", sz)), NAME(_vreg_name(w, "t", sz)))

    if prime == 52:     # unary group; vcst / vmfvc / vmtvc are special
        vop3 = (w >> 23) & 7
        vt = (w >> 16) & 0x7F
        if vop3 == 0 and ((w >> 21) & 3) == 3:        # vcst
            vc0 = (w >> 7) & 1
            vc1 = (w >> 15) & 1
            sz = {(0, 0): "s", (0, 1): "p", (1, 0): "t", (1, 1): "q"}[(vc1, vc0)]
            cst = VT.VCST[(w >> 16) & 0x1F]
            return emit(ins, "vcst.%s" % sz, NAME(_vreg_name(w, "d", sz)), NAME(cst))
        if vop3 == 0 and vt == 80:
            return emit(ins, "vmfvc", NAME(_vreg_name(w, "d", "s")),
                        NAME(isa.VFPU_CTL[w & 0xF] if (w & 0x7F) < 16 else "vctl%d" % (w & 0x7F)))
        if vop3 == 0 and vt == 81:
            return emit(ins, "vmtvc", NAME(_vreg_name(w, "s", "s")),
                        NAME(isa.VFPU_CTL[(w >> 16) & 0xF] if ((w >> 16) & 0x7F) < 16 else "?"))

    if prime == 60:     # vrot etc -- vop3==7 & vtop2==1 is vrot
        if ((w >> 23) & 7) == 7 and ((w >> 21) & 3) == 1:
            vc0 = (w >> 7) & 1
            vc1 = (w >> 15) & 1
            sz = {(0, 0): "s", (0, 1): "p", (1, 0): "t", (1, 1): "q"}[(vc1, vc0)]
            return emit(ins, "vrot.%s" % sz, NAME(_vreg_name(w, "d", sz)),
                        NAME(_vreg_name(w, "s", "s")), I((w >> 16) & 0x1F))

    # fall through to the generated arithmetic/unary/matrix table
    if _vtable_match(ins, w):
        return True
    # anything else in a VFPU opcode range -> honest generic intrinsic
    if prime in (24, 25, 26, 27, 52, 53, 54, 55, 60, 63):
        return emit(ins, "vfpu_op", I(w))
    return False


# --- control-flow helpers (traversal) --------------------------------------
def target_of(ins):
    for op in ins.ops:
        if op.mode == "near":
            return op.addr
    return None


def _succ(ins):
    """Reachable addresses for the decode-time traversal (includes the delay
    slot, which always executes)."""
    m = ins.mnem
    nxt = ins.ea + 4
    slot = ins.ea + 4
    after = ins.ea + 8
    t = target_of(ins)
    out = []
    if isa.is_transfer(m):
        out.append(slot)                        # delay slot always runs
        if t is not None:
            out.append(t)
        if m in isa.COND_BRANCH or m in isa.COND_CALL or m in isa.CALL or m in isa.CALL_IND:
            out.append(after)                   # fall-through past the slot
        return out
    out.append(nxt)
    return out


def decode(image, entries, base=0):
    insns, calls, seen = {}, set(), set()
    work = [e for e in entries if base <= e < base + len(image)]
    while work:
        ea = work.pop()
        if ea in seen or not (base <= ea < base + len(image)):
            continue
        seen.add(ea)
        ins = decode_one(image, ea, base)
        if ins is None:
            continue
        insns[ea] = ins
        if ins.mnem in isa.CALL or ins.mnem in isa.COND_CALL:
            t = target_of(ins)
            if t is not None:
                calls.add(t)
        for tgt in _succ(ins):
            if base <= tgt < base + len(image):
                work.append(tgt)
    return insns, calls
