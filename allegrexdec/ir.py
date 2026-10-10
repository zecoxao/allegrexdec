"""
IR for the Allegrex (PSP MIPS) decompiler.

A register machine shared in shape with spudec / rl78dec / f00ddec, so the
control-flow structurer, optimiser and highlighter are common.  MIPS
compare-and-branch folds into a self-contained :class:`Branch` carrying its
condition expression, so there is no flag layer.  Registers that read as a
machine value (``hi``/``lo``, FPU condition ``fcc``, VFPU ``CC`` ...) are plain
:class:`Reg` names; operations that do not map onto C (VFPU, coprocessor moves,
cache ops) are honest :class:`Intrinsic` / :class:`IntrExpr` pseudo-calls.
"""


class Expr:
    pass


class Const(Expr):
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value & 0xFFFFFFFF


class Reg(Expr):
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name

    def __eq__(self, o):
        return isinstance(o, Reg) and o.name == self.name

    def __hash__(self):
        return hash(("reg", self.name))


class Mem(Expr):
    """Memory access; ``addr`` is an int (absolute) or an Expr (reg-based).
    width in bytes (1/2/4); ``signed`` selects sign- vs zero-extension."""
    __slots__ = ("addr", "width", "signed")

    def __init__(self, addr, width=4, signed=False):
        self.addr = addr
        self.width = width
        self.signed = signed


class Bin(Expr):
    __slots__ = ("op", "l", "r")

    def __init__(self, op, l, r):
        self.op = op
        self.l = l
        self.r = r


class Un(Expr):
    __slots__ = ("op", "e")

    def __init__(self, op, e):
        self.op = op
        self.e = e


class IntrExpr(Expr):
    __slots__ = ("name", "args")

    def __init__(self, name, args):
        self.name = name
        self.args = args


# --- statements -------------------------------------------------------------

class Assign:
    __slots__ = ("ea", "dst", "src")

    def __init__(self, ea, dst, src):
        self.ea = ea
        self.dst = dst
        self.src = src


class Call:
    __slots__ = ("ea", "target", "expr", "args")

    def __init__(self, ea, target=None, expr=None, args=None):
        self.ea = ea
        self.target = target
        self.expr = expr
        self.args = args          # list of argument exprs (filled by callargs pass)


class Intrinsic:
    __slots__ = ("ea", "name", "args", "note")

    def __init__(self, ea, name, args, note=""):
        self.ea = ea
        self.name = name
        self.args = args
        self.note = note


class Ret:
    __slots__ = ("ea", "kind")

    def __init__(self, ea, kind="ret"):
        self.ea = ea
        self.kind = kind


class Goto:
    __slots__ = ("ea", "target")

    def __init__(self, ea, target):
        self.ea = ea
        self.target = target


class Branch:
    __slots__ = ("ea", "cexpr", "target", "fallthrough")

    def __init__(self, ea, cexpr, target, fallthrough):
        self.ea = ea
        self.cexpr = cexpr          # condition expression (taken when true)
        self.target = target
        self.fallthrough = fallthrough


class Nop:
    __slots__ = ("ea",)

    def __init__(self, ea):
        self.ea = ea
