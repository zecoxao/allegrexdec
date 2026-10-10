"""
Conservative, block-local optimisation for the Allegrex IR: constant folding
plus propagation of register constants and copies within a basic block.  This
folds the ``lui`` + ``addiu``/``ori`` address-building idiom into one constant
and turns ``addu rd,rs,zero`` / ``or rd,rs,zero`` into ``rd = rs``.

The environment tracks registers only, so a memory store never invalidates it.
A call clears it; an intrinsic clears it too unless it is known not to write a
GPR (CPU-control ops, stores, system-register writes, and VFPU ops, which only
touch vector registers).
"""

from . import ir


_OPS = {
    "+": lambda a, b: (a + b) & 0xFFFFFFFF, "-": lambda a, b: (a - b) & 0xFFFFFFFF,
    "|": lambda a, b: a | b, "&": lambda a, b: a & b, "^": lambda a, b: a ^ b,
    "<<": lambda a, b: (a << (b & 31)) & 0xFFFFFFFF, ">>": lambda a, b: a >> (b & 31),
}

# intrinsics that provably do not overwrite a general-purpose register
_KEEP = frozenset((
    "di", "ei", "sync", "synci", "cache", "break", "nop", "wait", "halt",
    "deret", "tlbr", "tlbwi", "tlbwr", "tlbp",
    "swl", "swr", "sc", "mtc0", "ctc0", "mtic", "wrpgpr",
    "tge", "tgeu", "tlt", "tltu", "teq", "tne",
    "tgei", "tgeiu", "tlti", "tltiu", "teqi", "tnei",
))


def _keeps_env(name):
    return name in _KEEP or name.startswith("v")   # VFPU writes vector regs only


def _fold(e):
    if isinstance(e, ir.Bin):
        l, r = _fold(e.l), _fold(e.r)
        if isinstance(l, ir.Const) and isinstance(r, ir.Const) and e.op in _OPS:
            return ir.Const(_OPS[e.op](l.value, r.value))
        if isinstance(r, ir.Const) and r.value == 0 and e.op in ("+", "-", "|", "^", "<<", ">>"):
            return l
        if isinstance(l, ir.Const) and l.value == 0 and e.op in ("+", "|", "^"):
            return r
        return ir.Bin(e.op, l, r)
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _fold(e.e))
    if isinstance(e, ir.Mem):
        return ir.Mem(_fold(e.addr) if isinstance(e.addr, ir.Expr) else e.addr, e.width, e.signed)
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_fold(a) for a in e.args])
    return e


def _mentions(e, name):
    if isinstance(e, ir.Reg):
        return e.name == name
    if isinstance(e, ir.Bin):
        return _mentions(e.l, name) or _mentions(e.r, name)
    if isinstance(e, ir.Un):
        return _mentions(e.e, name)
    if isinstance(e, ir.Mem):
        return isinstance(e.addr, ir.Expr) and _mentions(e.addr, name)
    if isinstance(e, ir.IntrExpr):
        return any(_mentions(a, name) for a in e.args)
    return False


def _subst(e, env):
    if isinstance(e, ir.Reg):
        return env.get(e.name, e)
    if isinstance(e, ir.Bin):
        return ir.Bin(e.op, _subst(e.l, env), _subst(e.r, env))
    if isinstance(e, ir.Un):
        return ir.Un(e.op, _subst(e.e, env))
    if isinstance(e, ir.Mem):
        return ir.Mem(_subst(e.addr, env) if isinstance(e.addr, ir.Expr) else e.addr, e.width, e.signed)
    if isinstance(e, ir.IntrExpr):
        return ir.IntrExpr(e.name, [_subst(a, env) for a in e.args])
    return e


def _kill(env, name):
    for k in [k for k, v in env.items() if k == name or _mentions(v, name)]:
        del env[k]


def _opt_block(block):
    env = {}
    for s in block.stmts:
        if isinstance(s, ir.Assign):
            s.src = _fold(_subst(s.src, env))
            if isinstance(s.dst, ir.Reg):
                _kill(env, s.dst.name)
                if isinstance(s.src, (ir.Const, ir.Reg)) and not _mentions(s.src, s.dst.name):
                    env[s.dst.name] = s.src
            else:
                s.dst = _fold(_subst(s.dst, env))
        elif isinstance(s, ir.Branch):
            s.cexpr = _fold(_subst(s.cexpr, env))
        elif isinstance(s, ir.Intrinsic):
            s.args = [_fold(_subst(a, env)) for a in s.args]
            if not _keeps_env(s.name):
                env.clear()
        elif isinstance(s, ir.Call):
            env.clear()
        elif isinstance(s, ir.Goto) or isinstance(s, ir.Ret) or isinstance(s, ir.Nop):
            pass


def optimize(func):
    for b in func.blocks.values():
        _opt_block(b)
    return func
