"""
Lightweight parameter / return-value recovery for Allegrex functions, using the
MIPS o32 calling convention.

Arguments arrive in ``a0``-``a3``; a register that is *read before being written*
on a path from the entry block (its live-in set) is an incoming argument.  IDA's
Hex-Rays does full inter-procedural type inference and stack-frame reconstruction;
this is deliberately simpler -- it recovers the argument *count* (``a0``..``aN``)
and whether the function yields a value in ``v0`` -- so a signature reads
``int sub_X(int a0, int a1)`` instead of the bare ``void sub_X(void)``.

A call clobbers the caller-saved registers (``a0``-``a3``, ``v0``/``v1``,
``t0``-``t9``, ``at``, ``ra``, ``hi``/``lo``), so an argument register read only
*after* a call does not count -- that matches how real code reloads nothing.
"""

from . import ir, isa

ARG_REGS = ("a0", "a1", "a2", "a3")
CALLER_SAVED = frozenset((
    "at", "v0", "v1", "a0", "a1", "a2", "a3",
    "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9",
    "ra", "hi", "lo",
))


def _regs(e, out):
    if isinstance(e, ir.Reg):
        out.add(e.name)
    elif isinstance(e, ir.Bin):
        _regs(e.l, out); _regs(e.r, out)
    elif isinstance(e, ir.Un):
        _regs(e.e, out)
    elif isinstance(e, ir.Mem):
        if isinstance(e.addr, ir.Expr):
            _regs(e.addr, out)
    elif isinstance(e, ir.IntrExpr):
        for a in e.args:
            _regs(a, out)
    return out


def _use_def(stmt):
    """(reads, writes) of GPR-ish register names for one IR statement."""
    use, defn = set(), set()
    if isinstance(stmt, ir.Assign):
        _regs(stmt.src, use)
        if isinstance(stmt.dst, ir.Reg):
            defn.add(stmt.dst.name)
        elif isinstance(stmt.dst, ir.Mem) and isinstance(stmt.dst.addr, ir.Expr):
            _regs(stmt.dst.addr, use)
    elif isinstance(stmt, ir.Branch):
        _regs(stmt.cexpr, use)
    elif isinstance(stmt, ir.Call):
        if stmt.expr is not None:
            _regs(stmt.expr, use)
        defn |= CALLER_SAVED
    elif isinstance(stmt, ir.Intrinsic):
        for a in stmt.args:
            _regs(a, use)
    return use, defn


def _block_use_def(block):
    """Upward-exposed uses and the kill set for a whole block."""
    use, defn = set(), set()
    for s in block.stmts:
        u, d = _use_def(s)
        use |= (u - defn)      # used before defined in this block
        defn |= d
    return use, defn


def live_in_entry(func):
    blocks = func.blocks
    bud = {ea: _block_use_def(b) for ea, b in blocks.items()}
    live_in = {ea: set() for ea in blocks}
    changed = True
    while changed:
        changed = False
        for ea, b in blocks.items():
            out = set()
            for _, tgt in b.succ:
                if tgt in live_in:
                    out |= live_in[tgt]
            use, defn = bud[ea]
            nin = use | (out - defn)
            if nin != live_in[ea]:
                live_in[ea] = nin
                changed = True
    return live_in.get(func.entry, set())


def params(func):
    lin = live_in_entry(func)
    hi = -1
    for i, r in enumerate(ARG_REGS):
        if r in lin:
            hi = i
    return list(ARG_REGS[:hi + 1])


def returns_value(func):
    """True if v0 is given a value that reaches a return.

    A definition of v0 (an explicit assignment, or a call whose result lands in
    v0) that can reach a `ret` block makes the function value-returning."""
    defs = set()
    for ea, b in func.blocks.items():
        for s in b.stmts:
            if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and s.dst.name == "v0":
                defs.add(ea); break
            if isinstance(s, ir.Call):
                defs.add(ea); break
    if not defs:
        return False
    # can any v0-defining block reach a ret block?
    succ = {ea: [t for _, t in b.succ if t in func.blocks] for ea, b in func.blocks.items()}
    rets = {ea for ea, b in func.blocks.items() if b.term == "ret"}
    # reverse reachability from ret blocks
    pred = {ea: [] for ea in func.blocks}
    for ea, ss in succ.items():
        for t in ss:
            pred[t].append(ea)
    seen = set(rets)
    work = list(rets)
    while work:
        n = work.pop()
        for p in pred.get(n, ()):
            if p not in seen:
                seen.add(p); work.append(p)
    # a v0 def reaches a ret if that def-block can reach a ret, AND explicitly
    # assigns v0 (call-only clobber is treated as a value too, matching Hex-Rays
    # `return foo();`).
    explicit = any(
        isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and s.dst.name == "v0"
        for b in func.blocks.values() for s in b.stmts
    )
    return explicit and bool(defs & seen)


def _mem_bases(e, out):
    """register names used as a memory base in expression *e*."""
    if isinstance(e, ir.Mem) and isinstance(e.addr, ir.Expr):
        a = e.addr
        if isinstance(a, ir.Reg):
            out.add(a.name)
        elif isinstance(a, ir.Bin) and a.op == "+" and isinstance(a.l, ir.Reg):
            out.add(a.l.name)
        _mem_bases(a, out)
    elif isinstance(e, ir.Bin):
        _mem_bases(e.l, out); _mem_bases(e.r, out)
    elif isinstance(e, ir.Un):
        _mem_bases(e.e, out)
    elif isinstance(e, ir.IntrExpr):
        for a in e.args:
            _mem_bases(a, out)
    return out


def _dst_bases(s, bases):
    if isinstance(s, ir.Assign):
        _mem_bases(s.src, bases)
        if isinstance(s.dst, ir.Mem):
            if isinstance(s.dst.addr, ir.Reg):
                bases.add(s.dst.addr.name)
            elif isinstance(s.dst.addr, ir.Bin) and isinstance(s.dst.addr.l, ir.Reg):
                bases.add(s.dst.addr.l.name)
            _mem_bases(s.dst, bases)
    elif isinstance(s, ir.Branch):
        _mem_bases(s.cexpr, bases)
    elif isinstance(s, ir.Intrinsic):
        for a in s.args:
            _mem_bases(a, bases)
    elif isinstance(s, ir.Call) and s.expr is not None:
        _mem_bases(s.expr, bases)
    return bases


def _pointer_params(func, ps):
    """A parameter is typed as a pointer when it (or a register that carries its
    value through single copies) is used as a memory base.  Tracking copies lets
    the common ``s0 = a0; ... lw (s0)`` idiom still mark ``a0`` as a pointer."""
    if not ps:
        return set()
    # how many times is each register assigned?
    defcount = {}
    for b in func.blocks.values():
        for s in b.stmts:
            if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg):
                defcount[s.dst.name] = defcount.get(s.dst.name, 0) + 1
    # alias each single-def register back to the parameter it copies (fixpoint)
    alias = {p: p for p in ps}
    for _ in range(6):
        changed = False
        for b in func.blocks.values():
            for s in b.stmts:
                if (isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg)
                        and isinstance(s.src, ir.Reg)
                        and s.src.name in alias and defcount.get(s.dst.name, 0) == 1
                        and s.dst.name not in alias):
                    alias[s.dst.name] = alias[s.src.name]
                    changed = True
        if not changed:
            break
    # a param whose alias set is dereferenced anywhere is a pointer
    ptr = set()
    for b in func.blocks.values():
        for s in b.stmts:
            bases = set()
            _dst_bases(s, bases)
            for reg in bases:
                root = alias.get(reg)
                if root in ps:
                    ptr.add(root)
    return ptr


def signature(func, name):
    ps = params(func)
    ret = "int" if returns_value(func) else "void"
    ptr = _pointer_params(func, ps)
    args = ", ".join(("int *%s" % p if p in ptr else "int %s" % p) for p in ps) if ps else "void"
    return "%s %s(%s)" % (ret, name, args), ps, ret == "int"
