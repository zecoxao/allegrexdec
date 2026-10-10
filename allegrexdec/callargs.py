"""
Call-argument folding: show how parameters are passed at each call site.

The MIPS o32 convention puts the first four integer arguments in ``a0``-``a3``
(further ones on the stack).  A compiler loads ``a0``, ``a1`` ... immediately
before the call, so this pass tracks the current value of each argument register
within a basic block and, at a ``Call``, attaches the contiguous ``a0``.. values
as the call's arguments and drops the now-folded ``aN = ...`` set-up statements.

    a0 = 1; a1 = 0x20; a2 = 0; sceAtaAhbSetAtaBlock();
        -->   sceAtaAhbSetAtaBlock(1, 0x20, 0);

When the callee is one of our own functions its recovered parameter count caps
the list; for library calls (unknown arity) the contiguous run of argument
registers set since the previous call is used, which is what the compiler emitted.
Stack-passed arguments (5+) are not recovered.
"""

from . import ir

ARGS = ("a0", "a1", "a2", "a3")


def rewrite(func, arity=None):
    arity = arity or {}
    for b in func.blocks.values():
        argexpr = {}        # reg name -> current value expr
        argstmt = {}        # reg name -> the Assign that set it (to drop if folded)
        out = []
        for s in b.stmts:
            if isinstance(s, ir.Assign) and isinstance(s.dst, ir.Reg) and s.dst.name in ARGS:
                argexpr[s.dst.name] = s.src
                argstmt[s.dst.name] = s
                out.append(s)
                continue
            if isinstance(s, ir.Call):
                run = []
                for a in ARGS:
                    if a in argexpr:
                        run.append(a)
                    else:
                        break
                # Cap by the callee's own parameter count only when we know it
                # takes at least one argument.  Arity 0 means either a genuine
                # void function (no a-regs are set before it anyway) or a library
                # import trampoline whose real arity we cannot see -- in both
                # cases the compiler's a0.. set-up run is the right answer.
                n = arity.get(s.target)
                if n:
                    run = run[:n]
                s.args = [argexpr[a] for a in run]
                for a in run:
                    st = argstmt.get(a)
                    if st in out:
                        out.remove(st)
                argexpr.clear()
                argstmt.clear()
                out.append(s)
                continue
            # a plain register move/clobber of an arg reg (not a const/value set
            # we want to fold) still updates the tracked value; anything else is
            # passed through untouched.
            out.append(s)
        b.stmts = out
    return func
