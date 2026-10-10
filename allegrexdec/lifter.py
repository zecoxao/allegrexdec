"""
Lift decoded Allegrex :class:`~allegrexdec.decoder.Insn` objects into IR.

MIPS compare-and-branch becomes an :class:`~allegrexdec.ir.Branch` carrying a
full relational condition, so no flag modelling is needed.  ``$zero`` reads as
the constant 0 and writes to it are dropped, which turns the ``addu rd,rs,zero``
/ ``or rd,rs,zero`` idioms into plain ``rd = rs;`` after optimisation.  COP1
(FPU) arithmetic lifts to real float expressions; multiply/divide write the
``hi``/``lo`` pair; the VFPU, coprocessor control moves, and other operations
that do not map onto C are honest :class:`~allegrexdec.ir.Intrinsic` /
:class:`~allegrexdec.ir.IntrExpr` pseudo-calls.
"""

from . import ir, isa
from .decoder import target_of


def _reg(i):
    return ir.Const(0) if (i & 0x1F) == 0 else ir.Reg(isa.GPR[i & 0x1F])


def op_expr(op):
    m = op.mode
    if m == "reg":
        return _reg(op.reg)
    if m == "imm":
        return ir.Const(op.value)
    if m == "freg":
        return ir.Reg(isa.FPR[op.reg & 0x1F])
    if m == "name":
        return ir.Reg(op.text)
    if m == "near":
        return ir.Const(op.addr)
    if m == "displ":
        base = _reg(op.base_reg)
        if isinstance(base, ir.Const) and base.value == 0:
            addr = ir.Const(op.disp)
        elif op.disp == 0:
            addr = base
        else:
            addr = ir.Bin("+", base, ir.Const(op.disp))
        return ir.Mem(addr, op.width, op.signed)
    return ir.Const(0)


def _san(mnem):
    return mnem.replace(".", "_")


_ALU = {"add": "+", "addu": "+", "sub": "-", "subu": "-", "and": "&",
        "or": "|", "xor": "^", "sllv": "<<", "srlv": ">>",
        "addi": "+", "addiu": "+", "andi": "&", "ori": "|", "xori": "^"}
_ALUI_CMP = {"slt": "<", "sltu": "<", "slti": "<", "sltiu": "<"}
_LOAD = {"lb": (1, True), "lbu": (1, False), "lh": (2, True), "lhu": (2, False),
         "lw": (4, False), "ll": (4, False)}
_STORE = {"sb": 1, "sh": 2, "sw": 4}
_FARITH = {"add": "+", "sub": "-", "mul": "*", "div": "/"}


def _assign(ea, dst_op, src_expr):
    # drop writes to $zero
    if dst_op.mode == "reg" and (dst_op.reg & 0x1F) == 0:
        return [ir.Nop(ea)]
    return [ir.Assign(ea, op_expr(dst_op), src_expr)]


def lift_insn(ins):
    ea = ins.ea
    m = ins.mnem
    ops = ins.ops

    def e(i):
        return op_expr(ops[i])

    # --- integer ALU (3-op reg/imm) ---------------------------------------
    if m in _ALU:
        return _assign(ea, ops[0], ir.Bin(_ALU[m], e(1), e(2)))
    if m in _ALUI_CMP:
        return _assign(ea, ops[0], ir.Bin("<", e(1), e(2)))
    if m == "nor":
        return _assign(ea, ops[0], ir.Un("~", ir.Bin("|", e(1), e(2))))
    if m == "lui":
        return _assign(ea, ops[0], ir.Const((ops[1].value & 0xFFFF) << 16))
    if m in ("sll", "srl"):
        return _assign(ea, ops[0], ir.Bin("<<" if m == "sll" else ">>", e(1), e(2)))
    if m in ("sra", "srav"):
        return _assign(ea, ops[0], ir.IntrExpr("sra", [e(1), e(2)]))
    if m in ("rotr", "rotrv"):
        return _assign(ea, ops[0], ir.IntrExpr("rotr", [e(1), e(2)]))
    if m in ("movz", "movn", "max", "min", "clz", "clo", "wsbh", "wsbw",
             "seb", "seh", "bitrev"):
        return _assign(ea, ops[0], ir.IntrExpr(m, [e(i) for i in range(1, len(ops))]))
    if m == "ext":
        return _assign(ea, ops[0], ir.IntrExpr("ext", [e(1), e(2), e(3)]))
    if m == "ins":
        return _assign(ea, ops[0], ir.IntrExpr("ins", [e(1), e(2), e(3)]))

    # --- loads / stores ----------------------------------------------------
    if m in _LOAD:
        w, sg = _LOAD[m]
        src = op_expr(ops[1]); src.width = w; src.signed = sg
        return _assign(ea, ops[0], src)
    if m in _STORE:
        dst = op_expr(ops[1]); dst.width = _STORE[m]
        return [ir.Assign(ea, dst, e(0))]
    if m in ("lwl", "lwr"):
        return _assign(ea, ops[0], ir.IntrExpr(m, [op_expr(ops[1])]))
    if m in ("swl", "swr", "sc"):
        return [ir.Intrinsic(ea, _san(m), [e(0), op_expr(ops[1])])]

    # --- hi/lo arithmetic --------------------------------------------------
    if m in ("mult", "multu"):
        return [ir.Assign(ea, ir.Reg("lo"), ir.IntrExpr(m, [e(0), e(1)])),
                ir.Assign(ea, ir.Reg("hi"), ir.IntrExpr(m + "h", [e(0), e(1)]))]
    if m == "div":
        return [ir.Assign(ea, ir.Reg("lo"), ir.IntrExpr("sdiv", [e(0), e(1)])),
                ir.Assign(ea, ir.Reg("hi"), ir.IntrExpr("smod", [e(0), e(1)]))]
    if m == "divu":
        return [ir.Assign(ea, ir.Reg("lo"), ir.Bin("/", e(0), e(1))),
                ir.Assign(ea, ir.Reg("hi"), ir.Bin("%", e(0), e(1)))]
    if m in ("madd", "maddu", "msub", "msubu"):
        return [ir.Intrinsic(ea, m, [e(0), e(1)], note="hi:lo accumulate")]
    if m == "mfhi":
        return _assign(ea, ops[0], ir.Reg("hi"))
    if m == "mflo":
        return _assign(ea, ops[0], ir.Reg("lo"))
    if m == "mthi":
        return [ir.Assign(ea, ir.Reg("hi"), e(0))]
    if m == "mtlo":
        return [ir.Assign(ea, ir.Reg("lo"), e(0))]

    # --- FPU (COP1) --------------------------------------------------------
    if "." in m and m.split(".")[0] in _FARITH and len(ops) == 3:
        return _assign(ea, ops[0], ir.Bin(_FARITH[m.split(".")[0]], e(1), e(2)))
    if m.startswith("mov.") and len(ops) == 2:
        return _assign(ea, ops[0], e(1))
    if m.startswith("neg.") and len(ops) == 2:
        return _assign(ea, ops[0], ir.Un("-", e(1)))
    if m.startswith(("abs.", "sqrt.")) and len(ops) == 2:
        return _assign(ea, ops[0], ir.IntrExpr(_san(m), [e(1)]))
    if (m.startswith(("cvt.", "trunc.", "round.", "ceil.", "floor."))) and len(ops) == 2:
        return _assign(ea, ops[0], ir.IntrExpr(_san(m), [e(1)]))
    if m.startswith("c.") and len(ops) == 2:
        cond = m.split(".")[1]
        simple = {"eq": "==", "lt": "<", "le": "<=", "seq": "==", "olt": "<", "ole": "<="}
        if cond in simple:
            cx = ir.Bin(simple[cond], e(0), e(1))
        else:
            cx = ir.IntrExpr(_san(m), [e(0), e(1)])
        return [ir.Assign(ea, ir.Reg("fcc"), cx)]
    if m == "mfc1":
        return _assign(ea, ops[0], e(1))
    if m == "mtc1":
        return [ir.Assign(ea, e(1), e(0))]
    if m in ("cfc1", "ctc1"):
        if m == "cfc1":
            return _assign(ea, ops[0], e(1))
        return [ir.Assign(ea, e(1), e(0))]
    if m == "lwc1":
        return _assign(ea, ops[0], op_expr(ops[1]))
    if m == "swc1":
        return [ir.Assign(ea, op_expr(ops[1]), e(0))]

    # --- COP0 --------------------------------------------------------------
    if m in ("mfc0", "cfc0", "rdpgpr"):
        return _assign(ea, ops[0], ir.IntrExpr(m, [e(1)]))
    if m in ("mtc0", "ctc0", "wrpgpr"):
        return [ir.Intrinsic(ea, m, [e(0), e(1)])]
    if m in ("mfic",):
        return _assign(ea, ops[0], ir.IntrExpr("mfic", []))
    if m in ("mtic",):
        return [ir.Intrinsic(ea, "mtic", [e(0)])]

    # --- control flow ------------------------------------------------------
    if m in ("j", "b", "bl"):
        return [ir.Goto(ea, target_of(ins))]
    if m == "jal":
        return [ir.Call(ea, target=target_of(ins))]
    if m == "jalr":
        return [ir.Call(ea, expr=e(1) if len(ops) > 1 else e(0))]
    if m in isa.COND_CALL:
        return [ir.Call(ea, target=target_of(ins),
                        expr=None)]
    if m == "jr_ra" or m == "eret":
        return [ir.Ret(ea, m)]
    if m == "jr":
        return [ir.Intrinsic(ea, "JUMPOUT", [e(0)], note="indirect jump")]
    if m in isa.COND_BRANCH:
        return [ir.Branch(ea, _branch_cond(m, ops), target_of(ins), ea + 8)]

    # --- cpu control / misc ------------------------------------------------
    if m in ("syscall", "break", "sync", "cache", "di", "ei", "wait",
             "tlbr", "tlbwi", "tlbwr", "tlbp", "synci", "deret", "halt",
             "rdhwr"):
        if m == "rdhwr":
            return _assign(ea, ops[0], ir.IntrExpr("rdhwr", [e(1)]))
        return [ir.Intrinsic(ea, m, [op_expr(o) for o in ops])]
    if m in ("tge", "tgeu", "tlt", "tltu", "teq", "tne",
             "tgei", "tgeiu", "tlti", "tltiu", "teqi", "tnei"):
        return [ir.Intrinsic(ea, m, [op_expr(o) for o in ops], note="trap")]
    if m == "nop" or m == ".word":
        return [ir.Nop(ea)] if m == "nop" else \
               [ir.Intrinsic(ea, "dword", [op_expr(ops[0])], note="undecoded")]

    # --- VFPU --------------------------------------------------------------
    if m in ("bvt", "bvf", "bvtl", "bvfl"):
        cc = ir.Reg("CC")
        cx = cc if m in ("bvt", "bvtl") else ir.Un("!", cc)
        return [ir.Branch(ea, cx, target_of(ins), ea + 8)]
    if m.startswith("v") or m in ("mfv", "mtv", "mfvc", "mtvc"):
        return [ir.Intrinsic(ea, _san(m), [op_expr(o) for o in ops], note="vfpu")]

    return [ir.Intrinsic(ea, _san(m), [op_expr(o) for o in ops], note="unmodelled")]


def _branch_cond(m, ops):
    if m in ("beq", "beql"):
        return ir.Bin("==", op_expr(ops[0]), op_expr(ops[1]))
    if m in ("bne", "bnel"):
        return ir.Bin("!=", op_expr(ops[0]), op_expr(ops[1]))
    rs = op_expr(ops[0])
    if m in ("bgez", "bgezl"):
        return ir.Bin(">=", rs, ir.Const(0))
    if m in ("bgtz", "bgtzl"):
        return ir.Bin(">", rs, ir.Const(0))
    if m in ("blez", "blezl"):
        return ir.Bin("<=", rs, ir.Const(0))
    if m in ("bltz", "bltzl"):
        return ir.Bin("<", rs, ir.Const(0))
    if m in ("bc1t", "bc1tl"):
        return ir.Reg("fcc")
    if m in ("bc1f", "bc1fl"):
        return ir.Un("!", ir.Reg("fcc"))
    return ir.Const(1)
