"""
Control-flow graph for Allegrex (MIPS).  Carves the decoded stream into
functions and basic blocks and lifts each block, folding MIPS *delay slots* into
their owning transfer: the instruction after a branch/jump/call is emitted just
before the control statement, so the pseudo-C reads in source order.

Block-ending transfers (branch / j / b / jr / jr ra / eret) close a block;
a call (jal / jalr) consumes its delay slot but keeps the block open, continuing
at the instruction past the slot.  Conditional branches fall through to ea+8.
"""

from . import isa
from .lifter import lift_insn
from .decoder import target_of

_ENDING = isa.UNCOND | isa.RET | isa.IJUMP | isa.COND_BRANCH
_CALLS = isa.CALL | isa.CALL_IND | isa.COND_CALL


class Block:
    __slots__ = ("start", "stmts", "succ", "term")

    def __init__(self, start):
        self.start = start
        self.stmts = []
        self.succ = []
        self.term = None


class Func:
    __slots__ = ("entry", "blocks", "calls", "name")

    def __init__(self, entry):
        self.entry = entry
        self.blocks = {}
        self.calls = set()
        self.name = None

    def ordered(self):
        return [self.blocks[k] for k in sorted(self.blocks)]


def _body_succ(ins):
    m = ins.mnem
    t = target_of(ins)
    if m in isa.UNCOND:
        return [t] if t is not None else []
    if m in isa.RET or m in isa.IJUMP:
        return []
    if m in isa.COND_BRANCH:
        s = [ins.ea + 8]
        if t is not None:
            s.append(t)
        return s
    if m in _CALLS:
        return [ins.ea + 8]
    return [ins.ea + ins.size]


def _collect_body(insns, entry, entry_set):
    body = set()
    work = [entry]
    while work:
        ea = work.pop()
        if ea in body or ea not in insns:
            continue
        body.add(ea)
        for tgt in _body_succ(insns[ea]):
            if tgt in insns and (tgt == entry or tgt not in entry_set):
                work.append(tgt)
    return body


def _leaders(insns, body):
    leaders = set()
    for ea in body:
        ins = insns[ea]
        m = ins.mnem
        t = target_of(ins)
        if m in isa.COND_BRANCH:
            if t in body:
                leaders.add(t)
            if ea + 8 in body:
                leaders.add(ea + 8)
        elif m in isa.UNCOND:
            if t in body:
                leaders.add(t)
    return leaders


def _terminator(ins, body):
    m = ins.mnem
    t = target_of(ins)
    if m in isa.UNCOND:
        return "goto", [("jump", t)] if t is not None else []
    if m in isa.RET or m in isa.IJUMP:
        return "ret", []
    if m in isa.COND_BRANCH:
        succ = []
        if t is not None:
            succ.append(("cond", t))
        succ.append(("fall", ins.ea + 8))
        return "branch", succ
    return "fall", []


def build_func(insns, entry, entry_set):
    body = _collect_body(insns, entry, entry_set)
    if not body:
        return None
    delay = set()
    for ea in body:
        if isa.is_transfer(insns[ea].mnem):
            delay.add(ea + 4)
    leaders = _leaders(insns, body)
    leaders.add(entry)

    addrs = [a for a in sorted(body) if a not in delay]
    f = Func(entry)
    cur = None
    for idx, ea in enumerate(addrs):
        ins = insns[ea]
        if cur is None or ea in leaders:
            cur = Block(ea)
            f.blocks[ea] = cur
        m = ins.mnem
        nextaddr = addrs[idx + 1] if idx + 1 < len(addrs) else None

        if isa.is_transfer(m):
            slot = insns.get(ea + 4)
            if slot is not None and not isa.is_transfer(slot.mnem):
                cur.stmts.extend(lift_insn(slot))
            cur.stmts.extend(lift_insn(ins))
            if m in isa.CALL or m in isa.COND_CALL:
                if target_of(ins) is not None:
                    f.calls.add(target_of(ins))
            if m in _ENDING:
                cur.term, cur.succ = _terminator(ins, body)
                cur = None
            else:                                   # a call: keep the block open
                nxt = ea + 8
                if nxt not in body or nextaddr != nxt or nxt in leaders:
                    cur.term = "fall"
                    cur.succ = [("fall", nxt)] if nxt in body else []
                    cur = None
        else:
            cur.stmts.extend(lift_insn(ins))
            nxt = ea + ins.size
            if nextaddr is None or nextaddr != nxt or nxt in leaders:
                cur.term = "fall"
                cur.succ = [("fall", nxt)] if nxt in body else []
                cur = None

    for b in f.blocks.values():
        if b.term is None:
            b.term = "ret"
            b.succ = []
    return f


def build_functions(insns, calls, extra_entries=()):
    entry_set = {e for e in (set(calls) | set(extra_entries)) if e in insns}
    funcs = {}
    for entry in sorted(entry_set):
        fn = build_func(insns, entry, entry_set)
        if fn is not None:
            funcs[entry] = fn
    return funcs
