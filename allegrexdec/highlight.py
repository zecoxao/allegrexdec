"""C syntax highlighting for the allegrexdec viewer (theme-aware; IDA-only import)."""

import re
import ida_lines

C_KEYWORDS = frozenset(("if", "else", "while", "do", "for", "return", "break",
                        "continue", "goto", "switch", "case", "default", "sizeof", "typedef"))
C_TYPES = frozenset(("void", "char", "short", "int", "long", "unsigned", "signed", "const"))
INTRINSICS = frozenset((
    "mem8", "mem16", "mem32", "s8", "s16", "JUMPOUT",
    "sra", "rotr", "movz", "movn", "max", "min", "clz", "clo",
    "wsbh", "wsbw", "seb", "seh", "bitrev", "ext", "ins",
    "mult", "multu", "multh", "multuh", "sdiv", "smod", "madd", "maddu",
    "msub", "msubu", "lwl", "lwr", "swl", "swr", "sc",
    "syscall", "break", "sync", "synci", "cache", "di", "ei", "wait",
    "halt", "deret", "eret", "tlbr", "tlbwi", "tlbwr", "tlbp", "rdhwr",
    "mfc0", "mtc0", "cfc0", "ctc0", "rdpgpr", "wrpgpr", "mfic", "mtic",
    "mfv", "mtv", "mfvc", "mtvc",
))


_TOK = re.compile(r"""
      (?P<comment>/\*.*?\*/|//.*)
    | (?P<hex>-?\b0[xX][0-9A-Fa-f]+)
    | (?P<num>-?\b\d+\b)
    | (?P<ident>[A-Za-z_$][A-Za-z_0-9$.]*)
    | (?P<ws>\s+)
    | (?P<op>.)
""", re.VERBOSE)
_CALL = re.compile(r"\s*[\(\[]")
_LABEL = re.compile(r"^[A-Za-z_]\w*:\s*$")


def _tag(t, c):
    return ida_lines.COLSTR(t, c)


def colorize(line):
    if not line:
        return line
    st = line.lstrip()
    if st.startswith(("//", "/*", "*", "*/")):
        return _tag(line, ida_lines.SCOLOR_AUTOCMT)
    if _LABEL.match(st):
        return _tag(line, ida_lines.SCOLOR_CREFTAIL)
    out, pos, n = [], 0, len(line)
    while pos < n:
        m = _TOK.match(line, pos)
        if not m:
            out.append(line[pos]); pos += 1; continue
        k, t = m.lastgroup, m.group(); pos = m.end()
        if k == "ws":
            out.append(t)
        elif k == "comment":
            out.append(_tag(t, ida_lines.SCOLOR_AUTOCMT))
        elif k in ("hex", "num"):
            out.append(_tag(t, ida_lines.SCOLOR_NUMBER))
        elif k == "ident":
            out.append(_tag(t, _ic(t, line, pos)))
        else:
            out.append(_tag(t, ida_lines.SCOLOR_SYMBOL))
    return "".join(out)


def _ic(t, line, after):
    if t in C_KEYWORDS:
        return ida_lines.SCOLOR_KEYWORD
    if t in C_TYPES:
        return ida_lines.SCOLOR_TYPE
    if t.startswith(("loc_", "sub_")):
        return ida_lines.SCOLOR_CREFTAIL
    base = t.split(".")[0]
    if t in INTRINSICS or base in INTRINSICS or base.startswith("v") or _CALL.match(line, after):
        return ida_lines.SCOLOR_CNAME
    return ida_lines.SCOLOR_REG


def colorize_all(lines):
    return [colorize(x) for x in lines]
