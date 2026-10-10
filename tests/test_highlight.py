"""Headless test for the highlighter (stubs ida_lines).  python tests/test_highlight.py"""

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _stub():
    il = types.ModuleType("ida_lines")
    il.COLSTR = lambda t, c: "<%s>%s</%s>" % (c, t, c)
    for n in ("AUTOCMT", "NUMBER", "KEYWORD", "TYPE", "CREFTAIL", "CNAME", "REG", "SYMBOL"):
        setattr(il, "SCOLOR_" + n, n.lower())
    sys.modules["ida_lines"] = il


def test_highlight():
    _stub()
    from allegrexdec import highlight as H
    assert "<keyword>do</keyword>" in H.colorize("    do {")
    assert "<keyword>while</keyword>" in H.colorize("    } while (a1 != 0);")
    assert "<creftail>sub_C370</creftail>" in H.colorize("    sub_C370();")
    assert "<creftail>loc_48</creftail>" in H.colorize("    goto loc_48;")
    assert "<number>0x80210000</number>" in H.colorize("    v0 = 0x80210000;")
    assert "<cname>mem32</cname>" in H.colorize("    mem32[sp] = ra;")
    assert "<reg>a0</reg>" in H.colorize("    a0 = a1;")
    assert "<cname>JUMPOUT</cname>" in H.colorize("    JUMPOUT(t9);")
    assert H.colorize("loc_48:").startswith("<creftail>")
    assert len(H.colorize_all(["void f(void)", "{", "}"])) == 3
    print("ok  test_highlight")


if __name__ == "__main__":
    test_highlight()
    print("\nall tests passed")
