"""
Headless tests for the Allegrex decoder and decompiler pipeline.  No IDA, no ROM.

    python tests/test_pipeline.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from allegrexdec import decoder, decompile_image        # noqa: E402


def _img(words):
    a = bytearray()
    for w in words:
        a += struct.pack("<I", w & 0xFFFFFFFF)
    return a


def _one(word):
    return decoder.decode_one(_img([word]), 0)


def test_decode_integer():
    # addiu a0, zero, 5   -> prime 9, rt=4, rs=0, imm=5
    ins = _one(0x24040005)
    assert ins.mnem == "addiu" and ins.ops[0].reg == 4 and ins.ops[1].reg == 0
    assert ins.ops[2].value == 5, ins.ops[2].value

    # lui v0, 0x8880  -> prime 15, rt=2
    ins = _one(0x3C028880)
    assert ins.mnem == "lui" and ins.ops[0].reg == 2 and ins.ops[1].value == 0x8880

    # lw ra, 0x10(sp) -> prime 35, base=29(sp), rt=31(ra), off=0x10
    ins = _one(0x8FBF0010)
    assert ins.mnem == "lw" and ins.ops[0].reg == 31
    assert ins.ops[1].mode == "displ" and ins.ops[1].base_reg == 29 and ins.ops[1].disp == 0x10

    # jr ra -> special fct=8 rs=31
    ins = _one(0x03E00008)
    assert ins.mnem == "jr_ra", ins.mnem

    # addu v0, a0, zero -> special fct=33, rd=2, rs=4, rt=0
    ins = _one(0x00801021)
    assert ins.mnem == "addu" and ins.ops[0].reg == 2 and ins.ops[1].reg == 4

    # sll zero,zero,0 == nop
    assert _one(0x00000000).mnem == "nop"
    print("ok  test_decode_integer")


def test_branch_target():
    # beq a0, a1, +0x20  : prime4 rs=4 rt=5 off=8 (8*4=0x20 from delay slot)
    #   target = ea + 4 + (off<<2) = 0 + 4 + 0x20 = 0x24
    ins = _one(0x10850008)
    assert ins.mnem == "beq"
    assert decoder.target_of(ins) == 0x24, hex(decoder.target_of(ins))

    # b (beq zero,zero) collapses to unconditional
    ins = _one(0x1000FFFF)
    assert ins.mnem == "b", ins.mnem

    # jal 0x10 : prime3, target=((ea+4)&0xF0000000)|(idx<<2); idx=4 -> 0x10
    ins = _one(0x0C000004)
    assert ins.mnem == "jal" and decoder.target_of(ins) == 0x10
    print("ok  test_branch_target")


def test_fpu_vfpu():
    # add.s f0, f2, f4 : prime17 fmt=0x10 ft=4 fs=2 fd=0 fct=0
    ins = _one(0x46042000)
    assert ins.mnem == "add.s", ins.mnem
    assert ins.ops[0].mode == "freg" and ins.ops[0].reg == 0

    # vadd.s S000,S000,S000 : prime24 vop3=0 vc1=0 vc0=0, all fields 0
    ins = _one(0x60000000)
    assert ins.mnem == "vadd.s", ins.mnem
    assert ins.ops[0].text == "S000"

    # vmul.q with all-zero regs : prime25 (0x64000000) vop3=0 vc1=1 vc0=1
    ins = _one(0x64008080)
    assert ins.mnem == "vmul.q", ins.mnem
    print("ok  test_fpu_vfpu")


def test_all_words_no_raise():
    # a scattered sweep -- the decoder must never raise, only fall back to .word
    img = bytearray(4)
    for hi in range(0, 0x100):
        for lo in (0x00000000, 0x12345678, 0xFFFFFFFF, 0xDEADBEEF):
            w = (hi << 24) | (lo & 0xFFFFFF)
            img[0] = w & 0xFF; img[1] = (w >> 8) & 0xFF
            img[2] = (w >> 16) & 0xFF; img[3] = (w >> 24) & 0xFF
            decoder.decode_one(img, 0)
    print("ok  test_all_words_no_raise")


def test_delayslot_and_structuring():
    # A small function with a loop that uses a delay slot:
    #   li   a1, 0          addiu a1,zero,0
    # loop:
    #   addiu a1, a1, 1
    #   slti  v0, a1, 4
    #   bne   v0, zero, loop   (delay slot: nop)
    #   nop
    #   jr ra                  (delay slot: nop)
    #   nop
    words = [
        0x24050000,                 # 0x00 addiu a1, zero, 0
        0x24A50001,                 # 0x04 addiu a1, a1, 1
        0x28A20004,                 # 0x08 slti v0, a1, 4
        0x1440FFFD,                 # 0x0C bne v0, zero, 0x04
        0x00000000,                 # 0x10 nop (delay slot)
        0x03E00008,                 # 0x14 jr ra
        0x00000000,                 # 0x18 nop (delay slot)
    ]
    prog = decompile_image(_img(words), entries=[0], base=0)
    fn = prog.funcs[0]
    text = "\n".join(fn.lines)
    assert "a1 = 0;" in text, text
    assert "a1 = a1 + 1;" in text, text
    assert ("while" in text or "do {" in text), text
    assert text.count("{") == text.count("}"), text
    print("ok  test_delayslot_and_structuring\n")
    print(text)


def test_param_return_recovery():
    # int f(a0, a1) { return a0 + a1; }
    #   addu v0, a0, a1   ; jr ra ; nop
    words = [0x00851021, 0x03E00008, 0x00000000]
    prog = decompile_image(_img(words), entries=[0], base=0)
    fn = prog.funcs[0]
    sig = fn.lines[0]
    assert sig == "int sub_0(int a0, int a1)", sig
    assert "return v0;" in "\n".join(fn.lines), fn.lines

    # void g(void) { } -- bare jr ra ; nop (reads/writes nothing)
    prog = decompile_image(_img([0x03E00008, 0x00000000]), entries=[0], base=0)
    sig = prog.funcs[0].lines[0]
    assert sig == "void sub_0(void)", sig
    print("ok  test_param_return_recovery")


def test_frame_and_pointer():
    # int f(int *a0) { return a0[0]; } with a full prologue/epilogue to hide:
    #   addiu sp, sp, -0x10 ; sw ra, 8(sp) ; lw v0, 0(a0)
    #   lw ra, 8(sp) ; addiu sp, sp, 0x10 ; jr ra ; nop
    words = [0x27BDFFF0, 0xAFBF0008, 0x8C820000,
             0x8FBF0008, 0x27BD0010, 0x03E00008, 0x00000000]
    prog = decompile_image(_img(words), entries=[0], base=0)
    text = "\n".join(prog.funcs[0].lines)
    assert prog.funcs[0].lines[0] == "int sub_0(int *a0)", prog.funcs[0].lines[0]
    assert "v0 = mem32[a0];" in text, text
    assert "return v0;" in text, text
    # prologue/epilogue and the ra spill must be gone
    assert "sp =" not in text and "mem32[sp" not in text and "ra =" not in text, text
    print("ok  test_frame_and_pointer")


def test_call_arguments():
    # sub_0:  a0 = 5; jal sub_40; (delay nop); jr ra; nop
    # sub_40: jr ra; nop
    words = [0] * 0x12
    words[0] = 0x24040005          # 0x00 addiu a0, zero, 5
    words[1] = 0x0C000010          # 0x04 jal 0x40
    words[2] = 0x00000000          # 0x08 nop (delay slot)
    words[3] = 0x03E00008          # 0x0C jr ra
    words[4] = 0x00000000          # 0x10 nop (delay slot)
    words[0x10] = 0x03E00008       # 0x40 jr ra
    words[0x11] = 0x00000000       # 0x44 nop
    prog = decompile_image(_img(words), entries=[0], base=0)
    text = "\n".join(prog.funcs[0].lines)
    assert "sub_40(5);" in text, text          # the a0 set-up is folded into the call
    assert "a0 = 5;" not in text, text          # and removed as a standalone stmt
    print("ok  test_call_arguments")


if __name__ == "__main__":
    test_decode_integer()
    test_branch_target()
    test_fpu_vfpu()
    test_all_words_no_raise()
    test_delayslot_and_structuring()
    test_param_return_recovery()
    test_frame_and_pointer()
    test_call_arguments()
    print("\nall tests passed")
