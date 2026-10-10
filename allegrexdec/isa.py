"""
Allegrex (Sony PSP, MIPS II + Allegrex extensions + VFPU) instruction-set
description: register names and control-flow classification.  Single source of
truth for the decoder (:mod:`allegrexdec.decoder`), lifter and CFG builder;
encodings follow the Allegrex Instruction/User manuals and kotcrab's
ghidra-allegrex SLEIGH.

Little-endian, fixed 32-bit instructions, with MIPS branch *delay slots*: the
instruction after a branch or jump executes before control transfers.  The CFG
builder folds each delay slot into its owning transfer.
"""

# General-purpose registers, index 0..31 (standard MIPS o32 ABI names).
GPR = ("zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
       "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
       "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
       "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra")

# Floating-point (COP1) registers f0..f31.
FPR = tuple("f%d" % i for i in range(32))

# A few FP control registers (FCR), indexed by fs.
FCR = {0: "fir", 25: "fccr", 26: "fexr", 28: "fenr", 31: "fcsr"}

# COP0 data registers (mfc0/mtc0), indexed by rd.
COP0D = ("cop0_0", "cop0_1", "cop0_2", "cop0_3", "cop0_4", "cop0_5", "cop0_6", "cop0_7",
         "BadVAddr", "Count", "cop0_10", "Compare", "Status", "Cause", "EPC", "PRId",
         "Config", "cop0_17", "cop0_18", "cop0_19", "cop0_20", "SyscallCode", "CpuId",
         "cop0_23", "cop0_24", "ExceptionBase", "cop0_26", "cop0_27", "TagLo", "TagHi",
         "ErrorEPC", "cop0_31")

# COP0 control registers (cfc0/ctc0), indexed by rd.
COP0C = ("SavedEPC", "SavedErrorEPC", "SavedStatus", "SavedCause", "SavedV0", "SavedV1",
         "SavedErrorV0", "SavedErrorV1", "ExceptionTable", "ErrorHandler", "DebugHandler",
         "SyscallHandler", "SyscallTable", "SyscallMax", "KernelSP", "UserSP", "TCB",
         "cop0c_17", "cop0c_18", "cop0c_19", "cop0c_20", "cop0c_21", "cop0c_22", "cop0c_23",
         "cop0c_24", "cop0c_25", "cop0c_26", "cop0c_27", "cop0c_28", "cop0c_29", "cop0c_30",
         "cop0c_31")

# VFPU control registers (0..15).
VFPU_CTL = ("SPFX", "TPFX", "DPFX", "CC", "INF4", "RSV5", "RSV6", "REV",
            "RCX0", "RCX1", "RCX2", "RCX3", "RCX4", "RCX5", "RCX6", "RCX7")


def gpr(i):
    return GPR[i & 0x1F]


def fpr(i):
    return FPR[i & 0x1F]


# --- control-flow classification -------------------------------------------
# Conditional branches: taken-target + fall-through at ea+8 (past the slot).
COND_BRANCH = frozenset((
    "beq", "bne", "bgez", "bgtz", "blez", "bltz",
    "beql", "bnel", "bgezl", "bgtzl", "blezl", "bltzl",
    "bc1f", "bc1t", "bc1fl", "bc1tl",
    "bvf", "bvt", "bvfl", "bvtl",
))
# Conditional, and also link (call) when taken.
COND_CALL = frozenset(("bgezal", "bltzal", "bgezall", "bltzall"))
# Direct, unconditional calls.
CALL = frozenset(("jal",))
# Register-indirect call.
CALL_IND = frozenset(("jalr",))
# Unconditional intra-procedural transfers.
UNCOND = frozenset(("j", "b"))
# Returns.
RET = frozenset(("jr_ra", "eret"))     # jr ra is rewritten to jr_ra by decoder
# Register-indirect jump (jump table / tail call).
IJUMP = frozenset(("jr", "jr_ind"))
# Everything that ends a basic block.
STOP = COND_BRANCH | COND_CALL | CALL | CALL_IND | UNCOND | RET | IJUMP

# Instructions that take a delay slot (the following word runs first).
HAS_DELAY = COND_BRANCH | COND_CALL | CALL | CALL_IND | UNCOND | RET | IJUMP


def is_transfer(mnem):
    return mnem in HAS_DELAY
