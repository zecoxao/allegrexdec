# allegrexdec — a Sony PSP Allegrex (MIPS + VFPU) decompiler

`allegrexdec` decompiles PSP code for the **Allegrex** CPU — MIPS II with the
Allegrex integer extensions, the COP1 FPU and the **VFPU** vector unit — to
readable pseudo-C. It is the MIPS member of zecoxao's decompiler family
([`spudec`](https://github.com/zecoxao/spudec),
[`startrekdec`](https://github.com/zecoxao/startrekdec),
[`f00ddec`](https://github.com/zecoxao/f00ddec),
[`rl78dec`](https://github.com/zecoxao/rl78dec),
[`mechadec`](https://github.com/zecoxao/mechadec)): a decoder produces
instructions, a lifter turns them into a machine-independent IR, and everything
above that is shared in design.

```
decoder → lifter → cfg → opt → structure → cgen
```

## What it produces

```c
int sub_70(int a0)                       // a0 recovered as a parameter (o32 ABI)
{
    sp = sp - 0x10;
    mem32[sp + 8] = ra;
    mem32[sp + 4] = s1;
    s1 = a0;
    sub_1C8();
    sub_0();
    v1 = v0;
    if (v0 == 0) {
        v1 = 0xB0;
        v0 = 0x80210000;                 // lui + ori folded to one constant
        if (s1 == 0xB0) goto loc_158;
        ...
    }
    return v0;
}
```

(That is `int __fastcall sceUmdManInit(int a1)` in Hex-Rays — same parameter and
return value.)

Function **parameters and return values** are recovered from the MIPS o32 calling
convention: an argument register (`a0`-`a3`) read before being written is an
incoming parameter, and a function that leaves a value in `v0` returns `int`. On
`umdman.prx` this matches IDA's Hex-Rays exactly on the number of functions that
take parameters (138) and closely on the per-function argument count. MIPS
**delay slots** are folded into their owning branch, so the pseudo-C reads in
source order. GPRs print as the o32 ABI names (`a0..a3`, `t0..t9`, `s0..s7`,
`sp`, `ra` …); `$zero` reads as 0, which turns `addu rd,rs,zero` / `or rd,rs,zero`
into plain `rd = rs`; the `lui`+`ori`/`addiu` address idiom folds to one
constant; compare-and-branch folds into relational `if`s; loops become
`while` / `do-while`. Memory reads print as `mem8`/`mem16`/`mem32` (`s8`/`s16`
for sign-extending loads). `hi`/`lo`, multiply/divide, the FPU condition `fcc`,
the VFPU and coprocessor control moves that do not map cleanly onto C print as
honest pseudo-calls; register-indirect and cross-function jumps as
`JUMPOUT(addr)`.

## Two ways to run it

**Headless (no IDA)** — a PSP ELF/PRX (entry points come from the ELF entry, the
`.rodata.sceModuleInfo` exports, and `STT_FUNC` symbols, exactly as `prxldr`
names them), or a raw code blob with an explicit base:

```
python -m allegrexdec umdman.prx -o umdman.c
python -m allegrexdec umdman.prx --func 0x70
python -m allegrexdec umdman.prx --nids psplibdoc.xml      # resolve export/import names
python -m allegrexdec boot.bin --base 0x8804000 --entry 0x8804000
```

With a `psplibdoc.xml` (found next to the input, via `--nids`, or
`$ALLEGREXDEC_PSPLIBDOC`) the module's exported and imported functions are named
from their NIDs — `sceUmdManInit` instead of `sub_8804070` — the same database
`prxldr` uses.

**As an IDA plugin** — open the module with the MIPS/Allegrex processor (the
companion [`prxldr`](https://github.com/zecoxao/prxldr_python) loader selects
processor `psp`/`mipsl` and a 32-bit database), then drop
`allegrexdec_plugin.py` **and** the `allegrexdec/` package into
`%APPDATA%\Hex-Rays\IDA Pro\plugins\`:

| Hotkey | Action |
| --- | --- |
| `Ctrl-Shift-S` | decompile the function under the cursor |
| `Ctrl-Shift-A` | decompile the whole database (and offer to save it) |

The family's shared "decompile all" is `Ctrl-F5`, but on a MIPS database that
hotkey belongs to the licensed Hex-Rays MIPS decompiler, so allegrexdec uses
`Ctrl-Shift-A` instead (`Ctrl-Shift-S` for one function is unaffected — Hex-Rays
uses `F5` for that).

The viewer is theme-highlighted and double-click navigates. Inside IDA the
output reuses whatever names you have applied.

## The instruction set

Allegrex is little-endian, fixed 32-bit MIPS II with branch delay slots. The
decoder covers:

* **Integer**: the MIPS II base plus the Allegrex extensions — `ext`/`ins`,
  `seb`/`seh`/`wsbh`/`wsbw`/`bitrev`, `clz`/`clo`, `min`/`max`, `rotr`/`rotrv`,
  `madd`/`msub`, `movz`/`movn`, `mfic`/`mtic`, `ll`/`sc`, the traps and the
  COP0 system registers.
* **FPU (COP1)**: single/word arithmetic, conversions, compares (`c.cond.s`
  into `fcc`) and the `bc1t`/`bc1f` branches.
* **VFPU**: the full vector unit. Register naming (single `Smmnn`, pair/row
  `C`/`R`, matrix `M`/`E`) and the ~300-form opcode table are generated from
  kotcrab's [ghidra-allegrex](https://github.com/kotcrab/ghidra-allegrex)
  SLEIGH; arithmetic/matrix/load-store ops decode with their vector operands and
  lift to pseudo-calls (the VFPU does not map onto scalar C).

## Limitations

* Type inference is light: a parameter or local is `int`, or `int *` when it is
  dereferenced (tracked through single-copy aliases), and stack locals are typed
  `char`/`short`/`int` by access width. It does **not** reach Hex-Rays depth —
  no multi-level pointers (`char **`), no `__int16`/`BOOL`/struct recovery, no
  overlapping-slot coalescing or full register-to-variable renaming.
* The prologue/epilogue, frame-pointer setup and callee-saved spills are hidden
  and stack slots become `var_<off>`, but there is no argument-vs-local
  disambiguation beyond the o32 convention. `hi`/`lo`, `sra`, rotates, VFPU and
  coprocessor control remain intrinsics.
* Call arguments (`foo(a0, a1 …)`) are folded from the `a0`-`a3` set-up the
  compiler emits, so they reflect what the machine actually passes (often more
  faithful than a tool without a prototype, which shows a bare `()`). Only the
  first four register arguments are recovered; stack-passed (5+) arguments, and
  arguments set in a *different* basic block than the call (e.g. at a loop
  header), are not folded.
* NID→name needs a `psplibdoc.xml`; without one, headless output falls back to
  `sub_<addr>`. Inside IDA the plugin always reuses your own names.
* Branch-*likely* instructions (`beql`, `bc1tl` …) are structured like ordinary
  branches, and the conditional-call forms (`bgezal`/`bltzal`) are approximated
  as unconditional calls — a minor imprecision in rarely-compiled code.
* Entry discovery follows the ELF/module-info exports, symbols and direct calls;
  indirect calls and jump tables need seeding with `--entry`.

## Tests

```
python tests/test_pipeline.py
python tests/test_highlight.py
```

Hand-assembled, so they need neither IDA nor a firmware dump.

## Credits

Instruction semantics follow the Allegrex Instruction/User and FPU manuals and
kotcrab's `ghidra-allegrex` (the VFPU register and opcode tables are generated
from its SLEIGH). Pairs with zecoxao's `prxldr` PSP PRX loader. Decompiler design
mirrors `spudec`. MIT licensed. No firmware is included.
