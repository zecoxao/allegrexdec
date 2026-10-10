"""
Headless CLI:

    python -m allegrexdec module.prx                 # entries from ELF/module info
    python -m allegrexdec module.prx -o module.c
    python -m allegrexdec boot.elf --func 0x8900120
    python -m allegrexdec blob.bin --base 0x8804000 --entry 0x8804000

No IDA required.
"""

import argparse
import sys

from . import decompile_file


def _int(s):
    return int(s, 0)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    ap = argparse.ArgumentParser(
        prog="allegrexdec",
        description="Decompile Sony PSP Allegrex (MIPS + VFPU) code to pseudo-C.")
    ap.add_argument("rom", help="PSP ELF/PRX, or a raw MIPS code blob")
    ap.add_argument("-o", "--out", help="write listing to this file (default: stdout)")
    ap.add_argument("--base", type=_int, default=None, help="link base for a raw blob")
    ap.add_argument("--entry", type=_int, action="append", default=None,
                    help="extra entry point (repeatable)")
    ap.add_argument("--func", type=_int, default=None,
                    help="only emit the function at this address")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args(argv)

    prog = decompile_file(args.rom, base=args.base,
                          extra_entries=tuple(args.entry) if args.entry else ())

    if args.func is not None:
        f = prog.funcs.get(args.func)
        if f is None:
            ap.error("no function decoded at 0x%X (try --entry 0x%X)" % (args.func, args.func))
        text = "\n".join(f.lines)
    else:
        text = prog.listing(banner=not args.no_banner)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fp:
            fp.write(text + "\n")
        print("allegrexdec: base 0x%X, %d functions -> %s"
              % (prog.base, len(prog.funcs), args.out), file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
