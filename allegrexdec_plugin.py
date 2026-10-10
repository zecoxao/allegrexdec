"""
IDA plugin entry point for allegrexdec, the Sony PSP Allegrex (MIPS + VFPU)
decompiler.

Install by copying this file *and* the ``allegrexdec`` package directory
together into IDA's user plugin directory (``%APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\``).
Open the PSP ELF/PRX with a MIPS/Allegrex processor -- the companion ``prxldr``
loader selects processor ``psp``/``mipsl`` and a 32-bit database:

    Ctrl-Shift-S   decompile the function under the cursor
    Ctrl-Shift-A   decompile every function in the database

The family's "decompile all" is normally Ctrl-F5, but on a MIPS database that
hotkey belongs to the licensed Hex-Rays MIPS decompiler, so allegrexdec uses
Ctrl-Shift-A instead (Ctrl-Shift-S for one function stays, as Hex-Rays uses F5).
"""

import os
import sys
import time
import traceback

import ida_idaapi
import ida_idp
import ida_kernwin
import ida_funcs

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

HOTKEY_ONE = "Ctrl-Shift-S"
HOTKEY_ALL = "Ctrl-Shift-A"   # NOT Ctrl-F5: the Hex-Rays MIPS decompiler owns that

_views = []
_hotkeys = []


def _is_allegrex():
    try:
        n = ida_idp.get_idp_name().lower()
    except Exception:
        return False
    return "mips" in n or n in ("psp", "allegrex", "r5900", "r3900")


def _run_one():
    from allegrexdec import ida_bridge, view
    if not _is_allegrex():
        ida_kernwin.warning("allegrexdec: this database is not MIPS/Allegrex.\n"
                            "Open the PSP ELF/PRX with the MIPS processor (prxldr).")
        return
    ea = ida_kernwin.get_screen_ea()
    if ida_funcs.get_func(ea) is None:
        ida_kernwin.warning("allegrexdec: no function at 0x%X. Press 'P' to create one." % ea)
        return
    try:
        fn = ida_bridge.decompile_one(ea)
    except Exception:
        ida_kernwin.warning("allegrexdec failed:\n\n%s" % traceback.format_exc())
        return
    v = view.show(fn)
    if v is not None:
        _views.append(v)
    print("allegrexdec: %s -> %d blocks" % (fn.name, len(fn.cfg.blocks)))


def _run_all():
    from allegrexdec import ida_bridge, view
    import ida_nalt
    if not _is_allegrex():
        ida_kernwin.warning("allegrexdec: this database is not MIPS/Allegrex.")
        return
    ida_kernwin.show_wait_box("allegrexdec: decompiling all functions...")
    t0 = time.time()
    try:
        prog = ida_bridge.decompile_program()
    except Exception:
        ida_kernwin.hide_wait_box()
        ida_kernwin.warning("allegrexdec: decompile all failed:\n\n%s" % traceback.format_exc())
        return
    finally:
        try:
            ida_kernwin.hide_wait_box()
        except Exception:
            pass
    lines = prog.listing().splitlines()
    print("allegrexdec: %d functions in %.1fs" % (len(prog.funcs), time.time() - t0))

    default = os.path.splitext(ida_nalt.get_input_file_path() or "allegrex")[0] + ".c"
    path = ida_kernwin.ask_file(True, default, "Save the decompiled listing")
    if path:
        try:
            with open(path, "w", encoding="utf-8") as fp:
                fp.write("\n".join(lines) + "\n")
            print("allegrexdec: wrote %d lines to %s" % (len(lines), path))
        except Exception as exc:
            ida_kernwin.warning("allegrexdec: could not write %s:\n%s" % (path, exc))
    v = view.show_listing("allegrexdec - all functions", lines)
    if v is not None:
        _views.append(v)


class AllegrexDecPlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "Sony PSP Allegrex (MIPS + VFPU) decompiler: lifter + structuring + pseudo-C"
    help = "%s decompiles the current function, %s decompiles everything." % (HOTKEY_ONE, HOTKEY_ALL)
    wanted_name = "Allegrex decompiler (allegrexdec)"
    wanted_hotkey = HOTKEY_ONE

    def init(self):
        if not _is_allegrex():
            return ida_idaapi.PLUGIN_SKIP
        ctx = ida_kernwin.add_hotkey(HOTKEY_ALL, _run_all)
        if ctx is not None:
            _hotkeys.append(ctx)
        print("allegrexdec: loaded -- %s = this function, %s = decompile all"
              % (HOTKEY_ONE, HOTKEY_ALL))
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        _run_one()

    def term(self):
        for ctx in _hotkeys:
            try:
                ida_kernwin.del_hotkey(ctx)
            except Exception:
                pass
        del _hotkeys[:]
        del _views[:]


def PLUGIN_ENTRY():
    return AllegrexDecPlugin()
