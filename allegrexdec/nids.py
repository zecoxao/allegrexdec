"""
PSP NID -> name resolution for the headless loader (so a standalone listing shows
``sceUmdManInit`` instead of ``sub_8804070``), mirroring zecoxao's ``prxldr``.

A ``psplibdoc.xml`` maps every library's export/import NIDs to names.  We search
the usual spots for one (an explicit path, ``$ALLEGREXDEC_PSPLIBDOC``, the
directory of the input file, the current directory, and ``$IDADIR``'s
loaders/cfg) and parse it into ``{library: {nid: name}}``.  Inside IDA this is
unnecessary -- the plugin reuses IDA's own names.
"""

import os
import re

_CACHE = {}


def _search_paths(input_path=None, explicit=None):
    cands = []
    if explicit:
        cands.append(explicit)
    env = os.environ.get("ALLEGREXDEC_PSPLIBDOC") or os.environ.get("PSPLIBDOC")
    if env:
        cands.append(env)
    if input_path:
        cands.append(os.path.join(os.path.dirname(os.path.abspath(input_path)),
                                  "psplibdoc.xml"))
    cands.append(os.path.join(os.getcwd(), "psplibdoc.xml"))
    idadir = os.environ.get("IDADIR")
    if idadir:
        cands.append(os.path.join(idadir, "loaders", "psplibdoc.xml"))
        cands.append(os.path.join(idadir, "cfg", "psplibdoc.xml"))
    seen, out = set(), []
    for c in cands:
        c = os.path.normpath(c)
        if c not in seen and os.path.isfile(c):
            seen.add(c)
            out.append(c)
    return out


def parse_psplibdoc(path):
    """psplibdoc.xml -> {libname: {nid: name}} (same shape as prxldr)."""
    libs = {}
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(path)
        for lib in tree.iter("LIBRARY"):
            name_el = lib.find("NAME")
            if name_el is None or not name_el.text:
                continue
            entries = libs.setdefault(name_el.text.strip(), {})
            for group in ("FUNCTION", "VARIABLE"):
                for fn in lib.iter(group):
                    nid_el, nm_el = fn.find("NID"), fn.find("NAME")
                    if nid_el is None or nm_el is None or not nid_el.text or not nm_el.text:
                        continue
                    try:
                        entries[int(nid_el.text.strip(), 16)] = nm_el.text.strip()
                    except ValueError:
                        pass
        if libs:
            return libs
    except Exception:
        pass
    # flat-scan fallback for truncated / hand-edited files
    try:
        data = open(path, "rb").read().decode("latin-1")
    except IOError:
        return {}
    for chunk in data.split("<LIBRARY>")[1:]:
        m = re.search(r"<NAME>(.*?)</NAME>", chunk, re.S)
        if not m:
            continue
        entries = libs.setdefault(m.group(1).strip(), {})
        for nid, nm in re.findall(r"<NID>(.*?)</NID>\s*<NAME>(.*?)</NAME>", chunk, re.S):
            try:
                entries[int(nid.strip(), 16)] = nm.strip()
            except ValueError:
                pass
    return libs


def load(input_path=None, explicit=None):
    """Return a {library: {nid: name}} database, or {} if no psplibdoc found."""
    for p in _search_paths(input_path, explicit):
        if p not in _CACHE:
            _CACHE[p] = parse_psplibdoc(p)
        if _CACHE[p]:
            return _CACHE[p]
    return {}


def lookup(db, libname, nid):
    lib = db.get(libname)
    if lib and nid in lib:
        return lib[nid]
    # some psplibdoc variants don't split by library name reliably; fall back to
    # a global search so a known NID still resolves.
    for entries in db.values():
        if nid in entries:
            return entries[nid]
    return None
