"""
Image loading and entry discovery for Allegrex binaries, adapted from zecoxao's
``prxldr`` PSP PRX loader (same ELF/PRX structures and the same module-info
export walk) so the headless CLI finds the same entry points IDA would.

PSP executables and PRX modules are little-endian 32-bit MIPS ELFs
(``ET_EXEC``/``ET_SCE`` or the PRX type ``ET_PRX = 0xFFA0``).  Every ``PT_LOAD``
segment is mapped into one flat 32-bit image at the lowest virtual address; the
decoder is then seeded with the ELF entry point, every function exported through
``.rodata.sceModuleInfo`` (as ``prxldr`` names them), and every ``STT_FUNC``
symbol.  A file that is not such an ELF is treated as a raw code blob based at 0.
"""

import struct

ELF_MAGIC = 0x464C457F
EI_CLASS, EI_DATA = 4, 5
ELFCLASS32, ELFDATA2LSB, EM_MIPS = 1, 1, 8
ET_PRX = 0xFFA0
PT_LOAD = 1
SHT_SYMTAB = 2
STT_FUNC = 2
PSP_MODULE_INFO_NAME = ".rodata.sceModuleInfo"

EHDR = struct.Struct("<16sHHIIIIIHHHHHH")   # 52
SHDR = struct.Struct("<10I")                # 40
PHDR = struct.Struct("<8I")                 # 32
MODINFO = struct.Struct("<I28s5I")          # 52


def load(path):
    with open(path, "rb") as fp:
        return bytearray(fp.read())


def _is_elf32le_mips(data):
    if len(data) < EHDR.size or data[:4] != b"\x7fELF":
        return False
    return data[EI_CLASS] == ELFCLASS32 and data[EI_DATA] == ELFDATA2LSB


class _Elf(object):
    def __init__(self, data):
        self.buf = data
        f = EHDR.unpack_from(data, 0)
        (self.e_ident, self.e_type, self.e_machine, self.e_version, self.e_entry,
         self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
         self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
         self.e_shstrndx) = f
        self.phdr = []
        for i in range(self.e_phnum):
            o = self.e_phoff + i * self.e_phentsize
            if o + PHDR.size > len(data):
                break
            g = PHDR.unpack_from(data, o)
            self.phdr.append(dict(p_type=g[0], p_offset=g[1], p_vaddr=g[2],
                                  p_paddr=g[3], p_filesz=g[4], p_memsz=g[5],
                                  p_flags=g[6], p_align=g[7]))
        self.shdr = []
        for i in range(self.e_shnum):
            o = self.e_shoff + i * self.e_shentsize
            if o + SHDR.size > len(data):
                break
            g = SHDR.unpack_from(data, o)
            self.shdr.append(dict(sh_name=g[0], sh_type=g[1], sh_flags=g[2],
                                  sh_addr=g[3], sh_offset=g[4], sh_size=g[5],
                                  sh_link=g[6], sh_info=g[7], sh_addralign=g[8],
                                  sh_entsize=g[9]))
        self._shstr = b""
        if 0 <= self.e_shstrndx < len(self.shdr):
            s = self.shdr[self.e_shstrndx]
            self._shstr = data[s["sh_offset"]:s["sh_offset"] + s["sh_size"]]

    def secname(self, sh):
        o = sh["sh_name"]
        end = self._shstr.find(b"\x00", o)
        return self._shstr[o:end if end >= 0 else None].decode("latin-1") if o < len(self._shstr) else ""


def _u32(image, base, va):
    o = va - base
    if o < 0 or o + 4 > len(image):
        return None
    return image[o] | (image[o + 1] << 8) | (image[o + 2] << 16) | (image[o + 3] << 24)


def _flat_image(elf):
    loads = [p for p in elf.phdr if p["p_type"] == PT_LOAD and p["p_memsz"] > 0]
    if not loads:
        return None, 0
    base = min(p["p_vaddr"] for p in loads)
    end = max(p["p_vaddr"] + p["p_memsz"] for p in loads)
    image = bytearray(end - base)
    for p in loads:
        chunk = elf.buf[p["p_offset"]:p["p_offset"] + p["p_filesz"]]
        at = p["p_vaddr"] - base
        image[at:at + len(chunk)] = chunk
    return image, base


def _cstr(image, base, va):
    o = va - base
    if o < 0 or o >= len(image):
        return ""
    end = image.find(b"\x00", o)
    return image[o:end if end >= 0 else len(image)].decode("latin-1", "replace")


def _module_info(elf):
    file_off = None
    for sh in elf.shdr:
        if elf.secname(sh) == PSP_MODULE_INFO_NAME and sh["sh_size"] >= MODINFO.size:
            file_off = sh["sh_offset"]
            break
    if file_off is None and elf.phdr:
        file_off = elf.phdr[0]["p_paddr"] & 0x0FFFFFFF
    if file_off is None or file_off + MODINFO.size > len(elf.buf):
        return None
    return MODINFO.unpack_from(elf.buf, file_off)


def _module_exports(elf, image, base, db=None, names=None):
    """Function entry points from .rodata.sceModuleInfo (prxldr's export walk);
    when a NID database is given, also fills ``names`` with {target: name}."""
    entries = []
    mi = _module_info(elf)
    if mi is None:
        return entries
    flags, name, gp, exports, exp_end, imports, imp_end = mi
    if not exports or not exp_end or exp_end <= exports:
        return entries
    exp_base = exports
    guard = 0
    while exp_end - exp_base >= 16 and guard < 4096:
        guard += 1
        stub = []
        for k in range(4):
            v = _u32(image, base, exp_base + 4 * k)
            if v is None:
                return entries
            stub.append(v)
        name_ptr, eflags, counts, exp_tbl = stub
        entsize = counts & 0xFF
        v_count = (counts >> 8) & 0xFF
        f_count = (counts >> 16) & 0xFFFF
        total = v_count + f_count
        libname = _cstr(image, base, name_ptr) if name_ptr else "syslib"
        for i in range(f_count):
            nid = _u32(image, base, exp_tbl + 4 * i)
            target = _u32(image, base, exp_tbl + 4 * total + 4 * i)
            if target is not None and base <= target < base + len(image):
                target &= ~1
                entries.append(target)
                if names is not None and db and nid is not None:
                    from . import nids as _nids
                    nm = _nids.lookup(db, libname, nid)
                    if nm:
                        names[target] = nm
        if entsize <= 0:
            break
        exp_base += entsize * 4
    return entries


def _module_imports(elf, image, base, db, names):
    """Name imported-function stub addresses (call targets) via their NID."""
    mi = _module_info(elf)
    if mi is None or not db:
        return
    flags, name, gp, exports, exp_end, imports, imp_end = mi
    if not imports or not imp_end or imp_end <= imports:
        return
    from . import nids as _nids
    imp_base = imports
    guard = 0
    while imp_end - imp_base >= 20 and guard < 4096:
        guard += 1
        stub = []
        for k in range(6):
            v = _u32(image, base, imp_base + 4 * k)
            stub.append(v if v is not None else 0)
        name_ptr, iflags, counts, nid_tbl, func_tbl, var_tbl = stub
        entsize = counts & 0xFF
        v_count = (counts >> 8) & 0xFF
        f_count = (counts >> 16) & 0xFFFF
        libname = _cstr(image, base, name_ptr) if name_ptr else ""
        for i in range(f_count):
            nid = _u32(image, base, nid_tbl + 4 * i)
            stub_ea = func_tbl + 8 * i          # 8-byte jr/jump stub per import
            if nid is not None and base <= stub_ea < base + len(image):
                nm = _nids.lookup(db, libname, nid)
                if nm:
                    names[stub_ea & ~1] = nm
        if entsize <= 0:
            break
        imp_base += entsize * 4


def _symbols(elf, base, end):
    entries = []
    for sh in elf.shdr:
        if sh["sh_type"] != SHT_SYMTAB:
            continue
        entsize = sh["sh_entsize"] or 16
        n = sh["sh_size"] // entsize
        for s in range(n):
            so = sh["sh_offset"] + s * entsize
            if so + 16 > len(elf.buf):
                break
            st_value = struct.unpack_from("<I", elf.buf, so + 4)[0]
            st_info = elf.buf[so + 12]
            if (st_info & 0xF) == STT_FUNC and base <= st_value < end:
                entries.append(st_value & ~1)
    return entries


def load_program(path, psplibdoc=None):
    """Return (image, base, entries, code_names) for *path*.

    code_names maps address -> name for module exports and import stubs, resolved
    through a psplibdoc.xml NID database when one can be found."""
    data = load(path)
    if _is_elf32le_mips(data):
        try:
            elf = _Elf(data)
        except struct.error:
            elf = None
        if elf is not None:
            image, base = _flat_image(elf)
            if image is not None:
                from . import nids as _nids
                db = _nids.load(input_path=path, explicit=psplibdoc)
                names = {}
                end = base + len(image)
                entries = []
                if base <= elf.e_entry < end:
                    entries.append(elf.e_entry & ~1)
                    names.setdefault(elf.e_entry & ~1, "module_start")
                entries += _module_exports(elf, image, base, db=db, names=names)
                _module_imports(elf, image, base, db, names)
                entries += _symbols(elf, base, end)
                entries = sorted(set(entries))
                if not entries:
                    entries = [base]
                return image, base, entries, names
    return data, 0, [0], {}


# kept for API parity with the other tools
def detect_base(image):
    return 0, 0
