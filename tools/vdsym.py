"""vdsym.py - obtain ground truth about the running build's virtual desktop
implementation directly from Microsoft's public symbols.

No DIA / dbghelp / Visual Studio required: this reads the PE debug directory to
derive the symbol-server path, downloads the PDB, and parses the MSF container
and CodeView public symbol records itself.

Subcommands
    pdbid   <pe>                 print PDB name / GUID / age / symbol server URL
    fetch   <pe>                 download the matching PDB into research/symbols
    syms    <pdb> [regex]        list public symbols, optionally filtered
    vtable  <pe> <pdb> <class>   dump a C++ vftable slot-by-slot with names
    report  <pe> <pdb>           the per-monitor findings this project needs

Only public symbols exist in Microsoft's shipped PDBs, which is exactly what is
needed here: function names and addresses.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import struct
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
SYMDIR = ROOT / "research" / "symbols"

# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------

IMAGE_DEBUG_TYPE_CODEVIEW = 2


class Section:
    __slots__ = ("name", "vaddr", "vsize", "raw_ptr", "raw_size", "flags")

    def __init__(self, name, vaddr, vsize, raw_ptr, raw_size, flags):
        self.name = name
        self.vaddr = vaddr
        self.vsize = vsize
        self.raw_ptr = raw_ptr
        self.raw_size = raw_size
        self.flags = flags

    @property
    def executable(self) -> bool:
        return bool(self.flags & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE

    def __repr__(self):
        return f"<{self.name} rva=0x{self.vaddr:x} size=0x{self.vsize:x}>"


class PE:
    def __init__(self, path: pathlib.Path):
        self.path = path
        self.data = path.read_bytes()
        d = self.data
        if d[:2] != b"MZ":
            raise ValueError(f"{path}: not a PE file")
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if d[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            raise ValueError(f"{path}: bad PE signature")
        coff = e_lfanew + 4
        (self.machine, num_sections, _ts, _sp, _ns, size_opt, _chars) = struct.unpack_from(
            "<HHIIIHH", d, coff
        )
        opt = coff + 20
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic == 0x20B:  # PE32+
            self.image_base = struct.unpack_from("<Q", d, opt + 24)[0]
            dd = opt + 112
        elif magic == 0x10B:
            self.image_base = struct.unpack_from("<I", d, opt + 28)[0]
            dd = opt + 96
        else:
            raise ValueError(f"{path}: unknown optional header magic 0x{magic:x}")
        self.num_dirs = struct.unpack_from("<I", d, dd - 4)[0]
        self.dirs = [
            struct.unpack_from("<II", d, dd + 8 * i) for i in range(self.num_dirs)
        ]
        sec_off = opt + size_opt
        self.sections = []
        for i in range(num_sections):
            o = sec_off + 40 * i
            raw = struct.unpack_from("<8sIIIIIIHHI", d, o)
            self.sections.append(
                Section(
                    raw[0].rstrip(b"\0").decode("ascii", "replace"),
                    raw[2],
                    raw[1],
                    raw[4],
                    raw[3],
                    raw[9],
                )
            )

    def section_of_rva(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size):
                return s
        return None

    def read_rva(self, rva: int, size: int) -> bytes | None:
        s = self.section_of_rva(rva)
        if s is None:
            return None
        off = s.raw_ptr + (rva - s.vaddr)
        if off + size > len(self.data):
            return None
        return self.data[off : off + size]

    def codeview(self) -> tuple[str, str, int] | None:
        """Returns (pdb_basename, guid_hex32, age)."""
        if len(self.dirs) <= 6:
            return None
        rva, size = self.dirs[6]
        if rva == 0 or size == 0:
            return None
        blob = self.read_rva(rva, size)
        if blob is None:
            return None
        for i in range(0, size, 28):
            if i + 28 > len(blob):
                break
            (_c, _t, _mj, _mn, dtype, dsize, daddr, dptr) = struct.unpack_from(
                "<IIHHIIII", blob, i
            )
            if dtype != IMAGE_DEBUG_TYPE_CODEVIEW:
                continue
            cv = self.data[dptr : dptr + dsize] if dptr else self.read_rva(daddr, dsize)
            if not cv or cv[:4] != b"RSDS":
                continue
            g = cv[4:20]
            d1, d2, d3 = struct.unpack_from("<IHH", g, 0)
            guid = f"{d1:08X}{d2:04X}{d3:04X}" + g[8:16].hex().upper()
            age = struct.unpack_from("<I", cv, 20)[0]
            name = cv[24:].split(b"\0")[0].decode("utf-8", "replace")
            return (pathlib.PurePath(name.replace("\\", "/")).name, guid, age)
        return None


def symbol_url(pdb: str, guid: str, age: int) -> str:
    return f"https://msdl.microsoft.com/download/symbols/{pdb}/{guid}{age:X}/{pdb}"


# ---------------------------------------------------------------------------
# MSF / PDB
# ---------------------------------------------------------------------------

MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"

S_PUB32 = 0x110E
S_GPROC32 = 0x1110
S_LPROC32 = 0x110F


class PDB:
    def __init__(self, path: pathlib.Path):
        self.path = path
        d = path.read_bytes()
        self.data = d
        if d[:32] != MSF_MAGIC:
            raise ValueError(f"{path}: not an MSF 7.00 container")
        (self.block_size, _free, self.num_blocks, dir_bytes, _unk,
         block_map_addr) = struct.unpack_from("<IIIIII", d, 32)

        n_dir_blocks = self._ceil(dir_bytes, self.block_size)
        map_off = block_map_addr * self.block_size
        dir_blocks = struct.unpack_from(f"<{n_dir_blocks}I", d, map_off)
        directory = self._read_blocks(dir_blocks, dir_bytes)

        pos = 0
        (num_streams,) = struct.unpack_from("<I", directory, pos)
        pos += 4
        sizes = list(struct.unpack_from(f"<{num_streams}I", directory, pos))
        pos += 4 * num_streams
        self.streams: list[bytes] = []
        for size in sizes:
            if size == 0xFFFFFFFF:  # deleted stream
                self.streams.append(b"")
                continue
            nb = self._ceil(size, self.block_size)
            blocks = struct.unpack_from(f"<{nb}I", directory, pos)
            pos += 4 * nb
            self.streams.append(self._read_blocks(blocks, size))

    @staticmethod
    def _ceil(a: int, b: int) -> int:
        return (a + b - 1) // b

    def _read_blocks(self, blocks, total: int) -> bytes:
        out = bytearray()
        for b in blocks:
            off = b * self.block_size
            out += self.data[off : off + self.block_size]
        return bytes(out[:total])

    # -- DBI ---------------------------------------------------------------

    def dbi_header(self):
        dbi = self.streams[3] if len(self.streams) > 3 else b""
        if len(dbi) < 64:
            return None
        f = struct.unpack_from("<iIIHHHHHHiiiiiIiiHHI", dbi, 0)
        return {
            "sig": f[0],
            "version": f[1],
            "age": f[2],
            "global_stream": f[3],
            "build": f[4],
            "public_stream": f[5],
            "pdb_dll_ver": f[6],
            "sym_record_stream": f[7],
            "mod_info_size": f[9],
            "sec_contrib_size": f[10],
            "sec_map_size": f[11],
            "src_info_size": f[12],
            "type_server_size": f[13],
            "opt_dbg_header_size": f[15],
            "ec_size": f[16],
            "flags": f[17],
            "machine": f[18],
        }

    def public_symbols(self):
        """Yields (name, segment, offset) for every S_PUB32 record."""
        h = self.dbi_header()
        if h is None:
            return
        idx = h["sym_record_stream"]
        if idx == 0xFFFF or idx >= len(self.streams):
            return
        s = self.streams[idx]
        pos = 0
        n = len(s)
        while pos + 4 <= n:
            (rec_len, kind) = struct.unpack_from("<HH", s, pos)
            if rec_len < 2:
                break
            body = s[pos + 4 : pos + 2 + rec_len]
            if kind == S_PUB32 and len(body) >= 10:
                (_flags, offset, seg) = struct.unpack_from("<IIH", body, 0)
                name = body[10:].split(b"\0")[0].decode("utf-8", "replace")
                yield (name, seg, offset)
            pos += 2 + rec_len
            if rec_len % 4:  # records are 4-byte aligned
                pass
        return

    def _opt_dbg_streams(self) -> list[int]:
        """The DbgHeader stream-index array at the end of the DBI stream.

        Index meanings (LLVM DbgHeaderType): 0 FPO, 1 Exception, 2 Fixup,
        3 OmapToSrc, 4 OmapFromSrc, 5 SectionHdr, 6 TokenRidMap, 7 Xdata,
        8 Pdata, 9 NewFPO, 10 SectionHdrOrig.
        """
        h = self.dbi_header()
        if h is None or h["opt_dbg_header_size"] <= 0:
            return []
        dbi = self.streams[3]
        off = (
            64
            + h["mod_info_size"]
            + h["sec_contrib_size"]
            + h["sec_map_size"]
            + h["src_info_size"]
            + h["type_server_size"]
            + h["ec_size"]
        )
        count = h["opt_dbg_header_size"] // 2
        try:
            return list(struct.unpack_from(f"<{count}H", dbi, off))
        except struct.error:
            return []

    def _stream(self, idx: int) -> bytes:
        if idx == 0xFFFF or idx >= len(self.streams):
            return b""
        return self.streams[idx]

    def _omap(self, which: int) -> list[tuple[int, int]]:
        ids = self._opt_dbg_streams()
        if len(ids) <= which:
            return []
        raw = self._stream(ids[which])
        n = len(raw) // 8
        if n == 0:
            return []
        flat = struct.unpack_from(f"<{2 * n}I", raw, 0)
        return [(flat[2 * i], flat[2 * i + 1]) for i in range(n)]

    def omap_from_src(self) -> list[tuple[int, int]]:
        return self._omap(4)

    def omap_to_src(self) -> list[tuple[int, int]]:
        return self._omap(3)

    def original_sections(self) -> list[Section]:
        """Section headers of the pre-BBT layout, when the PDB carries them."""
        ids = self._opt_dbg_streams()
        for which in (10, 5):  # SectionHdrOrig, then SectionHdr
            if len(ids) <= which:
                continue
            raw = self._stream(ids[which])
            if not raw or len(raw) % 40:
                continue
            out = []
            for i in range(len(raw) // 40):
                f = struct.unpack_from("<8sIIIIIIHHI", raw, 40 * i)
                out.append(
                    Section(
                        f[0].rstrip(b"\0").decode("ascii", "replace"),
                        f[2], f[1], f[4], f[3], f[9],
                    )
                )
            if out:
                return out
        return []

    def has_omap(self) -> bool:
        """OMAP means addresses were reordered and need translation."""
        return bool(self.omap_from_src()) or bool(self.omap_to_src())


def omap_translate(omap: list[tuple[int, int]], rva: int) -> int:
    """Standard OMAP lookup: last entry with rva <= x, then add the delta."""
    if not omap:
        return rva
    lo, hi = 0, len(omap) - 1
    best = -1
    while lo <= hi:
        mid = (lo + hi) // 2
        if omap[mid][0] <= rva:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    if best < 0:
        return 0
    src, dst = omap[best]
    if dst == 0:
        return 0  # the range was discarded by the optimiser
    return dst + (rva - src)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class SymbolMap:
    """Maps between PDB symbol space and the final image, handling OMAP.

    Windows system binaries are shipped BBT-reordered: the PDB records symbol
    addresses against the *original* section layout, and OMAP tables describe the
    permutation.  Without applying them, every address is wrong, so the mapping
    is built explicitly rather than assumed to be identity.
    """

    def __init__(self, pe: PE, pdb: PDB):
        self.pe = pe
        self.pdb = pdb
        self.from_src = pdb.omap_from_src()
        self.to_src = pdb.omap_to_src()
        self.src_sections = pdb.original_sections() or pe.sections
        self.by_rva: dict[int, list[str]] = {}
        self.count = 0
        for name, seg, off in pdb.public_symbols():
            if seg == 0 or seg > len(self.src_sections):
                continue
            src_rva = self.src_sections[seg - 1].vaddr + off
            rva = omap_translate(self.from_src, src_rva) if self.from_src else src_rva
            if rva == 0:
                continue
            self.by_rva.setdefault(rva, []).append(name)
            self.count += 1

    def names_at(self, image_rva: int) -> list[str]:
        return self.by_rva.get(image_rva, [])

    def describe(self) -> str:
        return (
            f"symbols={self.count} omap_from_src={len(self.from_src)} "
            f"omap_to_src={len(self.to_src)} "
            f"orig_sections={len(self.src_sections)}"
        )


def undecorate(name: str) -> str:
    """Just enough MSVC demangling to read a vtable dump.

    ?Method@Class@@... -> Class::Method
    """
    m = re.match(r"^\?\??([A-Za-z0-9_]+)@([A-Za-z0-9_]+)@@", name)
    if m:
        return f"{m.group(2)}::{m.group(1)}"
    m = re.match(r"^\?\??([A-Za-z0-9_]+)@([A-Za-z0-9_]+)@([A-Za-z0-9_]+)@@", name)
    if m:
        return f"{m.group(3)}::{m.group(2)}::{m.group(1)}"
    return name


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------


def cmd_pdbid(args) -> int:
    pe = PE(pathlib.Path(args.pe))
    cv = pe.codeview()
    if cv is None:
        print("no CodeView debug record", file=sys.stderr)
        return 1
    pdb, guid, age = cv
    print(f"pe        : {pe.path}")
    print(f"image base: 0x{pe.image_base:x}")
    print(f"pdb       : {pdb}")
    print(f"guid      : {guid}")
    print(f"age       : {age}")
    print(f"url       : {symbol_url(pdb, guid, age)}")
    for s in pe.sections:
        print(f"  section {s.name:<8} rva=0x{s.vaddr:08x} vsize=0x{s.vsize:08x} exec={s.executable}")
    return 0


def cmd_fetch(args) -> int:
    pe = PE(pathlib.Path(args.pe))
    cv = pe.codeview()
    if cv is None:
        print("no CodeView debug record", file=sys.stderr)
        return 1
    pdb, guid, age = cv
    SYMDIR.mkdir(parents=True, exist_ok=True)
    out = SYMDIR / f"{pathlib.Path(pdb).stem}-{guid}{age:X}.pdb"
    if out.exists():
        print(f"cached {out} ({out.stat().st_size} bytes)")
        return 0
    url = symbol_url(pdb, guid, age)
    print(f"GET {url}")
    req = urllib.request.Request(
        url, headers={"User-Agent": "Microsoft-Symbol-Server/10.0.0.0"}
    )
    with urllib.request.urlopen(req, timeout=180) as r, open(out, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
    print(f"saved {out} ({out.stat().st_size} bytes)")
    return 0


def cmd_syms(args) -> int:
    pdb = PDB(pathlib.Path(args.pdb))
    h = pdb.dbi_header()
    print(f"# streams={len(pdb.streams)} block_size={pdb.block_size}")
    if h:
        print(f"# dbi age={h['age']} machine=0x{h['machine']:x} "
              f"sym_record_stream={h['sym_record_stream']} omap={pdb.has_omap()}")
    rx = re.compile(args.regex, re.IGNORECASE) if args.regex else None
    n = 0
    for name, seg, off in pdb.public_symbols():
        if rx and not rx.search(name):
            continue
        n += 1
        print(f"seg={seg:<3} off=0x{off:08x}  {name}")
        if args.limit and n >= args.limit:
            print("... (limit reached)")
            break
    print(f"# {n} matching public symbols")
    return 0


def cmd_vtable(args) -> int:
    pe = PE(pathlib.Path(args.pe))
    pdb = PDB(pathlib.Path(args.pdb))
    smap = SymbolMap(pe, pdb)
    print(f"# {smap.describe()}")

    # MSVC mangles a vftable as ??_7<Class>@@6B<Base>@.  `cls` is treated as a
    # regex over the whole mangled name so a specific base can be selected.
    want = re.compile(args.cls)
    hits = [
        (rva, nm)
        for rva, names in smap.by_rva.items()
        for nm in names
        if nm.startswith("??_7") and want.search(nm)
    ]
    if not hits:
        print(f"no vftable symbol matching {args.cls!r}", file=sys.stderr)
        return 1

    for rva, sym in sorted(hits):
        sec = pe.section_of_rva(rva)
        print(f"\n== {sym}")
        print(f"   vftable rva 0x{rva:08x} in {sec.name if sec else '?'}")
        for slot in range(args.max_slots):
            raw = pe.read_rva(rva + 8 * slot, 8)
            if raw is None:
                print(f"   slot {slot:>3}: <unreadable> - stop")
                break
            va = struct.unpack("<Q", raw)[0]
            if va == 0:
                print(f"   slot {slot:>3}: (null) - end of vtable")
                break
            target = va - pe.image_base
            tsec = pe.section_of_rva(target)
            if tsec is None or not tsec.executable:
                print(f"   slot {slot:>3}: 0x{target:08x} not in a code section "
                      f"-> end of vtable")
                break
            names = smap.names_at(target)
            label = undecorate(names[0]) if names else "(no public symbol)"
            print(f"   slot {slot:>3}: 0x{target:08x}  {label}")
            if names and args.mangled:
                for nm in names:
                    print(f"              {nm}")
    return 0


PER_MONITOR_PATTERNS = [
    r"GetDesktopIsPerMonitor",
    r"SetDesktopIsPerMonitor",
    r"IsPerMonitor",
    r"PerMonitorDesktop",
    r"DesktopPerMonitor",
]

MONITOR_API_PATTERNS = [
    r"CVirtualDesktopManagerInternal",
    r"CVirtualDesktop(?!Manager)",
    r"VirtualDesktopManagerInternal",
]


def cmd_report(args) -> int:
    pe = PE(pathlib.Path(args.pe))
    pdb = PDB(pathlib.Path(args.pdb))
    syms = list(pdb.public_symbols())
    names = [s[0] for s in syms]
    print(f"module        : {pe.path.name}")
    print(f"pdb           : {pathlib.Path(args.pdb).name}")
    print(f"public symbols: {len(names)}")
    print(f"OMAP present  : {pdb.has_omap()}")

    print("\n-- per-monitor virtual desktop symbols --")
    found_any = False
    for pat in PER_MONITOR_PATTERNS:
        rx = re.compile(pat, re.IGNORECASE)
        hits = sorted({n for n in names if rx.search(n)})
        print(f"  {pat:<26} : {len(hits)} hit(s)")
        for h in hits[:40]:
            found_any = True
            print(f"      {undecorate(h)}   [{h}]")
    if not found_any:
        print("  => NO per-monitor virtual desktop symbol of any spelling is present")

    print("\n-- virtual desktop implementation classes --")
    for pat in MONITOR_API_PATTERNS:
        rx = re.compile(pat)
        hits = sorted({n for n in names if rx.search(n)})
        print(f"  {pat:<34} : {len(hits)} hit(s)")

    print("\n-- CVirtualDesktopManagerInternal members --")
    rx = re.compile(r"CVirtualDesktopManagerInternal")
    members = sorted({undecorate(n) for n in names if rx.search(n)})
    for m in members:
        print(f"  {m}")

    print("\n-- HMONITOR-related desktop symbols --")
    rx = re.compile(r"(Monitor).*(Desktop)|(Desktop).*(Monitor)", re.IGNORECASE)
    hits = sorted({undecorate(n) for n in names if rx.search(n)})
    for h in hits[:80]:
        print(f"  {h}")
    print(f"  ({len(hits)} total)")
    return 0


def parse_guid(text: str) -> bytes:
    """{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} -> 16 raw bytes as stored in a PE."""
    t = text.strip().strip("{}").replace("-", "")
    if len(t) != 32:
        raise ValueError(f"not a GUID: {text}")
    b = bytes.fromhex(t)
    return (
        struct.pack("<I", int.from_bytes(b[0:4], "big"))
        + struct.pack("<H", int.from_bytes(b[4:6], "big"))
        + struct.pack("<H", int.from_bytes(b[6:8], "big"))
        + b[8:16]
    )


def format_guid(raw: bytes) -> str:
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    tail = raw[8:16].hex().upper()
    return f"{{{d1:08X}-{d2:04X}-{d3:04X}-{tail[0:4]}-{tail[4:16]}}}"


def cmd_guid(args) -> int:
    """Read the GUID stored at each matching data symbol."""
    pe = PE(pathlib.Path(args.pe))
    pdb = PDB(pathlib.Path(args.pdb))
    smap = SymbolMap(pe, pdb)
    rx = re.compile(args.regex)
    hits = sorted(
        (rva, nm) for rva, names in smap.by_rva.items() for nm in names if rx.search(nm)
    )
    if not hits:
        print("no matching symbol", file=sys.stderr)
        return 1
    for rva, nm in hits:
        raw = pe.read_rva(rva, 16)
        if raw is None or len(raw) < 16:
            print(f"  {nm:<52} <unreadable at 0x{rva:08x}>")
            continue
        print(f"  {nm:<52} {format_guid(raw)}   (rva 0x{rva:08x})")
    return 0


def cmd_findguid(args) -> int:
    """Search a PE image for the raw bytes of a GUID.

    Used to answer 'is this interface revision still present in the binary at
    all, even as dead code?'.  Absence of the bytes is strong evidence that the
    revision was removed rather than merely unregistered.
    """
    needle = parse_guid(args.guid)
    total = 0
    for spec in args.pe:
        p = pathlib.Path(spec)
        if not p.exists():
            print(f"  {p.name:<34} (file not found)")
            continue
        try:
            pe = PE(p)
        except ValueError as e:
            print(f"  {p.name:<34} ({e})")
            continue
        found = []
        start = 0
        data = pe.data
        while True:
            i = data.find(needle, start)
            if i < 0:
                break
            sec = None
            for s in pe.sections:
                if s.raw_ptr <= i < s.raw_ptr + s.raw_size:
                    sec = s
                    break
            rva = (sec.vaddr + (i - sec.raw_ptr)) if sec else None
            found.append((i, sec.name if sec else "?", rva))
            start = i + 1
        total += len(found)
        if found:
            print(f"  {p.name:<34} FOUND {len(found)}x")
            for off, secname, rva in found:
                rva_txt = f"rva 0x{rva:08x}" if rva is not None else "rva ?"
                print(f"      file offset 0x{off:08x}  section {secname:<8} {rva_txt}")
        else:
            print(f"  {p.name:<34} absent")
    print(f"\n  {format_guid(needle)}: {total} occurrence(s) across "
          f"{len(args.pe)} module(s)")
    return 0


def cmd_proxyinfo(args) -> int:
    """Recover the marshalled method count for an IID from a MIDL proxy DLL.

    MIDL emits, per interface:
        CInterfaceStubHeader  { const IID* piid; const void* pServerInfo;
                                unsigned long DispatchTableCount; ... }
        CInterfaceProxyVtbl   { const IID* piid; void* Vtbl[]; }
    So locating a pointer to the IID and reading the following fields yields the
    exact number of methods the RPC layer believes the interface has -- the
    contract a cross-process caller like vdprobe actually talks to.
    """
    pe = PE(pathlib.Path(args.pe))
    needle = parse_guid(args.guid)
    iid_offsets = []
    start = 0
    while True:
        i = pe.data.find(needle, start)
        if i < 0:
            break
        iid_offsets.append(i)
        start = i + 1
    if not iid_offsets:
        print(f"{format_guid(needle)} not present in {pe.path.name}")
        return 1

    for off in iid_offsets:
        sec = next((s for s in pe.sections
                    if s.raw_ptr <= off < s.raw_ptr + s.raw_size), None)
        if sec is None:
            continue
        iid_rva = sec.vaddr + (off - sec.raw_ptr)
        iid_va = pe.image_base + iid_rva
        print(f"\n{format_guid(needle)} at rva 0x{iid_rva:08x} ({sec.name})")
        ptr = struct.pack("<Q", iid_va)
        refs = []
        s2 = 0
        while True:
            j = pe.data.find(ptr, s2)
            if j < 0:
                break
            refs.append(j)
            s2 = j + 1
        print(f"  {len(refs)} pointer(s) to it")
        for j in refs:
            rsec = next((s for s in pe.sections
                         if s.raw_ptr <= j < s.raw_ptr + s.raw_size), None)
            if rsec is None:
                continue
            rrva = rsec.vaddr + (j - rsec.raw_ptr)
            # Interpret as CInterfaceStubHeader.
            blob = pe.data[j : j + 32]
            if len(blob) < 24:
                continue
            server_info = struct.unpack_from("<Q", blob, 8)[0]
            dispatch_count = struct.unpack_from("<I", blob, 16)[0]
            si_rva = server_info - pe.image_base if server_info else 0
            si_ok = server_info != 0 and pe.section_of_rva(si_rva) is not None
            plausible = si_ok and 3 <= dispatch_count <= 512
            print(f"    ref at rva 0x{rrva:08x} ({rsec.name})")
            if plausible:
                # DispatchTableCount counts every vtable entry, the three
                # IUnknown slots included, so the interface's own method count
                # is DispatchTableCount - 3.  Cross-check against a vtable dump
                # before relying on it.
                print(f"      -> CInterfaceStubHeader: pServerInfo rva 0x{si_rva:08x}, "
                      f"DispatchTableCount = {dispatch_count}"
                      f"  => {dispatch_count - 3} methods after the 3 IUnknown slots")
            else:
                # Try to read it as CInterfaceProxyVtbl instead: count the
                # leading run of pointers into executable sections.
                n = 0
                while True:
                    raw = pe.data[j + 8 + 8 * n : j + 16 + 8 * n]
                    if len(raw) < 8:
                        break
                    va = struct.unpack("<Q", raw)[0]
                    if va == 0:
                        break
                    t = pe.section_of_rva(va - pe.image_base)
                    if t is None or not t.executable:
                        break
                    n += 1
                if n:
                    print(f"      -> CInterfaceProxyVtbl: {n} code pointers "
                          f"({max(n - 3, 0)} methods after IUnknown)")
                else:
                    print("      -> not a recognisable MIDL header")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pdbid")
    p.add_argument("pe")
    p.set_defaults(fn=cmd_pdbid)

    p = sub.add_parser("fetch")
    p.add_argument("pe")
    p.set_defaults(fn=cmd_fetch)

    p = sub.add_parser("syms")
    p.add_argument("pdb")
    p.add_argument("regex", nargs="?")
    p.add_argument("--limit", type=int, default=0)
    p.set_defaults(fn=cmd_syms)

    p = sub.add_parser("vtable")
    p.add_argument("pe")
    p.add_argument("pdb")
    p.add_argument("cls")
    p.add_argument("--max-slots", type=int, default=64)
    p.add_argument("--mangled", action="store_true")
    p.set_defaults(fn=cmd_vtable)

    p = sub.add_parser("report")
    p.add_argument("pe")
    p.add_argument("pdb")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("guid")
    p.add_argument("pe")
    p.add_argument("pdb")
    p.add_argument("regex")
    p.set_defaults(fn=cmd_guid)

    p = sub.add_parser("proxyinfo")
    p.add_argument("pe")
    p.add_argument("guid")
    p.set_defaults(fn=cmd_proxyinfo)

    p = sub.add_parser("findguid")
    p.add_argument("guid")
    p.add_argument("pe", nargs="+")
    p.set_defaults(fn=cmd_findguid)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
