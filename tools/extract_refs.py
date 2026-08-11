"""Extract [Guid(...)] + method order for each interface from MScholtes-style C# refs.

Produces a compact per-file interface/vtable summary used to cross-reference IIDs
and vtable slot numbers across Windows builds.
"""

import pathlib
import re
import sys

REF = pathlib.Path(__file__).resolve().parent.parent / "research" / "ref"

GUID_RE = re.compile(r'\[Guid\("([0-9A-Fa-f\-]{36})"\)\]')
IFACE_RE = re.compile(r"^\s*internal\s+interface\s+(\w+)")

WANTED = {
    "IVirtualDesktopManagerInternal",
    "IVirtualDesktop",
    "IVirtualDesktopManager",
    "IApplicationViewCollection",
    "IVirtualDesktopPinnedApps",
    "IVirtualDesktopNotificationService",
    "IApplicationView",
}


def parse(path: pathlib.Path):
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out = []
    pending_guid = None
    i = 0
    while i < len(lines):
        m = GUID_RE.search(lines[i])
        if m:
            pending_guid = m.group(1).upper()
        m2 = IFACE_RE.match(lines[i])
        if m2:
            name = m2.group(1)
            # collect method lines until closing brace at same indent
            methods = []
            j = i + 1
            while j < len(lines) and "{" not in lines[j]:
                j += 1
            j += 1
            depth = 1
            while j < len(lines) and depth > 0:
                s = lines[j].strip()
                depth += s.count("{") - s.count("}")
                if depth <= 0:
                    break
                if s and not s.startswith("[") and not s.startswith("//") and "(" in s:
                    methods.append(s.rstrip(";"))
                j += 1
            if name in WANTED:
                out.append((name, pending_guid, methods))
            pending_guid = None
            i = j
            continue
        i += 1
    return out


def main() -> int:
    files = sorted(REF.glob("MScholtes_*.cs"))
    if not files:
        print("no reference files found", file=sys.stderr)
        return 1
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for f in files:
        print("=" * 78)
        print(f.name)
        print("=" * 78)
        for name, guid, methods in parse(f):
            if only and only.lower() not in name.lower():
                continue
            print(f"\n  {name}  IID={{{guid}}}  methods={len(methods)}")
            for k, sig in enumerate(methods):
                print(f"    slot {k + 3:2d}  {sig}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
