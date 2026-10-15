"""live_funds_diff.py -- pin down the LIVE money variable by intersection.

The game re-renders the money label only when the amount changes *in game*, so
the reliable way to find the live variable is a two-snapshot differential inside
one process:

    1. note the amount shown in game            -> A cents
    2. python live_funds_diff.py snap A   a.json
    3. buy/sell something in game; note amount  -> B cents
    4. python live_funds_diff.py snap B   b.json
    5. python live_funds_diff.py diff a.json b.json      # -> the address
    6. python live_funds_diff.py set <addr> 99999999     # patch it
    7. buy something in game -> the HUD repaints with the new amount

Only addresses present in BOTH snapshots (same address, holding A then B) are
candidates, which collapses ~150 hits down to a handful.
"""
import ctypes, json, struct, subprocess, sys
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_ALL = 0x0400 | 0x0010 | 0x0020 | 0x0008
CHUNK = 8 << 20

KINDS = (
    ("int32", lambda v: struct.pack("<i", v), 4),
    ("int64", lambda v: struct.pack("<q", v), 8),
    ("double", lambda v: struct.pack("<d", float(v)), 8),
    ("float", lambda v: struct.pack("<f", float(v)), 4),
    ("ascii", lambda v: str(v).encode(), None),
    ("label", lambda v: f"{v/100:.2f}".encode(), None),
)


class MBI64(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", wintypes.DWORD), ("__a1", wintypes.DWORD),
                ("RegionSize", ctypes.c_ulonglong), ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD), ("__a2", wintypes.DWORD)]


k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, ctypes.POINTER(MBI64), ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


def pid_of(name="PizzaBusiness.exe"):
    out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    for line in out.strip().splitlines():
        p = [x.strip('"') for x in line.split('","')]
        if len(p) >= 2 and p[0].lower() == name.lower():
            return int(p[1])


class Mem:
    def __init__(self):
        self.pid = pid_of()
        if not self.pid:
            raise SystemExit("PizzaBusiness.exe is not running")
        self.h = k32.OpenProcess(PROCESS_ALL, False, self.pid)
        if not self.h:
            raise SystemExit(f"OpenProcess failed err={ctypes.get_last_error()} -- run as admin")

    def regions(self):
        addr, mbi = 0, MBI64()
        while addr < 0x7FFFFFFFFFFF:
            if not k32.VirtualQueryEx(self.h, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            if (mbi.State == 0x1000 and mbi.Protect not in (0x01, 0x100)
                    and (mbi.Protect & 0xFF) in {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}):
                yield mbi.BaseAddress, mbi.RegionSize
            addr = mbi.BaseAddress + mbi.RegionSize

    def read(self, a, n):
        b = ctypes.create_string_buffer(n); g = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(self.h, a, b, n, ctypes.byref(g)):
            return b.raw[:g.value]

    def write(self, a, d):
        b = ctypes.create_string_buffer(d, len(d)); w = ctypes.c_size_t(0)
        return bool(k32.WriteProcessMemory(self.h, a, b, len(d), ctypes.byref(w)))


def snapshot(m, cents):
    """{(addr, kind): length} for every representation of `cents`."""
    out = {}
    for kind, enc, fixed in KINDS:
        pat = enc(cents)
        if not pat:
            continue
        for base, size in m.regions():
            off = 0
            while off < size:
                n = min(CHUNK, size - off)
                d = m.read(base + off, n)
                if d:
                    s = 0
                    while True:
                        i = d.find(pat, s)
                        if i < 0:
                            break
                        s = i + 1
                        if fixed == 4 and i % 4:
                            continue
                        out[f"{base + off + i}:{kind}"] = len(pat)
                off += n
    return out


def main():
    cmd = sys.argv[1]
    m = Mem()

    if cmd == "snap":
        cents = int(sys.argv[2])
        path = sys.argv[3]
        snap = snapshot(m, cents)
        json.dump({"cents": cents, "slots": snap}, open(path, "w"), indent=1)
        print(f"pid {m.pid}: {len(snap)} representations of {cents} "
              f"(${cents/100:,.2f}) -> {path}")

    elif cmd == "diff":
        a = json.load(open(sys.argv[2]))
        b = json.load(open(sys.argv[3]))
        common = sorted(set(a["slots"]) & set(b["slots"]),
                        key=lambda k: (k.split(":")[1], int(k.split(":")[0])))
        print(f"{a['cents']} ({len(a['slots'])}) n {b['cents']} ({len(b['slots'])}) "
              f"-> {len(common)} common addresses")
        for k in common:
            addr, kind = k.split(":")
            print(f"  LIVE?  0x{int(addr):012x}  [{kind}]")
        if not common:
            print("  none -- make sure the game process was NOT restarted between snaps")

    elif cmd == "set":
        addr = int(sys.argv[2], 0)
        cents = int(sys.argv[3])
        for kind, enc, fixed in (("int32", lambda v: struct.pack("<i", v), 4),
                                 ("int64", lambda v: struct.pack("<q", v), 8),
                                 ("double", lambda v: struct.pack("<d", float(v)), 8)):
            data = enc(cents)
            before = m.read(addr, len(data))
            if before is None:
                continue
            ok = m.write(addr, data)
            after = m.read(addr, len(data))
            print(f"  0x{addr:012x} {kind}: {before.hex(' ')} -> {after.hex(' ')} ok={ok}")
            break
        print("now buy/sell something in game to make the HUD repaint")

    elif cmd == "read":
        addr = int(sys.argv[2], 0)
        d = m.read(addr, 8)
        print(f"0x{addr:012x} {d.hex(' ')}  int32={struct.unpack_from('<i', d, 0)[0]} "
              f"int64={struct.unpack_from('<q', d, 0)[0]} double={struct.unpack_from('<d', d, 0)[0]}")

    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
