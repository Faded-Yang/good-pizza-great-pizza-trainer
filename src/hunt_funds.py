"""Exhaustive funds hunt: every representation, every region, no size cap.

Earlier scans capped each region at 64 MB, which can silently skip data inside a
large reserved region.  This version walks each committed region in 8 MB chunks.
"""
import ctypes, struct, subprocess, collections, math
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_ALL = 0x0400 | 0x0010 | 0x0020 | 0x0008
CHUNK = 8 << 20


class MBI64(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", wintypes.DWORD), ("__a1", wintypes.DWORD),
                ("RegionSize", ctypes.c_ulonglong), ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD), ("__a2", wintypes.DWORD)]


k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, ctypes.POINTER(MBI64), ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


def pid_of(name="PizzaBusiness.exe"):
    out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    for line in out.strip().splitlines():
        p = [x.strip('"') for x in line.split('","')]
        if len(p) >= 2 and p[0].lower() == name.lower():
            return int(p[1])


class Mem:
    def __init__(self, pid):
        self.h = k32.OpenProcess(PROCESS_ALL, False, pid)
        assert self.h, ctypes.get_last_error()

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


FUNDS = 5470
m = Mem(pid_of())
print("pid", m.h)

needles = {
    "double 5470.0": struct.pack("<d", 5470.0),
    "float 5470.0": struct.pack("<f", 5470.0),
    "int32 5470": struct.pack("<i", 5470),
    "int64 5470": struct.pack("<q", 5470),
    "ascii '5470'": b"5470",
    "ascii '54.70'": b"54.70",
    "utf16 '5470'": "5470".encode("utf-16-le"),
    "ascii '54.7'": b"54.7",
    "double 54.70": struct.pack("<d", 54.70),
    "float 54.70": struct.pack("<f", 54.70),
}
hits = collections.defaultdict(list)
total = 0
nreg = 0
for base, size in m.regions():
    nreg += 1
    off = 0
    while off < size:
        n = min(CHUNK, size - off)
        d = m.read(base + off, n)
        if d:
            total += len(d)
            for k, pat in needles.items():
                s = 0
                while True:
                    i = d.find(pat, s)
                    if i < 0:
                        break
                    hits[k].append(base + off + i)
                    s = i + 1
        off += n
print(f"scanned {total/1e6:.1f} MB over {nreg} regions")
for k in needles:
    addrs = hits[k]
    print(f"  {k:16s} {len(addrs):6d}  {[hex(a) for a in addrs[:8]]}")

# range search for doubles/floats near 5470 (in case of float drift)
print("\n=== doubles in [5469.0, 5471.0] ===")
found = []
for base, size in m.regions():
    off = 0
    while off < size:
        n = min(CHUNK, size - off)
        d = m.read(base + off, n)
        if d:
            for i in range(0, len(d) - 8, 4):
                v = struct.unpack_from("<d", d, i)[0]
                if 5469.0 <= v <= 5471.0:
                    found.append((base + off + i, v))
        off += n
print(f"  {len(found)} -> {[(hex(a), v) for a, v in found[:20]]}")

# signature scan: int32 day(1..9999) followed by double in [0,5e8] then int32 gems
print("\n=== day|double_funds|gems clusters (any funds value) ===")
clusters = []
for base, size in m.regions():
    off = 0
    while off < size:
        n = min(CHUNK, size - off)
        d = m.read(base + off, n)
        if d:
            for i in range(0, len(d) - 16, 4):
                day = struct.unpack_from("<i", d, i)[0]
                if not (1 <= day <= 9999):
                    continue
                f = struct.unpack_from("<d", d, i + 4)[0]
                if not (0.0 <= f <= 5e8) or f != int(f):
                    continue
                gems = struct.unpack_from("<i", d, i + 12)[0]
                if 0 <= gems <= 100000:
                    clusters.append((base + off + i + 4, day, int(f), gems))
        off += n
print(f"  {len(clusters)} clusters")
for a, day, f, g in clusters[:30]:
    print(f"    0x{a:012x} day={day} funds={f} gems={g}")
