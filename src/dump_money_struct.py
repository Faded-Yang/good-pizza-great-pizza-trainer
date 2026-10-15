"""Dump the neighbourhood of the money Double that CE found (19BA73C8).

The game overwrites it, so it is a derived copy -- but its struct usually also
holds the source (an int in cents, the gems, a pointer to the state store...).
"""
import ctypes, struct, subprocess, re
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_ALL = 0x0400 | 0x0010 | 0x0020 | 0x0008
CHUNK = 8 << 20
HUD_HDR = b"\x05\x00\x00\x00\x07\x00\x00\x00"
MONEY_RE = re.compile(rb"^\d{1,7}\.\d\d$")


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
    def __init__(self):
        self.pid = pid_of()
        if not self.pid:
            raise SystemExit("game not running")
        self.h = k32.OpenProcess(PROCESS_ALL, False, self.pid)
        assert self.h, f"OpenProcess err={ctypes.get_last_error()}"

    def regions(self):
        addr, mbi = 0, MBI64()
        while addr < 0x7FFFFFFFFFFF:
            if not k32.VirtualQueryEx(self.h, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            if (mbi.State == 0x1000 and mbi.Protect not in (0x01, 0x100)
                    and (mbi.Protect & 0xFF) in {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}):
                yield mbi.BaseAddress, mbi.RegionSize, mbi.Protect
            addr = mbi.BaseAddress + mbi.RegionSize

    def read(self, a, n):
        b = ctypes.create_string_buffer(n); g = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(self.h, a, b, n, ctypes.byref(g)):
            return b.raw[:g.value]


m = Mem()
print(f"pid {m.pid}")

# --- what does the HUD say right now?
shown = []
for base, size, prot in m.regions():
    off = 0
    while off < size:
        n = min(CHUNK, size - off)
        d = m.read(base + off, n)
        if d:
            s = 0
            while True:
                i = d.find(HUD_HDR, s)
                if i < 0:
                    break
                s = i + 1
                t = d[i + 8:i + 13]
                if MONEY_RE.match(t):
                    shown.append(t.decode())
        off += n
val = shown[0] if shown else None
print(f"HUD shows: {shown[:4]}")
cents = int(round(float(val) * 100)) if val else None
print(f"-> cents = {cents}")

# --- find the money Double(s) ourselves
needle = struct.pack("<d", float(cents)) if cents else None
hits = []
if needle:
    for base, size, prot in m.regions():
        off = 0
        while off < size:
            n = min(CHUNK, size - off)
            d = m.read(base + off, n)
            if d:
                s = 0
                while True:
                    i = d.find(needle, s)
                    if i < 0:
                        break
                    s = i + 1
                    hits.append((base + off + i, prot))
            off += n
print(f"\ndoubles == {cents}: {[(hex(a), hex(p)) for a, p in hits]}")

TARGET = 0x19BA73C8
for a0 in [a for a, _ in hits] + [TARGET]:
    blob = m.read(a0 - 160, 352)
    if not blob:
        print(f"\n=== 0x{a0:012x}: unreadable (stale address) ===")
        continue
    base = a0 - 160
    print(f"\n=== window around 0x{a0:012x} (region start 0x{base:012x}) ===")
    for r in range(0, 352, 32):
        ch = blob[r:r + 32]
        mark = "  <<< money double" if base + r <= a0 < base + r + 32 else ""
        print(f"  {base+r:>14}  {ch.hex(' ')}  |{''.join(chr(x) if 32 <= x < 127 else '.' for x in ch)}|{mark}")
    # neighbours holding the same money as int / int64
    ip = struct.pack("<i", cents) if cents else None
    qp = struct.pack("<q", cents) if cents else None
    li = [hex(base + i) for i in range(len(blob) - 4) if blob[i:i + 4] == ip]
    lq = [hex(base + i) for i in range(len(blob) - 8) if blob[i:i + 8] == qp]
    print(f"   int32 == {cents} nearby: {li}")
    print(f"   int64 == {cents} nearby: {lq}")
