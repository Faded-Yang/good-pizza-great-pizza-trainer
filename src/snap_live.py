"""snap_live.py -- read the on-screen money out of memory, then snapshot every
representation of it, so a single in-game purchase resolves the live variable.

    python snap_live.py show                 # what does the game display right now?
    python snap_live.py snap a.json          # snapshot all reps of the displayed value
    python snap_live.py diff a.json b.json   # live variable = common addresses

The HUD text lives in memory as a `<u32 5><u32 7>"NN.NN"` record, which is how we
learn the displayed amount without asking anybody.
"""
import ctypes, json, re, struct, subprocess, sys
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_ALL = 0x0400 | 0x0010 | 0x0020 | 0x0008
CHUNK = 8 << 20
HUD_HDR = b"\x05\x00\x00\x00\x07\x00\x00\x00"      # <u32 5><u32 7> then 5 ASCII chars
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
            raise SystemExit(f"OpenProcess failed err={ctypes.get_last_error()}")

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

    def write(self, a, d):
        b = ctypes.create_string_buffer(d, len(d)); w = ctypes.c_size_t(0)
        return bool(k32.WriteProcessMemory(self.h, a, b, len(d), ctypes.byref(w)))


def chunks(m):
    for base, size, prot in m.regions():
        off = 0
        while off < size:
            n = min(CHUNK, size - off)
            d = m.read(base + off, n)
            if d:
                yield base + off, d, prot
            off += n


def shown_money(m):
    """Read the HUD text out of memory -> cents."""
    vals = []
    for base, d, _ in chunks(m):
        s = 0
        while True:
            i = d.find(HUD_HDR, s)
            if i < 0:
                break
            s = i + 1
            txt = d[i + 8:i + 13]
            if MONEY_RE.match(txt):
                vals.append((base + i + 8, txt.decode()))
    return vals


def snapshot(m, cents):
    pats = {
        "int32": struct.pack("<i", cents),
        "int64": struct.pack("<q", cents),
        "double": struct.pack("<d", float(cents)),
        "float": struct.pack("<f", float(cents)),
        "ascii": str(cents).encode(),
        "label": f"{cents/100:.2f}".encode(),
    }
    out = {}
    for kind, pat in pats.items():
        for base, d, prot in chunks(m):
            s = 0
            while True:
                i = d.find(pat, s)
                if i < 0:
                    break
                s = i + 1
                if kind in ("int32", "float") and i % 4:
                    continue
                out[f"{base + i}:{kind}"] = prot
    return out


m = Mem()
cmd = sys.argv[1] if len(sys.argv) > 1 else "show"

if cmd == "show":
    found = shown_money(m)
    print(f"pid {m.pid}: {len(found)} HUD money strings")
    seen = set()
    for a, t in found:
        if t not in seen:
            seen.add(t)
            print(f"   displayed  ${t}   (string @0x{a:012x}, = {int(round(float(t)*100))} cents)")

elif cmd == "snap":
    found = shown_money(m)
    if not found:
        raise SystemExit("no HUD money string found -- is a save actually loaded?")
    txt = found[0][1]
    cents = int(round(float(txt) * 100))
    snap = snapshot(m, cents)
    json.dump({"cents": cents, "shown": txt, "slots": snap}, open(sys.argv[2], "w"), indent=1)
    print(f"displayed ${txt} -> {cents} cents; {len(snap)} representations -> {sys.argv[2]}")

elif cmd == "diff":
    a = json.load(open(sys.argv[2]))
    b = json.load(open(sys.argv[3]))
    common = sorted(set(a["slots"]) & set(b["slots"]),
                    key=lambda k: (k.split(":")[1], int(k.split(":")[0])))
    print(f"${a['shown']} ({len(a['slots'])})  n  ${b['shown']} ({len(b['slots'])})"
          f"   ->   {len(common)} addresses held BOTH values")
    for k in common:
        addr, kind = k.split(":")
        print(f"   LIVE?  0x{int(addr):012x}  [{kind}]  prot=0x{int(a['slots'][k]):x}")

elif cmd == "set":
    addr = int(sys.argv[2], 0)
    cents = int(sys.argv[3])
    shown = shown_money(m)
    print(f"current display: {[t for _, t in shown][:3]}")
    for kind, enc in (("int32", lambda v: struct.pack("<i", v)),
                      ("int64", lambda v: struct.pack("<q", v)),
                      ("double", lambda v: struct.pack("<d", float(v)))):
        d = m.read(addr, 8)
        if d is None:
            continue
        print(f"  before 0x{addr:012x}: {d.hex(' ')}")
        ok = m.write(addr, enc(cents))
        print(f"  {kind}: write_ok={ok} -> {m.read(addr,8).hex(' ')}")
        break
    print("now buy/sell something in game to force the HUD to repaint")
