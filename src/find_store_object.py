"""Find the live store object via  store = [this + 0x1c].

The money getter (RVA 0x52808e) does:

    mov esi, [ecx+0x1c]      ; store object
    push "funds"
    call store->get("funds")

and its caller (RVA 0x3C1A82) holds `this` in EBX, with:
    [this+0x470] = pointer (render obj)
    [this+0x474] = int
    [this+0x478] = byte
    [this+0x480] = cached money  <-- equals what the HUD shows

So: find the int32 equal to the displayed money, treat addr-0x480 as `this`,
then follow [this+0x1c] and dump the store looking for the real "funds" value.
"""
import ctypes, re, struct, subprocess
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
CHUNK = 4 << 20
HUD_RE = re.compile(rb"([\x04-\x0b])\x00\x00\x00\x07\x00\x00\x00")


class M(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", wintypes.DWORD), ("__a1", wintypes.DWORD),
                ("RegionSize", ctypes.c_ulonglong), ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD), ("__a2", wintypes.DWORD)]


k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, ctypes.POINTER(M), ctypes.c_size_t]


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
        self.h = k32.OpenProcess(0x0400 | 0x0010, False, self.pid)
        assert self.h, f"OpenProcess err={ctypes.get_last_error()}"

    def chunks(self):
        a, mbi = 0, M()
        while a < 0x7FFFFFFFFFFF:
            if not k32.VirtualQueryEx(self.h, a, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            if (mbi.State == 0x1000 and mbi.Protect not in (0x01, 0x100)
                    and (mbi.Protect & 0xFF) in {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}):
                off = 0
                while off < mbi.RegionSize:
                    n = min(CHUNK, mbi.RegionSize - off)
                    d = self.read(mbi.BaseAddress + off, n)
                    if d:
                        yield mbi.BaseAddress + off, d
                    off += n
            a = mbi.BaseAddress + mbi.RegionSize

    def read(self, a, n):
        b = ctypes.create_string_buffer(n); g = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(self.h, a, b, n, ctypes.byref(g)):
            return b.raw[:g.value]


m = Mem()
print(f"pid {m.pid}")

money = None
for base, d in m.chunks():
    for mm in HUD_RE.finditer(d):
        t = d[mm.end():mm.end() + mm.group(1)[0]]
        if re.fullmatch(rb"\d{1,8}\.\d\d", t):
            money = int(round(float(t) * 100))
            print(f"HUD ${t.decode()} -> {money} cents")
            break
    if money:
        break

pat = struct.pack("<i", money)
cands = []
for base, d in m.chunks():
    s = 0
    while True:
        i = d.find(pat, s)
        if i < 0:
            break
        s = i + 1
        if i % 4:
            continue
        cands.append(base + i)
print(f"\nint32 == {money}: {len(cands)} candidates")

# check the object signature around addr-0x480
print("\n=== checking candidates for the caller-object signature ===")
for a in cands:
    this = a - 0x480
    blob = m.read(this + 0x460, 0x40)
    if not blob or len(blob) < 0x30:
        continue
    ptr470 = struct.unpack_from("<I", blob, 0x470 - 0x460)[0]
    i474 = struct.unpack_from("<i", blob, 0x474 - 0x460)[0]
    b478 = blob[0x478 - 0x460]
    ok_ptr = 0x10000 < ptr470 < 0x7FFFFFFF and m.read(ptr470, 4) is not None
    print(f"  cache 0x{a:08x} -> this 0x{this:08x}  [470]=0x{ptr470:08x}"
          f"{' (readable)' if ok_ptr else ' (bad)'}  [474]={i474}  [478]={b478}")
    if ok_ptr and 0 <= i474 <= 100000 and b478 in (0, 1):
        store_ptr = struct.unpack("<I", m.read(this + 0x1C, 4))[0]
        print(f"      *** matches!  [this+0x1c] = 0x{store_ptr:08x}")
        if 0x10000 < store_ptr < 0x7FFFFFFF:
            sd = m.read(store_ptr, 0x120)
            if sd:
                print(f"      store object dump:")
                for r in range(0, min(len(sd), 0x120), 32):
                    ch = sd[r:r + 32]
                    print(f"        0x{store_ptr+r:08x}  {ch.hex(' ')}  "
                          f"|{''.join(chr(x) if 32 <= x < 127 else '.' for x in ch)}|")
            # hunt for "funds" and for the base value near it
            for probe in (b"funds", b"670"):
                idx = (sd or b"").find(probe)
                print(f"      '{probe.decode()}' inside store object: {idx}")
