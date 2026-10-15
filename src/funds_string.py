"""The live money is the STRING value of the key "funds" in the game's key/value
state store (values are u16-length-prefixed strings):

    ... 0f 00 "fullscreen_mode" 01 00 "1" 00 05 00 "funds" 04 00 "5470" 01 19 00 "garden_bed_00_growthStage" ...

So `funds` = "5470" == 5470 cents == $54.70, matching the HUD.

Verify with a same-length patch ("5470" -> "9999"), then (if confirmed) extend
the value in place using the u16 length prefix.

    python funds_string.py find
    python funds_string.py set 9999          # same length only (safe test)
    python funds_string.py set 99999999 --extend
"""
import ctypes, struct, subprocess, sys
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_ALL = 0x0400 | 0x0010 | 0x0020 | 0x0008
CHUNK = 8 << 20
KEY = b"funds"


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

    def write(self, a, d):
        b = ctypes.create_string_buffer(d, len(d)); w = ctypes.c_size_t(0)
        return bool(k32.WriteProcessMemory(self.h, a, b, len(d), ctypes.byref(w)))


def find(m):
    """Return [(value_addr, value_len, key_addr, region_base)] for key 'funds'."""
    out = []
    needle = struct.pack("<H", len(KEY)) + KEY
    for base, size in m.regions():
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
                    vlen_off = i + len(needle)
                    if vlen_off + 2 > len(d):
                        continue
                    vlen = struct.unpack_from("<H", d, vlen_off)[0]
                    if not (1 <= vlen <= 32):
                        continue
                    vaddr = base + off + vlen_off + 2
                    val = d[vlen_off + 2: vlen_off + 2 + vlen]
                    if val.isdigit():
                        out.append((vaddr, vlen, base + off + i, val.decode()))
            off += n
    return out


m = Mem(pid_of())
cmd = sys.argv[1] if len(sys.argv) > 1 else "find"
slots = find(m)
print(f"pid {m.h}: found {len(slots)} 'funds' entries")
for vaddr, vlen, kaddr, val in slots:
    print(f"  value@0x{vaddr:012x} len={vlen} key@0x{kaddr:012x} value=\"{val}\" (${int(val)/100:,.2f})")

if cmd == "find" or not slots:
    sys.exit()

newval = sys.argv[2]
new = newval.encode()
if cmd == "set":
    if len(new) != slots[0][1] and "--extend" not in sys.argv:
        print(f"\nValue length {len(new)} != {slots[0][1]} on disk. "
              f"Use --extend to rewrite the length prefix and following bytes.")
        # still do it if lengths match for some slot
        todo = [s for s in slots if s[1] == len(new)]
        if not todo:
            sys.exit(1)
        slots = todo
    for vaddr, vlen, kaddr, val in slots:
        if len(new) == vlen:
            ok = m.write(vaddr, new)
        else:
            # extend: new length prefix + value, then re-pad the remainder of the
            # old value slot with the following records untouched -> only safe if
            # new is shorter, or if we pad the tail with spaces (breaks nothing
            # for this parser since length prefix drives parsing)
            print(f"  extending {vlen} -> {len(new)} at 0x{vaddr:012x}")
            m.write(kaddr + (vaddr - kaddr) - 2, struct.pack("<H", len(new)))
            ok = m.write(vaddr, new)
        back = m.read(vaddr, len(new))
        print(f"  0x{vaddr:012x} {val} -> {back}  ok={ok}")
