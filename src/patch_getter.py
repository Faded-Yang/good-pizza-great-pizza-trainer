"""Make getFunds() return a huge amount by patching ONE instruction.

Offline disassembly of PizzaBusiness.exe gave:

    RVA 0x52808E  getFunds():
      0x528092  call 0x6FB385        ; A = singleton->something(0x24)
      0x5280A4  call 0x5280AE        ; B = store->get("funds")     <-- 5 bytes
      0x5280AA  add  eax, esi        ; return B + A

`call rel32` is exactly 5 bytes, the same length as `mov eax, imm32` (0xB8).
So replacing that single call makes the getter return a constant:

      0x5280A4   E8 05 00 00 00   ->   B8 <imm32 little-endian>   ; mov eax, imm32

ASLR is enabled (the module base was 0x8E0000 in one run), so the runtime address
is module_base + 0x5280A4, resolved via psapi.

Memory-only patch: the exe on disk is untouched and a game restart reverts it.
"""
import ctypes, struct, subprocess, sys
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

PROCESS_ALL = 0x0400 | 0x0010 | 0x0020 | 0x0008 | 0x0100   # + PROCESS_QUERY_INFORMATION
PATCH_RVA = 0x5280A4
EXPECT = b"\xE8\x05\x00\x00\x00"          # call 0x5280AE
NEW_CENTS = 99999999                       # $999,999.99
PAGE_EXECUTE_READWRITE = 0x40

k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, ctypes.c_size_t,
                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ulonglong),
                                     wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", wintypes.DWORD),
                ("EntryPoint", ctypes.c_void_p)]


psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                       ctypes.POINTER(MODULEINFO), wintypes.DWORD]


def pid_of(name="PizzaBusiness.exe"):
    out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    for line in out.strip().splitlines():
        p = [x.strip('"') for x in line.split('","')]
        if len(p) >= 2 and p[0].lower() == name.lower():
            return int(p[1])


pid = pid_of()
if not pid:
    raise SystemExit("PizzaBusiness.exe is not running")
h = k32.OpenProcess(PROCESS_ALL, False, pid)
if not h:
    raise SystemExit(f"OpenProcess failed err={ctypes.get_last_error()} (run as admin)")
print(f"pid {pid}  handle {h}")

mods = (ctypes.c_ulonglong * 512)()
need = wintypes.DWORD(0)
if not psapi.EnumProcessModules(h, mods, ctypes.sizeof(mods), ctypes.byref(need)):
    raise SystemExit(f"EnumProcessModules failed err={ctypes.get_last_error()}")
mi = MODULEINFO()
if not psapi.GetModuleInformation(h, ctypes.c_void_p(mods[0]), ctypes.byref(mi), ctypes.sizeof(mi)):
    raise SystemExit("GetModuleInformation failed")
base = mi.lpBaseOfDll
print(f"module base 0x{base:08x}  size 0x{mi.SizeOfImage:x}"
      f"   (so PizzaBusiness.exe+0x{PATCH_RVA:x} = 0x{base + PATCH_RVA:08x})")

addr = base + PATCH_RVA


def rd(a, n):
    b = ctypes.create_string_buffer(n); g = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, a, b, n, ctypes.byref(g)):
        return b.raw[:g.value]


before = rd(addr, 8)
print(f"\nbytes at patch site: {before.hex(' ')}")
if before[:5] != EXPECT:
    print(f"!! expected {EXPECT.hex(' ')} (call 0x5280AE) -- NOT matching.")
    print("   The binary may differ from the one I disassembled; aborting to be safe.")
    sys.exit(1)
print("   confirmed: 'call 0x5280AE'")

new = b"\xB8" + struct.pack("<I", NEW_CENTS)      # mov eax, imm32
old_prot = wintypes.DWORD(0)
if not k32.VirtualProtectEx(h, addr, len(new), PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot)):
    raise SystemExit(f"VirtualProtectEx failed err={ctypes.get_last_error()}")
wrote = ctypes.c_size_t(0)
ok = k32.WriteProcessMemory(h, addr, ctypes.create_string_buffer(new, len(new)),
                            len(new), ctypes.byref(wrote))
k32.VirtualProtectEx(h, addr, len(new), old_prot, ctypes.byref(old_prot))
k32.FlushInstructionCache(h, addr, len(new))
print(f"\nwrote {new.hex(' ')}  ok={bool(ok)} bytes={wrote.value}")
print(f"after: {rd(addr, 8).hex(' ')}")
print(f"\ngetFunds() now returns {NEW_CENTS} + delta  (${NEW_CENTS/100:,.2f} + delta)")
print("NOW buy/sell something in game -> the HUD should jump to ~999,999.99")
print("(restarting the game reverts this patch; the exe on disk is untouched)")
