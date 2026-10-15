"""Offline disassembly of PizzaBusiness.exe around RVA 0x3C1ADA.

CE told us the money is written by

    PizzaBusiness.exe+3C1ADA :  mov [ebx+0x480], edx

We want to see where EDX is loaded from.  The game and CE are not involved, so
the game's anti-debug cannot interfere.
"""
import os, struct, sys, subprocess

EXE = r"<game>\PizzaBusiness.exe"
TARGET_RVA = 0x3C1ADA
BACK = 384          # how many bytes before the target to start disassembling


def read_pe(path):
    d = open(path, "rb").read()
    assert d[:2] == b"MZ"
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    assert d[pe:pe + 4] == b"PE\0\0"
    machine, nsec = struct.unpack_from("<HH", d, pe + 4)
    opt_size = struct.unpack_from("<H", d, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    image_base = (struct.unpack_from("<I", d, opt + 28)[0] if magic == 0x10b
                  else struct.unpack_from("<Q", d, opt + 24)[0])
    secs = []
    sp = opt + opt_size
    for _ in range(nsec):
        name = d[sp:sp + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", d, sp + 8)
        secs.append((name, vaddr, vsize, raddr, rsize))
        sp += 40
    return d, machine, magic, image_base, secs


def rva_to_off(rva, secs):
    for name, vaddr, vsize, raddr, rsize in secs:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return raddr + (rva - vaddr), name
    return None, None


data, machine, magic, image_base, secs = read_pe(EXE)
print(f"size           {len(data):,} bytes")
print(f"machine        0x{machine:04x} ({'i386 32-bit' if machine==0x14c else 'x86-64' if machine==0x8664 else '?'})")
print(f"optional magic 0x{magic:04x} ({'PE32' if magic==0x10b else 'PE32+'})")
print(f"image base     0x{image_base:x}")
for n, va, vs, ra, rs in secs:
    print(f"  {n:8s} RVA 0x{va:08x} vsize 0x{vs:06x} file 0x{ra:08x} rsize 0x{rs:06x}")

off, secname = rva_to_off(TARGET_RVA, secs)
if off is None:
    raise SystemExit("RVA not inside any section")
print(f"\nRVA 0x{TARGET_RVA:x} -> section {secname}, file offset 0x{off:x}")

start = max(0, off - BACK)
blob = data[start:off + 48]
blob_rva = TARGET_RVA - (off - start)
blob_va = image_base + blob_rva
print(f"disassembling {len(blob)} bytes at RVA 0x{blob_rva:x} (VA 0x{blob_va:x})\n")

try:
    import capstone
except ImportError:
    print("capstone not present -> pip install ...")
    subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "capstone"],
                   capture_output=True)
    try:
        import capstone
    except ImportError:
        capstone = None

if capstone:
    mode = capstone.CS_MODE_32 if machine == 0x14c else capstone.CS_MODE_64
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    print(f"=== capstone {capstone.__version__} "
          f"({'32-bit' if machine==0x14c else '64-bit'}) ===")
    for ins in md.disasm(blob, blob_va):
        rva = ins.address - image_base
        mark = ""
        if rva == TARGET_RVA:
            mark = "     <<<<<<<<<< MONEY WRITE  mov [ebx+0x480],edx"
        elif rva == TARGET_RVA - 6:
            mark = "     <<<< read of [ebx+0x470]"
        print(f"  {rva:08x}  {ins.bytes.hex(' '):<26} {ins.mnemonic:<8} {ins.op_str}{mark}")
        if ins.address > blob_va + len(blob) - 16:
            break
else:
    print("no disassembler available; raw hex follows")
    for r in range(0, len(blob), 16):
        print(f"  {blob_rva+r:08x}  {blob[r:r+16].hex(' ')}")
