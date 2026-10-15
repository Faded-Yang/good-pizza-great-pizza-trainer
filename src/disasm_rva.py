"""Disassemble an arbitrary RVA of PizzaBusiness.exe (offline, no game needed).

    python disasm_rva.py 0x92808e [nbytes]
    python disasm_rva.py 0x92e634 160
"""
import struct, subprocess, sys
import capstone

EXE = r"<game>\PizzaBusiness.exe"


def read_pe(path):
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
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
    return d, machine, image_base, secs


def rva_to_off(rva, secs):
    for name, vaddr, vsize, raddr, rsize in secs:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return raddr + (rva - vaddr)
    return None


data, machine, image_base, secs = read_pe(EXE)
mode = capstone.CS_MODE_32 if machine == 0x14c else capstone.CS_MODE_64
md = capstone.Cs(capstone.CS_ARCH_X86, mode)

for arg in sys.argv[1:]:
    if arg.startswith("0x"):
        rva = int(arg, 16)
    n = 0x100
    if "--n" in sys.argv:
        n = int(sys.argv[sys.argv.index("--n") + 1], 0)
    off = rva_to_off(rva, secs)
    blob = data[off:off + n]
    print(f"\n===== RVA 0x{rva:x}  (file 0x{off:x}, {n} bytes) =====")
    for ins in md.disasm(blob, image_base + rva):
        r = ins.address - image_base
        note = ""
        op = ins.op_str
        if "ecx +" in op or "ecx+" in op or op.startswith("ecx,"):
            note = "   <-- this->field"
        print(f"  {r:08x}  {ins.bytes.hex(' '):<26} {ins.mnemonic:<8} {op}{note}")
