"""Extract the full multi-resolution icon group from a PE (RT_GROUP_ICON + RT_ICON)
and rebuild a proper .ico file.

    python extract_icon.py <exe> <out.ico>

Rebuilding the whole ico (instead of System.Drawing.Icon.ExtractAssociatedIcon)
keeps every embedded size, so the icon stays sharp in Explorer / taskbar.
"""
import struct
import sys

RT_ICON = 3
RT_GROUP_ICON = 14


def load_pe(path):
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    opt_size = struct.unpack_from("<H", d, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    dd = opt + (96 if magic == 0x10b else 112)      # data directories start
    rsrc_rva, rsrc_size = struct.unpack_from("<II", d, dd + 2 * 8)   # entry 2
    secs = []
    sp = opt + opt_size
    for _ in range(nsec):
        name = d[sp:sp + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", d, sp + 8)
        secs.append((name, vaddr, vsize, raddr, rsize))
        sp += 40
    return d, rsrc_rva, rsrc_size, secs


def rva2off(rva, secs):
    for _n, va, vs, ra, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ra + (rva - va)
    return None


class Res:
    def __init__(self, data, base_rva, secs):
        self.d = data
        self.base = base_rva
        self.secs = secs

    def off(self, rel):
        return rva2off(self.base + rel, self.secs)

    def entries(self, rel):
        """yield (id_or_name, is_dir, child_rel_or_dataentry_rel)"""
        o = self.off(rel)
        n_named, n_id = struct.unpack_from("<HH", self.d, o + 12)
        total = n_named + n_id
        for i in range(total):
            p = o + 16 + i * 8
            name, off = struct.unpack_from("<II", self.d, p)
            name_id = name & 0x7FFFFFFF
            is_dir = bool(off & 0x80000000)
            yield name_id, is_dir, off & 0x7FFFFFFF

    def data_entry(self, rel):
        o = self.off(rel)
        rva, size = struct.unpack_from("<II", self.d, o)
        fo = rva2off(rva, self.secs)
        return self.d[fo:fo + size]


def main():
    exe, out = sys.argv[1], sys.argv[2]
    d, rsrc_rva, rsrc_size, secs = load_pe(exe)
    if rsrc_rva == 0:
        raise SystemExit("no resource directory")
    r = Res(d, rsrc_rva, secs)

    groups = []      # (name_id, [ (w,h,colors,planes,bits,bytes,nID) ])
    icons = {}       # id -> bytes
    for name_id, is_dir, child in r.entries(0):
        if not is_dir:
            continue
        if name_id == RT_GROUP_ICON:
            for gid, gdir, goff in r.entries(child):
                if not gdir:
                    continue
                for _lid, ldir, loff in r.entries(goff):
                    if ldir:
                        continue
                    blob = r.data_entry(loff)
                    _, _, cnt = struct.unpack_from("<HHH", blob, 0)
                    ent = []
                    for i in range(cnt):
                        e = blob[6 + i * 14: 6 + (i + 1) * 14]
                        w, h, col, _rsv, planes, bits, nbytes, iid = struct.unpack("<BBBBHHIH", e)
                        ent.append((w, h, col, planes, bits, nbytes, iid))
                    groups.append((gid, ent))
        elif name_id == RT_ICON:
            for iid, idir, ioff in r.entries(child):
                if idir:
                    continue
                for _lid, ldir, loff in r.entries(ioff):
                    if ldir:
                        continue
                    icons[iid] = r.data_entry(loff)

    if not groups:
        raise SystemExit("no RT_GROUP_ICON found")
    print(f"found {len(groups)} icon group(s); RT_ICON images: {len(icons)}")
    for gid, ent in groups:
        print(f"  group {gid}: " + ", ".join(
            f"{e[0] or 256}x{e[1] or 256}/{e[5]}B" for e in ent))

    # pick the group with the largest total pixel area (usually the main app icon)
    gid, ent = max(groups, key=lambda g: sum((e[0] or 256) * (e[1] or 256) for e in g[1]))
    print(f"\nusing group {gid} with {len(ent)} image(s)")

    header = struct.pack("<HHH", 0, 1, len(ent))
    dir_entries = b""
    blobs = b""
    offset = 6 + 16 * len(ent)
    for w, h, col, planes, bits, nbytes, iid in ent:
        img = icons.get(iid)
        if img is None:
            print(f"  !! missing RT_ICON id {iid}, skipping")
            continue
        dir_entries += struct.pack("<BBBBHHII", w, h, col, 0, planes, bits, len(img), offset)
        blobs += img
        offset += len(img)

    with open(out, "wb") as f:
        f.write(header + dir_entries + blobs)
    print(f"wrote {out}  ({offset} bytes)")


if __name__ == "__main__":
    main()
