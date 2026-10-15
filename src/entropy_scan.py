"""Find unencrypted / low-entropy regions in the .dat saves."""
import os, math, collections

S = r"C:\Users\<user>\AppData\Local\PizzaBusiness"
def load(n): return open(os.path.join(S, n), "rb").read()

def H(b):
    if not b: return 0.0
    c = collections.Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

for name in ["profile.dat", "profile.dat.bak", "last_day.dat", "last_day.dat.bak",
             "profile.dat.bak.bak", "rc.dat"]:
    b = load(name)
    print("=" * 78)
    print(f"{name}  len={len(b)}  whole-file entropy={H(b):.3f}")
    # full 256-byte windows only
    wins = []
    for i in range(0, len(b) - 255, 256):
        wins.append((H(b[i:i+256]), i))
    low = [w for w in wins if w[0] < 7.0]
    print(f"  256B windows: {len(wins)}  low-entropy(<7.0): {len(low)}")
    for h, i in low[:20]:
        chunk = b[i:i+256]
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        print(f"    @{i:6d} H={h:.3f}  {asc[:100]}")
    # longest run of identical bytes
    best = (0, 0, 0)
    i = 0
    while i < len(b):
        j = i
        while j + 1 < len(b) and b[j+1] == b[i]:
            j += 1
        if j - i + 1 > best[0]:
            best = (j - i + 1, i, b[i])
        i = j + 1
    print(f"  longest identical-byte run: len={best[0]} @{best[1]} byte=0x{best[2]:02x}")

# --- focused look at the shared region 5..725 of profile.dat / last_day.dat
p, ld = load("profile.dat"), load("last_day.dat")
print("=" * 78)
print("shared region profile.dat[5:725] == last_day.dat[5:725]")
seg = p[5:725]
print(f"  entropy of shared 720B segment: {H(seg):.3f}")
print("  first 128:", seg[:128].hex(" "))
print("  ascii    :", "".join(chr(c) if 32 <= c < 127 else "." for c in seg[:128]))
# byte histogram of segment
c = collections.Counter(seg)
print("  most common bytes:", [(f"0x{k:02x}", v) for k, v in c.most_common(10)])

# --- where exactly does the divergence start and is it periodic?
d = [i for i in range(len(p)) if p[i] != ld[i]]
print(f"\n  first differing offset: {d[0] if d else None}")
print(f"  last differing offset: {d[-1] if d else None}")
print(f"  total differing: {len(d)}  equal: {len(p) - len(d)}")
# periodicity of the matching positions
eq = [i for i in range(len(p)) if p[i] == ld[i]]
gaps = [eq[i+1] - eq[i] for i in range(len(eq) - 1)]
gc = collections.Counter(gaps)
print("  top gap sizes between equal positions:", gc.most_common(8))

# --- dump first 800 bytes of profile.dat in hex rows
print("\n=== profile.dat first 800 bytes ===")
for i in range(0, 800, 32):
    chunk = p[i:i+32]
    print(f"  {i:5d}  {chunk.hex(' ')}  |{''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)}|")
