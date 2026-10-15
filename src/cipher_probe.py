"""Determine the cipher structure of the Good Pizza Great Pizza .dat saves."""
import os, math, collections, zlib

S = r"C:\Users\<user>\AppData\Local\PizzaBusiness"
def load(n): return open(os.path.join(S, n), "rb").read()

FILES = ["profile.dat", "profile.dat.bak", "profile.dat.bak.bak",
         "last_day.dat", "last_day.dat.bak", "rc.dat", "made_pizzas.dat"]

data = {n: load(n) for n in FILES if os.path.exists(os.path.join(S, n))}
for n, b in data.items():
    print(f"{n:24s} len={len(b):6d}  mod4={len(b)%4} mod8={len(b)%8} mod16={len(b)%16}")

print("\n=== duplicate block counts (ECB signature) ===")
for bs in (4, 8, 16, 32):
    print(f" block={bs}:")
    for n, b in data.items():
        blks = [b[i:i+bs] for i in range(0, len(b) - bs + 1, bs)]
        c = collections.Counter(blks)
        dup = sum(v - 1 for v in c.values() if v > 1)
        print(f"   {n:24s} blocks={len(blks):5d} unique={len(c):5d} dups={dup}")

print("\n=== window entropy (512-byte windows) ===")
def H(b):
    if not b: return 0.0
    c = collections.Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())
for n, b in data.items():
    ws = [H(b[i:i+512]) for i in range(0, len(b), 512)]
    print(f"  {n:24s} min={min(ws):.2f} max={max(ws):.2f} low(<6)={sum(1 for w in ws if w<6)}/{len(ws)}")

print("\n=== all-pairs longest common run (min 24) ===")
names = list(data)
def longest_common(a, b, minlen=24):
    # rolling: index 8-grams of a
    idx = {}
    for i in range(len(a) - 7):
        idx.setdefault(a[i:i+8], []).append(i)
    best = (0, -1, -1)
    for j in range(len(b) - 7):
        for i in idx.get(b[j:j+8], ()):
            L = 8
            while i+L < len(a) and j+L < len(b) and a[i+L] == b[j+L]:
                L += 1
            if L > best[0]:
                best = (L, i, j)
    return best if best[0] >= minlen else None

for i in range(len(names)):
    for j in range(i+1, len(names)):
        r = longest_common(data[names[i]], data[names[j]])
        if r:
            print(f"  {names[i]:22s} @{r[1]:6d}  ==  {names[j]:22s} @{r[2]:6d}   run={r[0]}")
        else:
            print(f"  {names[i]:22s} <-> {names[j]:22s}   no run >= 24")

print("\n=== profile.dat vs profile.dat.bak.bak: differing offsets ===")
a, b = data["profile.dat"], data["profile.dat.bak.bak"]
n = min(len(a), len(b))
d = [i for i in range(n) if a[i] != b[i]]
print(f"  count={len(d)} of {n}")
# summarize as runs of difference
runs = []
if d:
    s = p = d[0]
    for x in d[1:]:
        if x == p + 1: p = x
        else: runs.append((s, p)); s = p = x
    runs.append((s, p))
print(f"  diff runs ({len(runs)}): {runs[:25]}")

print("\n=== profile.dat vs last_day.dat: differing offsets ===")
c = data["last_day.dat"]
n = min(len(a), len(c))
d2 = [i for i in range(n) if a[i] != c[i]]
runs2 = []
if d2:
    s = p = d2[0]
    for x in d2[1:]:
        if x == p + 1: p = x
        else: runs2.append((s, p)); s = p = x
    runs2.append((s, p))
print(f"  count={len(d2)} of {n}")
print(f"  diff runs ({len(runs2)}): {runs2[:25]}")

print("\n=== header bytes 0..15 of each .dat ===")
for n, b in data.items():
    if n == "made_pizzas.dat": continue
    print(f"  {n:24s} {b[:16].hex(' ')}")

print("\n=== searching for plaintext schema tokens in .dat files ===")
toks = [b"funds", b"gems", b"money", b"business_day", b"day", b"version",
        b"profile", b"last_day", b"{", b"}", b'"']
for n, b in data.items():
    hits = {t.decode(): b.find(t) for t in toks if b.find(t) >= 0}
    if hits: print(f"  {n:24s} {hits}")

print("\n=== XOR profile.dat with rc.dat / made_pizzas.dat: printable ratio ===")
p = data["profile.dat"]
for other in ["rc.dat", "made_pizzas.dat", "last_day.dat"]:
    o = data[other]
    x = bytes(u ^ v for u, v in zip(p, o))
    pr = sum(1 for ch in x if 32 <= ch < 127 or ch in (9,10,13)) / len(x)
    print(f"  xor({other:22s}) printable={pr:.3f}  head={x[:32].hex(' ')}")
