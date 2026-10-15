# Reverse-engineering notes

Everything below was established by evidence, not guesswork. It is written down
mainly so that the next person (or the next game update) does not have to redo
it.

## 1. Where the save files live

```
%LOCALAPPDATA%\PizzaBusiness\
```

Found by observing that the game writes `local_flags.json` there at runtime.
It is **not** under `AppData\LocalLow` (this is a cocos2d-x title, not Unity)
and **not** in the install directory.

| file | notes |
|---|---|
| `profile.dat` (+`.bak`, `.bak.bak`) | main save, 3-deep rotation, **encrypted** |
| `last_day.dat` (+`.bak`) | previous-day snapshot, **encrypted** |
| `rc.dat` | written at launch, **encrypted** |
| `made_pizzas.dat` | **plaintext** |
| `bi_sync_journal.jsonl` | **plaintext** analytics events |
| `local_flags.json`, `UserDefault.xml` | **plaintext** settings |

## 2. The money field

The game calls it `funds`, and it is an integer number of **cents**.
`bi_sync_journal.jsonl` states it outright:

```json
{"business_day":21,"current_funds":5470.0,"current_gems":88,"tbid":"<tapblaze-id>"}
```

`5470` == `$54.70`, matching the HUD. The in-memory state store keeps the same
value as a **length-prefixed decimal string**:

```
<u16 keyLen><key><u16 valLen><value>
...
05 00 "funds" 03 00 "670"        <- 3 chars, not 4 -- easy to miss
19 00 "garden_bed_00_growthStage" 01 00 "0"
```

## 3. How the money is actually computed

`Cheat Engine -> Find out what writes to this address` on the cached value gives:

```
PizzaBusiness.exe+3C1ADA : mov [ebx+00000480], edx
```

That address is only a **cache**. Disassembling the getter offline
(`PizzaBusiness.exe` is a 32-bit PE, image base `0x400000`, ASLR active):

```asm
RVA 0x52808E  getFunds():
  0x528092  call 0x6FB385          ; singleton
  0x52809B  call 0x6F6C2E          ; -> esi   component A
  0x5280A4  call 0x5280AE          ; -> eax   component B
  0x5280AA  add  eax, esi          ; return B + A

RVA 0x5280AE  component B:
  0x5280BA  mov  esi, [ecx+0x1C]   ; store = [this+0x1c]
  0x5280CB  push 0x90053C          ; string literal
  0x5280DF  call 0x779DA9          ; store->get(<literal>)
```

The literal at **RVA 0x90053C is `"funds"`**, confirmed by reading `.rdata`.
Hence:

```
money = store->get("funds")  +  the day's running net
```

### Why every simpler approach fails

* **Value scanning can never find it.** No location holds the displayed amount.
  CE converges to exactly two addresses (the cache and a serialisation copy),
  and patching either is pointless because the value is recomputed.
* **The HUD does not repaint for memory edits.** The caller compares against the
  cache and returns early when unchanged:
  `cmp edx,[ebx+0x480] / je -> return`. The label only refreshes when the game
  itself changes the money.
* **The saved value is the base, the delta lives in the day.** That is why the
  store string can sit unchanged all day while the HUD keeps moving.

## 4. The patch

`call rel32` and `mov eax, imm32` are both exactly 5 bytes, so the whole fix is:

```
RVA 0x5280A4 : E8 05 00 00 00   ->   B8 <imm32>
```

`getFunds()` then returns a constant, which the game reports and saves through
its own code paths.

## 5. Save-file encryption

The save files are **not** worth attacking blindly:

| observation | conclusion |
|---|---|
| entropy ~7.97 bits/byte, no low-entropy region | strong encryption / good keystream |
| no repeated 16-byte block | not ECB |
| isolated 1-byte diffs between saves | byte-wise stream cipher, not a block cipher |
| **0~1 shared 9-byte runs between any two saves** | **each save has its own keystream** |

That last row is the decisive one: cross-save differentials are impossible, so
editing `profile.dat` would require recovering the key from the binary.

## 6. Dead ends (do not repeat these)

* Treating it as a Unity game and looking in `AppData\LocalLow`.
* Assuming a fixed field offset and diffing saves:
  `C_a[i] ^ C_b[i] == funds_a ^ funds_b` — zero hits.
* Assuming the store string is live — it is a load-time snapshot, rewritten on
  save from the computed value.
* Patching the `[ebx+0x480]` cache, the profile-snapshot double, or any of the
  `"670"` store copies — all are derived.
* Searching for the amount in **dollars**: `double 6.70` / `float 6.70` are
  absent; the game stores cents.
* Cheat Engine's debugger: this game is aggressively anti-debug. The VEH
  debugger still crashes it; `Page exceptions` yielded one result and then
  `Show disassembler` killed the process.
* Full-disk `Get-ChildItem -Recurse` while hunting for saves: blows up in output
  and timeouts. Use `cmd /c "dir /s /b <pattern>"`.

## 7. Tooling

| script | purpose |
|---|---|
| `disasm.py` | offline disassembly around the money write |
| `disasm_rva.py` | disassemble any RVA (used to follow the getter) |
| `extract_icon.py` | extract a PE icon group (for the maintainer's own use) |

All of it works **offline on the shipped `.exe`** — the running game and any
debugger are not needed, which matters because the game's anti-debug makes live
analysis painful.
