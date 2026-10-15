# Good Pizza, Great Pizza — Money Trainer
# 可口的披萨，美味的披萨 — 金钱修改器

A tiny single-file money trainer for the Steam game **Good Pizza, Great Pizza**
(appid 770810), plus a full write-up of how the game's money value was located.

一个单文件金钱修改器，附带**完整的逆向分析过程**。

> **Disclaimer / 免责声明**
> For **single-player / offline** use only. Do not use it in multiplayer or on
> leaderboards. This project contains **no game assets** — no extracted
> artwork, no game binaries, no save files.
> 仅供单人离线使用，请勿用于联机或排行榜。本项目**不含任何游戏素材**。

---

## Features / 功能

* Money input in **dollars** (auto-converted), thousands separators accepted
* One click apply / restore
* Auto-detects the game; optional "keep applied" across game restarts
* Single 117 KB `.exe`, no Python, no installer — .NET Framework 4.x only
  (already present on Windows 10/11)
* **Touches memory only**: never modifies the game `.exe` or any save file

---

## Usage / 使用

1. Start the game and enter your shop
2. Run `GpgpTrainer.exe` (right-click → *Run as administrator* if it complains)
3. Type an amount such as `999999.99` and click **修改金钱**

---

## How it works / 原理

Cheat Engine's *"find out what writes to this address"* points at

```
PizzaBusiness.exe+3C1ADA :  mov [ebx+0x480], edx
```

Following `edx` backwards through an **offline disassembly** of
`PizzaBusiness.exe` gives the real getter:

```asm
RVA 0x52808E   getFunds():
  0x528092  call 0x6FB385        ; component A  (the day's net income)
  0x5280A4  call 0x5280AE        ; component B  = store->get("funds")   <-- 5 bytes
  0x5280AA  add  eax, esi        ; return B + A
```

`[ebx+0x480]` is only a **cache**, and the label is refreshed only when the
value changes:

```asm
  0x3C1AC8  cmp  edx, [ebx+0x480]
  0x3C1ACE  je   -> return        ; unchanged => no repaint
  0x3C1ADA  mov  [ebx+0x480], edx
```

So **the money is computed, not stored**:

```
money = store->get("funds")  +  the day's running net
```

That is why *every* value-scan approach fails: no memory location ever equals
the displayed amount. The fix is to replace the single 5-byte call — `call rel32`
and `mov eax,imm32` are both 5 bytes:

```
RVA 0x5280A4 :  E8 05 00 00 00   (call)   ->   B8 <imm32>   (mov eax, amount)
```

`getFunds()` then returns a constant, and the game's own HUD / save path picks
it up. Full details, including the dead ends, are in
[`docs/REVERSE-ENGINEERING.md`](docs/REVERSE-ENGINEERING.md).

---

## Build / 自行编译

No toolchain needed — Windows ships a C# compiler:

```bat
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe ^
   /target:winexe /optimize+ /debug- /out:GpgpTrainer.exe ^
   /win32icon:gpgp.ico ^
   /r:System.Windows.Forms.dll /r:System.Drawing.dll GpgpTrainer.cs
```

---

## Compatibility / 兼容性

Tested against **5.59.0 (724)**. Before touching anything the trainer verifies
the bytes at the patch site, so a game update makes it **fail safely** rather
than corrupt the game.

The offset is version-specific. If the game updates, re-locate it with the
offline disassembler in [`src/`](src):

```bat
python src\disasm.py            :: dumps the code around the money write
python src\disasm_rva.py 0x52808e
```

---

## License

MIT for the code in this repository. The game, its name and its artwork belong
to TapBlaze — none of it is included here.
