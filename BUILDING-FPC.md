# Building with FPC / Lazarus

Complete process for compiling this library with **plain FPC on Linux**, from a
bare machine to a passing test run.

Automated equivalent: [`scripts/build-tests-fpc.sh`](scripts/build-tests-fpc.sh).

> **Delphi users:** none of this applies. This library compiles under Delphi with
> no extra dependencies — `Masks` and `ZLib` are both in the Delphi RTL. See
> [Delphi](#delphi-windows) at the end for the one build trap that does bite.

---

## Why the toolchain is unusual

Two constraints drive everything below, and neither is currently stated in the
README.

**FPC 3.3.1 (trunk) is mandatory, not recommended.** `zLib.inc` sets
`{$MODESWITCH FUNCTIONREFERENCES}` and `{$MODESWITCH ANONYMOUSFUNCTIONS}`,
neither of which exists in FPC 3.2.2. The README's "Supports FPC 3.3.1" is a
floor, not a preference — there is no 3.2.2 fallback.

**Lazarus is required even if you never open the IDE.** `Utils/Utils.IOUtils.pas`
has `Masks` in its uses clause, for a single `MatchesMask` call. On Delphi that
is `System.Masks` from the RTL; **on FPC there is no such RTL unit**, and the one
that exists lives in Lazarus's LazUtils component. The `.lpi` files carry the
path — `Net/Tests/FPC/WebSocketFrameTests/WebSocketFrameTests.lpi` lists

```
$(LazarusDir)\components\lazutils\lib\$(TargetCPU)-$(TargetOS)
```

— so IDE builds work and command-line builds do not. You need the Lazarus
*sources*; you do not need to build the IDE.

---

## Step 0 — Prerequisites

```bash
sudo apt update
sudo apt install -y build-essential git fpc
```

`fpc` here is distro 3.2.2 and is used **only as the bootstrap compiler** for
building trunk. It stays installed, and stays the default on `PATH`.

## Step 1 — FPC 3.3.1 trunk

```bash
git clone https://gitlab.com/freepascal.org/fpc/source.git ~/fpc-trunk-src
cd ~/fpc-trunk-src
make clean all OVERRIDEVERSIONCHECK=1 PP=$(which ppcx64)
sudo make install INSTALL_PREFIX=/usr/local/fpc-trunk

/usr/local/fpc-trunk/bin/fpc -iV        # must print 3.3.1
```

Do **not** put `/usr/local/fpc-trunk/bin` first on `PATH`. Leave distro 3.2.2 as
the default `fpc` and invoke trunk by full path. Mixing the two on `PATH` is how
half a project ends up compiled by the wrong compiler.

The unit tree lands at
`/usr/local/fpc-trunk/lib/fpc/3.3.1/units/x86_64-linux`. Verify it exists: a
wrong unit-tree path surfaces much later as `PPU Invalid Version 207 expecting
208`, an error that names a *unit* rather than the path that caused it.

*(Alternative: [fpcupdeluxe](https://github.com/LongDirtyAnimAlf/fpcupdeluxe)
installs trunk FPC and trunk Lazarus together in one pass. Its layout differs;
set `TRUNK_FPC` and `TRUNK_UNITS` accordingly.)*

## Step 2 — Lazarus sources, for LazUtils

```bash
sudo apt install -y lazarus-src        # → /usr/share/lazarus/<version>/
# or
git clone --depth 1 https://gitlab.com/freepascal.org/lazarus/lazarus.git ~/lazarus
```

Verify the one file that matters:

```bash
ls ~/lazarus/components/lazutils/masks.pas
```

**Use the source directory, not `components/lazutils/lib/…`.** The prebuilt
`.ppu` there were compiled by whatever FPC your Lazarus install uses — usually
distro 3.2.2 — and feeding those to trunk produces the `PPU Invalid Version`
error again. Compiling `masks.pas` from source under trunk avoids it.

## Step 3 — Build and run the tests

```bash
LAZARUS_DIR=~/lazarus ./scripts/build-tests-fpc.sh
```

Expected:

```
── WebSocketFrameTests ──
   built ok
All WebSocket frame tests passed.
   PASS
── CryptRandomTests ──
   built ok
All cryptographic random tests passed.
   PASS
```

---

## The flags, and why each is load-bearing

If you are writing your own command line rather than using the script:

| flag | why |
|---|---|
| `-n` | Ignore `/etc/fpc.cfg`, which points at the **distro 3.2.2** unit tree. Without it trunk silently loads 3.2.2 `.ppu` for anything not on the explicit path → `PPU Invalid Version 207 expecting 208`. |
| `-MDelphi` | This library is Delphi-syntax Object Pascal. |
| `-Sc` | C-style assignment operators (`+=`). Needed **only by LazUtils** — `lazutf8.pas` uses them, and neither `-MDelphi` nor the unit's own mode directive enables them. Lazarus supplies this through `lazutils.lpk`; a bare build must pass it. Additive, so this library's own sources are unaffected. |
| **no** `-Sh` | `-Sh` makes `ansistring` the default `string`, changing generic instantiation and therefore FPC's mangled symbol names. The link then fails with `undefined reference to …$_$…` for symbols that are present. |
| `-Fu Net -Fu Utils -Fu DelphiToFPC` | The library's own units. `DelphiToFPC` holds the FPC-only shims (`DTF.RTL`, `DTF.StaticZLib`); a Delphi build never reveals that this path is missing. |
| `-Fi .` | **Include** path for the repo root. Every unit opens `{$I zLib.inc}`, which lives there, not beside them. Missing it reads as a broken checkout. |
| `-Fu CnPack/Common -Fu CnPack/Crypto` | `Utils/Utils.Hash.pas` uses `CnMD5`/`CnSHA1`/`CnSHA2`. Fork-only — see `MAINTAINING-CNPACK-SUBSET.md`. |
| `-Fi CnPack/Common` | Every CnPack unit opens `{$I CnPack.inc}`, which lives there. **A unit path does not satisfy an include** — a separate flag from the `-Fu` above, and forgetting it is its own error. |
| `-Fu <lazarus>/components/lazutils` | `Masks`. See Step 2. |
| `-Fu <trunk units>/*/` | See below. |
| `-FU <fresh dir>` | A private, **wiped** unit output directory per program. FPC's `.ppu` cache does not account for changed defines *or* switches, so a shared directory silently reuses units compiled in an incompatible context. |

### Why every trunk package directory, rather than a curated list

`Utils/Utils.Hash.pas` has an **unguarded** `ZLib` in its uses clause, where
`Net/Net.CrossHttpClient.pas` correctly branches to `DTF.StaticZLib` on FPC. So
the transitive closure cannot be read off the source, and a curated `-Fu` list
fails one package at a time.

`scripts/build-tests-fpc.sh` therefore adds every `$TRUNK_UNITS/*/` directory.
The tradeoff is that if two packages export the same unit name, first match on
the path wins, silently — acceptable for a test that only has to link, and worth
being deliberate about anywhere a wrong unit would produce a wrong *result*
rather than a failure.

---

## Test coverage

| suite | asserts | needs |
|---|---|---|
| `Utils/Tests/FPC/CryptRandomTests` | the cryptographically-secure random API | `Utils/` only — builds with none of Step 2 |
| `Net/Tests/FPC/WebSocketFrameTests` | RFC 6455 per-frame masking | the whole `Net/` chain, so everything above |

That split is why `CryptRandomTests` builds first try while the other needs the
full setup: it never touches `Net/`.

Building `WebSocketFrameTests` compiles `Net.CrossWebSocketParser` →
`Net.CrossSocket.Base`, `Utils.Hash`, `Utils.Utils`, `Utils.IOUtils`, CnPack and
`DTF.StaticZLib` — so a green run there doubles as a compile check over most of
the library, which is most of its value.

**Neither suite covers TLS, mTLS, or the HTTP client.**

---

## Troubleshooting

Every row is an error message someone actually hit.

| Error | Cause | Fix |
|---|---|---|
| `Can't find unit Masks used by Utils.IOUtils` | LazUtils absent. It is **not** FPC RTL. | Step 2, then `-Fu <lazarus>/components/lazutils` |
| `C styled assignment operators are turned off` in `lazutf8.pas` | LazUtils needs `-Sc` | add `-Sc` |
| `Cannot open include file "CnPack.inc"` | `-Fu` given for CnPack but not `-Fi` | add `-Fi CnPack/Common` |
| `Cannot open include file "zLib.inc"` | no include path for the repo root | add `-Fi .` |
| `Can't find unit ZLib used by Utils.Hash` | trunk package dir not on the path (`Utils.Hash` has an unguarded `ZLib`) | add all `$TRUNK_UNITS/*/` |
| `PPU Invalid Version 207 expecting 208` | 3.2.2 units reached a trunk build — missing `-n`, wrong unit tree, or LazUtils' prebuilt `lib/` | add `-n`; verify the unit tree; use LazUtils **source** |
| `undefined reference to …$_$…` at link | `-Sh` used, or a stale `-FU` dir mixing compilation contexts | drop `-Sh`; wipe the unit output dir |
| `Can't find unit DTF.RTL` | `DelphiToFPC` not on the unit path | add `-Fu DelphiToFPC` |
| Builds, but behaves like a different build | FPC reused `.ppu` compiled with other defines | wipe the `-FU` dir |

---

## Delphi (Windows)

No extra dependencies — `System.Masks` and `System.ZLib` are RTL. Open and build.

**The one trap** is the DCU cache. A `{$DEFINE …}` in a `.dpr` does **not**
invalidate `.dcu` files built without it — dcc compares timestamps, not the
define set — so you silently link a differently-configured build with no
diagnostic. Always:

1. **Project Options → Conditional defines** — set defines there, not only in the `.dpr`
2. `del *.dcu`
3. **Build**, not Compile

---

## Notes for maintainers

Two things above are arguably worth fixing rather than documenting:

- **`Masks`** is one `MatchesMask` call in `Utils/Utils.IOUtils.pas`, and it
  forces every FPC consumer — including headless CI with no IDE — to have
  Lazarus checked out. Replacing that call would remove the dependency outright.
- **`Utils/Utils.Hash.pas`'s unguarded `ZLib`**, where every other unit in the
  library branches with `{$IFDEF DELPHI}` to `DTF.StaticZLib`.
