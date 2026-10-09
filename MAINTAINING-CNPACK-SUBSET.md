# Maintaining the bundled CnPack subset (boss-installability)

**Read this before touching `CnPack/`, releasing a new tag, or running the fork-sync.**

## Why this fork exists

`freitasjca/Delphi-Cross-Socket` is a fork of
[`winddriver/Delphi-Cross-Socket`](https://github.com/winddriver/Delphi-Cross-Socket)
whose **only reason to exist is to be installable with [Boss](https://github.com/HashLoad/boss)**
(the Delphi package manager). Two upstreams block that:

- **`winddriver/Delphi-Cross-Socket`** ships no `boss.json`.
- **CnPack / [`cnpack/cnvcl`](https://github.com/cnpack/cnvcl)** — a *dependency* of
  Delphi-Cross-Socket's SSL/crypto layer — also has no `boss.json` and is a huge repo.

So this fork adds (a) a `boss.json` and (b) the **minimal CnPack subset** that
Delphi-Cross-Socket actually needs, vendored under `CnPack/`. Since v1.0.16 (2026-10-08)
everything under `Net/` and `Utils/` is upstream's: the fork's earlier fixes (mTLS, the HEAD
resend loop, the compression guard, `SetMinTlsVersion`, `Content-Length: 0`) are all merged
upstream. A consumer (e.g.
[`horse-provider-crosssocket`](https://github.com/freitasjca/horse-provider-crosssocket))
can then `boss install` this fork and compile **without ever touching cnvcl**.

> Check the `boss.json` `description` against the code at every release; it went stale twice.

## The invariant — what must always hold

The vendored subset **must be a complete, self-contained transitive closure** so the package
compiles standalone:

1. **`CnPack/Common/CnPack.inc` must be present.** Every Cn unit begins with `{$I CnPack.inc}`;
   without it nothing compiles.
2. **Every unit named in any `uses` clause of a bundled unit must also be bundled.** If you add
   a Crypto unit that pulls in a new `Cn*` dependency, that dependency has to be copied in too.
3. The split mirrors cnvcl's own layout: foundation units in `CnPack/Common/`, crypto in
   `CnPack/Crypto/`.

### Current inventory (18 files — keep this list and the fork-sync in step)

```
CnPack/Common/   CnPack.inc  CnConsts.pas  CnFloat.pas  CnStrings.pas  CnWideStrings.pas
CnPack/Crypto/   CnAES.pas  CnBase64.pas  CnDES.pas  CnKDF.pas  CnMD5.pas  CnNative.pas
                 CnPemUtils.pas  CnRandom.pas  CnSHA1.pas  CnSHA2.pas  CnSHA3.pas
                 CnSM3.pas  CnSM4.pas
```

> History: earlier releases kept everything under `CnPack/Crypto/` (14 units). cnvcl later
> moved the foundation units to `Source/Common/` and added `CnStrings`, `CnWideStrings`,
> `CnSM4`; the v1.0.3 re-sync follows that — hence the `Common/` directory.

### Current source (fork v1.0.17)

All 18 files are **byte-identical to `cnpack/cnvcl` commit `19d3f72`** (2026-10-08).

- **Use `cnpack/cnvcl`, never `winddriver/cnvcl`.** The latter is a fork whose last commit
  is from 2025-02-16.
- **Take every file from ONE commit.** Before v1.0.17 the subset mixed versions: `CnPack.inc`
  dated from 2025-02-15 and the units from 2025-12-31 to 2026-06-29. Each file was an
  unmodified cnvcl version, but no single cnvcl commit ever contained that combination.
  An audit that compared against one snapshot found 13 "differences" that were really
  different points in time.
- **Copy the raw blob, not a checkout.** `CnPack/** -text` in `.gitattributes` keeps these
  files byte-exact, and cnvcl stores them CRLF. Something like
  `git -C cnvcl show <sha>:Source/Crypto/CnSHA2.pas > CnPack/Crypto/CnSHA2.pas` reproduces
  them exactly; a checkout through `core.autocrlf` may not.

## Re-syncing the subset when cnvcl updates

1. Pick ONE cnvcl commit and record its hash here, under "Current source".
2. Copy the units above from that commit into the fork:
   - `cnvcl/Source/Common/{CnPack.inc,CnConsts,CnFloat,CnStrings,CnWideStrings}` → `CnPack/Common/`
   - `cnvcl/Source/Crypto/{the 13 crypto units}.pas` → `CnPack/Crypto/`
   - (verify the cnvcl source-side paths — cnvcl occasionally relocates units between
     `Source/Common` and `Source/Crypto`.)
3. **Check the API DCS uses did not move.** DCS calls only `Utils/Utils.Hash.pas`'s
   `MD5*/SHA1*/SHA256*/SHA384*/SHA512*/SM3*` `Init/Update/Final` and their `TCn*Context` /
   `TCn*Digest` types. Diff those declarations old vs new.
4. **Run `tests/CnPackHashTests`**: `scripts/build-tests-fpc.sh` on FPC,
   `tests\CnPackHashTests\build-dcc.bat` on Delphi. It hashes one message in seven split
   patterns with every algorithm DCS takes from CnPack, against Python's hashlib. Run it on
   the OLD subset first: before v1.0.17 SHA-384/512 failed 6 checks (cnvcl `0d2ce92`), so
   a green run there means the test is not exercising the code.
5. **Re-validate the closure** — the only authoritative check (the CnPack sources are
   **GBK/ANSI-encoded**, which defeats `grep`-based scans): `boss install` this fork into a
   throwaway project, or build `horse-provider-crosssocket` against it, and confirm a clean
   compile with **no missing `Cn*` unit**. If the compiler reports a missing unit, copy it in
   and repeat.
6. Commit the subset change on its own (`git add -A CnPack/` so renames register), separate
   from version bumps and `.gitattributes` changes.

## No sync automation

Earlier versions of this file described a nightly GitHub Action (`.github/workflows/sync-upstream.yml`
plus `.sync/README.md`) that re-layered the subset from a hard-coded list. **Neither file is in
the fork** (checked 2026-10-09). Upstream syncs are done by hand: merge `upstream/master` with
`-X renormalize`, then confirm `git diff --ignore-cr-at-eol upstream/master -- Net Utils` lists
nothing but untracked IDE files. If automation is ever added, its file list must match the
inventory above.

## Consumer-side note

Because the foundation units live in `CnPack/Common/`, any consuming project's search path must
include **both** `CnPack/Common` **and** `CnPack/Crypto` (see the "Required search paths" list
in `horse-provider-crosssocket`'s README). Adding only `Crypto/` will fail to resolve
`CnConsts`/`CnFloat`/`CnStrings`/`CnWideStrings`.

## Don't track build/IDE artifacts

`.dcu`, `.res`, `.dproj.local`, `.dsv`, `__history/` must stay out of the repo (they bloat it
and create false "modified" churn). They are covered by `.gitignore`; if any are already
tracked, `git rm --cached` them.

## Endgame

Every source change the fork carried is now upstream (v1.0.16). What keeps the fork alive is
Boss: upstream has no `boss.json`, and CnPack has neither a `boss.json` nor a small enough
footprint to depend on. If upstream ever ships both, this fork and this subset can be retired.
