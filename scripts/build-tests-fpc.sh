#!/usr/bin/env bash
# ============================================================================
#  build-tests-fpc.sh — build + run this library's FPC unit tests.
#
#    WebSocketFrameTests  — RFC 6455 per-frame masking
#    CryptRandomTests     — the cryptographically-secure random API
#
#  Both need only this library — no network, no external server — so they are
#  the cheapest check that a change here still builds and behaves.
#
#  Building WebSocketFrameTests pulls in Net.CrossWebSocketParser ->
#  Net.CrossSocket.Base, Utils.Hash, Utils.Utils, Utils.IOUtils, CnPack and
#  DTF.StaticZLib, so a green run doubles as a compile check over most of the
#  library. Neither suite covers TLS, mTLS or the HTTP client.
#
#  Prerequisites, and why each is needed: BUILDING-FPC.md at the repo root.
#
#  Usage:
#    ./scripts/build-tests-fpc.sh              build and run both
#    ./scripts/build-tests-fpc.sh --build-only
#
#  Environment:
#    TRUNK_FPC    default /usr/local/fpc-trunk/bin/fpc
#    TRUNK_UNITS  default .../lib/fpc/3.3.1/units/x86_64-linux
# ============================================================================
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1   # repo root

BUILD_ONLY=0
[[ "${1:-}" == "--build-only" ]] && BUILD_ONLY=1

FPCBIN=${TRUNK_FPC:-/usr/local/fpc-trunk/bin/fpc}
TU=${TRUNK_UNITS:-/usr/local/fpc-trunk/lib/fpc/3.3.1/units/x86_64-linux}

# Locate the repo root by walking up for a landmark, never by counting '..' —
# that breaks the moment the script is moved or invoked from elsewhere. Note
# bash's `cd ..` is logical (it tracks $PWD through symlinks) while fpc resolves
# paths physically, so from a symlinked checkout the two disagree; [[ -d ]] uses
# the same physical resolution fpc will, which is why the probe uses it.
DCS=""; _p="."
for _ in 1 2 3 4 5 6; do
  [[ -d "$_p/Net" && -f "$_p/zLib.inc" ]] && { DCS="$_p"; break; }
  _p="$_p/.."
done
[[ -n "$DCS" ]] || {
  echo "ERROR: not inside a Delphi-Cross-Socket checkout." >&2
  echo "       Looked upward from $PWD for a directory with Net/ and zLib.inc." >&2
  exit 1
}

if [[ ! -x "$FPCBIN" ]]; then
  echo "ERROR: trunk fpc not found at $FPCBIN — set TRUNK_FPC." >&2
  exit 1
fi
if [[ ! -d "$TU/rtl" ]]; then
  echo "ERROR: TRUNK_UNITS does not look like a unit tree: $TU" >&2
  echo "       Expected $TU/rtl to exist." >&2
  exit 1
fi

# -n so /etc/fpc.cfg cannot drag in the distro 3.2.2 unit tree (that mismatch
# reports as "PPU Invalid Version 207 expecting 208", naming a unit rather than
# the config file that caused it). No -Sh: it changes the default string type
# and therefore FPC's mangled symbol names, and the link then fails with
# undefined references to symbols that are present.
# -Sc enables C-style assignment operators (+=, -=, *=, /=). Needed only by
# LazUtils: its lazutf8.pas uses them, and neither -MDelphi nor the unit's own
# mode directive turns them on, so compiling that dependency from source fails
# with "C styled assignment operators are turned off" at five sites. Lazarus
# builds LazUtils through its .lpk, which supplies the switch; a bare fpc build
# has to supply it here. Purely additive — it enables a syntax, so DCS's own
# units are unaffected.
FPCFLAGS=(-n -MDelphi -O2 -Sc
  "-Fu$DCS/Net" "-Fu$DCS/Utils" "-Fu$DCS/DelphiToFPC"
  # zLib.inc sits at the DCS root, not beside the units that {$I} it.
  "-Fi$DCS"
)
# CnPack — vendored in the fork so it is boss-installable, and Utils.Hash.pas
# uses CnMD5/CnSHA1/CnSHA2 from it directly. Absent upstream, so upstream's own
# .lpi never needed these paths.
for _c in "$DCS/CnPack/Common" "$DCS/CnPack/Crypto"; do
  [[ -d "$_c" ]] && FPCFLAGS+=("-Fu$_c")
done
# -Fi as well as -Fu: every CnPack unit opens with {$I CnPack.inc}, and that
# file sits in CnPack/Common. A unit path does not satisfy an include.
[[ -d "$DCS/CnPack/Common" ]] && FPCFLAGS+=("-Fi$DCS/CnPack/Common")

# EVERY trunk package dir, rather than a curated list.
#
# The curated approach cost three round trips here — one missing package per
# run (fcl-base, then LazUtils, then ZLib via paszlib) — because the transitive
# closure is not obvious from the source: Utils.Hash.pas has an UNGUARDED
# `ZLib` in its uses clause, where Net.CrossHttpClient.pas correctly branches
# to DTF.StaticZLib on FPC.
#
# Tradeoff, accepted deliberately: if two packages export the same unit name,
# the first match on the path wins and that choice is silent. For a small
# self-contained test build that is worth trading against another round trip;
# run-p1.sh keeps its explicit list precisely because a wrong unit there would
# corrupt a measurement rather than just fail to link.
_n=0
for _d in "$TU"/*/; do
  [[ -d "$_d" ]] && { FPCFLAGS+=("-Fu${_d%/}"); _n=$((_n + 1)); }
done

# ── LazUtils, for anything that touches Net/ ────────────────────────────────
# Utils.IOUtils has `Masks` in its uses clause (one call, MatchesMask). On
# Delphi that is System.Masks, in the RTL; on FPC it is NOT RTL at all — it
# lives in Lazarus's LazUtils. Upstream's own WebSocketFrameTests.lpi says so
# outright, listing
#   $(LazarusDir)\components\lazutils\lib\$(TargetCPU)-$(TargetOS)
# among its unit paths. So this is upstream's intended dependency, not a fork
# quirk; it only bites a bare-fpc build like this one, and it reports as
# "Can't find unit Masks used by Utils.IOUtils" — a unit name with no hint it
# belongs to a different product.
#
# CryptRandomTests is unaffected: it touches only Utils/, never Net/.
#
# SOURCE dir preferred over the prebuilt lib/: LazUtils' .ppu are built by
# whatever fpc Lazarus was installed with (typically distro 3.2.2), and mixing
# those into a trunk build gives "PPU Invalid Version 207 expecting 208".
MASKS_DIR=""
for _c in ${LAZARUS_DIR:+"$LAZARUS_DIR/components/lazutils"} \
          ${LAZARUS_DIR:+"$LAZARUS_DIR"} \
          /usr/share/lazarus/*/components/lazutils \
          /usr/lib/lazarus/*/components/lazutils \
          /usr/share/lazarus/components/lazutils \
          /usr/lib/lazarus/components/lazutils \
          /opt/lazarus/components/lazutils \
          "$HOME"/lazarus/components/lazutils; do
  if [[ -f "$_c/masks.pas" || -f "$_c/masks.pp" ]]; then MASKS_DIR="$_c"; break; fi
done
if [[ -n "$MASKS_DIR" ]]; then
  FPCFLAGS+=("-Fu$MASKS_DIR" "-Fi$MASKS_DIR")
fi

BIN="./bin"; mkdir -p "$BIN"
if [[ -z "$MASKS_DIR" ]]; then
  echo "WARNING: no 'masks' unit found — anything using Net/ will fail with" >&2
  echo "         \"Can't find unit Masks used by Utils.IOUtils\". It is a" >&2
  echo "         Lazarus LazUtils unit, not FPC RTL, and upstream's own .lpi" >&2
  echo "         depends on it. Get it with either:" >&2
  echo "           sudo apt install lazarus-src" >&2
  echo "           git clone --depth 1 https://gitlab.com/freepascal.org/lazarus/lazarus.git ~/lazarus" >&2
  echo "         then re-run (set LAZARUS_DIR=~/lazarus if you cloned)." >&2
  echo >&2
fi

echo "fpc:   $FPCBIN ($("$FPCBIN" -iV 2>/dev/null))"
echo "units: $_n trunk package dir(s) on the path"
echo "masks: ${MASKS_DIR:-<none — Net/ tests will fail>}"
echo "dcs:  $(cd "$DCS" && pwd -P)"
echo "head: $(git -C "$DCS" rev-parse --short HEAD 2>/dev/null) on $(git -C "$DCS" rev-parse --abbrev-ref HEAD 2>/dev/null)"
echo

TESTS=(
  "WebSocketFrameTests|$DCS/Net/Tests/FPC/WebSocketFrameTests/WebSocketFrameTests.lpr"
  "CryptRandomTests|$DCS/Utils/Tests/FPC/CryptRandomTests/CryptRandomTests.lpr"
)

FAILED=0
for row in "${TESTS[@]}"; do
  IFS='|' read -r NAME LPR <<< "$row"
  echo "── $NAME ────────────────────────────────────────────────"
  if [[ ! -f "$LPR" ]]; then
    echo "   SKIP — not present: $LPR"
    echo "   (If this is missing, the merge did not bring it in.)"
    continue
  fi
  # Fresh unit dir per program: FPC's .ppu cache does not account for changed
  # switches or defines, so a shared dir silently reuses incompatible units.
  UD="$BIN/units-$NAME"; rm -rf "$UD"; mkdir -p "$UD"
  if ! "$FPCBIN" "${FPCFLAGS[@]}" -FU"$UD" -o"$BIN/$NAME" "$LPR" \
        > "$BIN/$NAME.build.log" 2>&1; then
    echo "   FAILED TO BUILD — $BIN/$NAME.build.log"
    grep -E 'Fatal|Error' "$BIN/$NAME.build.log" | head -6 | sed 's/^/     | /'
    FAILED=$((FAILED + 1))
    continue
  fi
  echo "   built ok"
  [[ $BUILD_ONLY -eq 1 ]] && continue
  if "$BIN/$NAME"; then
    echo "   PASS"
  else
    echo "   FAIL (exit $?)"
    FAILED=$((FAILED + 1))
  fi
  echo
done

echo "════════════════════════════════════════════════════════════"
if [[ $FAILED -eq 0 ]]; then
  echo " both DCS unit suites OK — necessary, NOT sufficient."
  echo " Still untested by this script: TLS, mTLS, and the"
  echo " PATCH-CSHTTP-3 client retry. See BUILDING-FPC.md."
  exit 0
fi
echo " $FAILED suite(s) failed — do not fast-forward master."
exit "$FAILED"
