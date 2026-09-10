#!/usr/bin/env bash
#
# .github/scripts/verify-kernel-tarball.sh - download a kernel.org
# tarball with full cryptographic verification (issue #6 follow-up).
#
# Usage: verify-kernel-tarball.sh <version> <output-tarball-path>
#
# Downloads linux-<version>.tar.xz plus the per-series sha256sums.asc,
# PGP-verifies the sums file against kernel.org's checksum-autosigner
# key (vendored as kernel-autosigner.asc, pinned to the expected
# fingerprint), then sha256-verifies the tarball against the
# now-trusted sums entry before moving it to <output-tarball-path>.
# Any failure exits nonzero with nothing left at the output path, so
# callers can never extract an unverified tree.
#
# This is the shared implementation behind the download steps in
# .github/workflows/build-matrix.yml,
# .github/workflows/qemu-boot-test.yml, and
# tests/test_detection_qemu.sh - fix verification logic here once,
# not in three places. The flow follows kernel.org's own
# get-verified-tarball helper (gpgv GOODSIG+VALIDSIG against an
# autosigner-only keyring), minus the per-tarball developer-signature
# check, which needs each release signer's individual key and stays
# an optional hardening step.
#
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <kernel-version> <output-tarball-path>" >&2
    exit 2
fi
VERSION="$1"
OUT="$2"

# Trust anchor: kernel.org's checksum-autosigner public key, vendored
# as kernel-autosigner.asc (ASCII-armored, committed to this repo so
# verification needs no live key fetch - WKD proved too flaky for CI
# to depend on). The fingerprint pin below is what makes the file
# trustworthy rather than just present: it is only honored if it
# carries exactly this identity. If kernel.org ever rotates the
# autosigner key, replace the file AND the pin together and say so
# in the commit message.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTOSIGNER_KEY="$SCRIPT_DIR/kernel-autosigner.asc"
AUTOSIGNER_FPR="B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1"
if [ ! -f "$AUTOSIGNER_KEY" ]; then
    echo "::error::verify-kernel-tarball.sh: vendored key $AUTOSIGNER_KEY missing" >&2
    exit 1
fi

for cmd in curl gpg gpgv sha256sum awk mktemp; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "::error::verify-kernel-tarball.sh: missing required tool: $cmd" >&2
        exit 1
    fi
done

MAJOR="$(echo "$VERSION" | cut -d. -f1)"
TARBALL_BASENAME="linux-${VERSION}.tar.xz"
BASE_URL="https://cdn.kernel.org/pub/linux/kernel/v${MAJOR}.x"

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/kernel-verify.XXXXXXXXXX.untrusted")"
trap 'rm -rf "$TMPDIR"' EXIT
GNUPGHOME="$TMPDIR/gnupg"
mkdir -m 0700 "$GNUPGHOME"

gpg --batch --quiet --homedir "$GNUPGHOME" --import "$AUTOSIGNER_KEY"
if ! gpg --batch --homedir "$GNUPGHOME" --list-keys --with-colons \
        autosigner@kernel.org 2>/dev/null | grep -q "$AUTOSIGNER_FPR"; then
    echo "::error::verify-kernel-tarball.sh: vendored key does not match pinned fingerprint $AUTOSIGNER_FPR (key rotated? replace the file and the pin together)" >&2
    exit 1
fi
gpg --batch --quiet --homedir "$GNUPGHOME" \
    --export autosigner@kernel.org > "$TMPDIR/shakeyring.gpg"

# --retry/--retry-all-errors/--http1.1: kernel.org's CDN occasionally
# resets connections mid-transfer (curl exit 92) - observed directly
# in CI, not a hypothetical.
curl -fL --http1.1 --retry 5 --retry-all-errors --retry-delay 5 \
    --connect-timeout 20 -o "$TMPDIR/$TARBALL_BASENAME" \
    "$BASE_URL/$TARBALL_BASENAME"
curl -fL --http1.1 --retry 5 --retry-all-errors --retry-delay 5 \
    --connect-timeout 20 -o "$TMPDIR/sha256sums.asc" \
    "$BASE_URL/sha256sums.asc"

# gpgv's exit status alone only says "a valid signature from the
# keyring exists somewhere" - require both GOODSIG and VALIDSIG in
# the status output, same threshold kernel.org's own helper uses, so
# a revoked/expired signing key fails closed here too.
VERIFY_OUT="$(gpgv --keyring="$TMPDIR/shakeyring.gpg" --status-fd=1 \
    "$TMPDIR/sha256sums.asc" 2>"$TMPDIR/gpgv.err" || true)"
if ! printf '%s\n' "$VERIFY_OUT" | grep -q '^\[GNUPG:\] GOODSIG' || \
   ! printf '%s\n' "$VERIFY_OUT" | grep -q '^\[GNUPG:\] VALIDSIG'; then
    echo "::error::verify-kernel-tarball.sh: PGP verification of sha256sums.asc failed (not signed by pinned autosigner key)" >&2
    cat "$TMPDIR/gpgv.err" >&2 || true
    exit 1
fi

# Exact-field match, not substring grep: adjacent sums entries like
# linux-6.12.107.tar.xz.sign must never collide with the tarball row.
EXPECTED="$(awk -v f="$TARBALL_BASENAME" '$2 == f {print $1}' "$TMPDIR/sha256sums.asc")"
if [ -z "$EXPECTED" ]; then
    echo "::error::verify-kernel-tarball.sh: no sha256 entry for $TARBALL_BASENAME in sha256sums.asc" >&2
    exit 1
fi
ACTUAL="$(sha256sum "$TMPDIR/$TARBALL_BASENAME" | awk '{print $1}')"
if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "::error::verify-kernel-tarball.sh: sha256 mismatch for $TARBALL_BASENAME" >&2
    exit 1
fi

mv "$TMPDIR/$TARBALL_BASENAME" "$OUT"
trap - EXIT
rm -rf "$TMPDIR"
