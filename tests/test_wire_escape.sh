#!/usr/bin/env bash
#
# tests/test_wire_escape.sh - round-trip tests for the control-protocol
# percent-escaping in userspace/avd/wire_escape.h (issues #59, #64
# item 2): tab/newline-containing filenames must survive the
# tab/newline-framed VERDICTS/QUARANTINE rows and the quarantine
# sidecar without shifting fields, injecting rows, or truncating on
# restore.
#
# Pure userspace, no kernel module or root needed - safe to run
# standalone, same as test_sha256.sh:
#   tests/test_wire_escape.sh
#
# The C harness below pins wire_escape()/wire_unescape(); the Python
# section pins the GUI's mirror decoder (unescape_field in
# userspace/av-gui/av_gui/avd_client.py) against the same vectors, so
# the two implementations cannot drift apart silently.
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AVD_DIR="$REPO_ROOT/userspace/avd"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_wire_escape.XXXXXX")" || exit 1

cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

cat > "$BUILD_DIR/escape_test.c" <<'EOF'
/* Round-trip checks for wire_escape.h - built and run by
 * tests/test_wire_escape.sh only, not part of the shipped binaries. */
#include <stdio.h>
#include <string.h>
#include "wire_escape.h"

static int PASS, FAIL;

static void check_escape(const char *label, const char *in,
                         const char *expected) {
  char out[4096];
  if (wire_escape(in, out, sizeof(out)) != 0 || strcmp(out, expected)) {
    printf("FAIL escape %s: got \"%s\", want \"%s\"\n", label, out, expected);
    FAIL++;
  } else {
    PASS++;
  }
}

static void check_unescape(const char *label, const char *in,
                           const char *expected) {
  char buf[4096];
  snprintf(buf, sizeof(buf), "%s", in);
  wire_unescape(buf);
  if (strcmp(buf, expected)) {
    printf("FAIL unescape %s: got \"%s\", want \"%s\"\n", label, buf,
           expected);
    FAIL++;
  } else {
    PASS++;
  }
}

static void check_roundtrip(const char *label, const unsigned char *data,
                            size_t len) {
  /* NUL cannot appear in a C string field - every other byte value
   * must survive escape -> unescape byte-identically. */
  char in[512], esc[2048], back[2048];
  if (len >= sizeof(in))
    return;
  memcpy(in, data, len);
  in[len] = '\0';
  if (wire_escape(in, esc, sizeof(esc)) != 0) {
    printf("FAIL roundtrip %s: escape truncated\n", label);
    FAIL++;
    return;
  }
  snprintf(back, sizeof(back), "%s", esc);
  wire_unescape(back);
  if (memcmp(back, in, len + 1)) {
    printf("FAIL roundtrip %s: mismatch\n", label);
    FAIL++;
  } else {
    PASS++;
  }
}

int main(void) {
  /* Ordinary paths are byte-identical on the wire (backward
   * compatible with pre-escape rows/sidecars). */
  check_escape("plain", "/var/lib/av-quarantine/1_2_eicar.quarantined",
               "/var/lib/av-quarantine/1_2_eicar.quarantined");
  check_escape("empty", "", "");
  check_escape("spaces", "a b/c.d-e_f", "a b/c.d-e_f");
  /* High bytes pass through literally (no UTF-8 interaction). */
  check_escape("high-bytes", "\xc3\xa9\x80\xff", "\xc3\xa9\x80\xff");

  /* The actual attack bytes from #59. */
  check_escape("tab", "evil\tx", "evil%09x");
  check_escape("newline", "evil\nfake-row", "evil%0Afake-row");
  check_escape("cr", "evil\rx", "evil%0Dx");
  check_escape("del", "evil\x7fx", "evil%7Fx");
  check_escape("ctrl", "\x01\x02", "%01%02");
  check_escape("percent", "100% cover", "100%25 cover");
  /* A literal "%09" in a real name must NOT become a tab. */
  check_escape("literal-triplet", "100%09 cover", "100%2509 cover");

  /* Decode side: exact triplets (either hex case), lenient rest. */
  check_unescape("basic", "evil%09x", "evil\tx");
  check_unescape("lower-hex", "evil%0ax", "evil\nx");
  check_unescape("percent", "100%25 cover", "100% cover");
  check_unescape("bare-percent", "100%", "100%");
  check_unescape("short-triplet", "a%2", "a%2");
  check_unescape("bad-hex", "%ZZ", "%ZZ");
  check_unescape("space-hex", "% 1", "% 1");
  check_unescape("empty", "", "");

  /* Exhaustive round-trip over every encodable byte value. */
  {
    unsigned char all[255];
    int i;
    for (i = 1; i <= 255; i++)
      all[i - 1] = (unsigned char)i;
    check_roundtrip("all-bytes-1..255", all, sizeof(all));
  }
  check_roundtrip("hostile-name",
                  (const unsigned char *)"12_3\tevil\nrow\x01%100",
                  strlen("12_3\tevil\nrow\x01%100"));

  /* Truncation fails closed, never emits a partial triplet. */
  {
    char tiny[4];
    if (wire_escape("a\tb", tiny, sizeof(tiny)) == 0) {
      printf("FAIL truncation: expected -1 for undersized dst\n");
      FAIL++;
    } else {
      PASS++;
    }
  }

  printf("wire_escape: %d passed, %d failed\n", PASS, FAIL);
  return FAIL != 0;
}
EOF

if ! gcc -Wall -Wextra -Werror -I "$AVD_DIR" -o "$BUILD_DIR/escape_test" \
    "$BUILD_DIR/escape_test.c"; then
    echo "FAIL: could not build C escape harness"
    exit 1
fi
if ! "$BUILD_DIR/escape_test"; then
    exit 1
fi

# Python mirror decoder pinned to the same vectors: the escaped forms
# below are the exact C outputs asserted above, so any C/Python drift
# fails loudly here.
PYTHONPATH="$REPO_ROOT/userspace/av-gui" python3 - <<'EOF'
import sys
from av_gui.avd_client import unescape_field

vectors = [
    ("/var/lib/av-quarantine/1_2_eicar.quarantined",
     "/var/lib/av-quarantine/1_2_eicar.quarantined"),
    ("", ""),
    ("evil%09x", "evil\tx"),
    ("evil%0Afake-row", "evil\nfake-row"),
    ("evil%0Dx", "evil\rx"),
    ("evil%7Fx", "evil\x7fx"),
    ("%01%02", "\x01\x02"),
    ("100%25 cover", "100% cover"),
    ("100%2509 cover", "100%09 cover"),
    ("100%", "100%"),
    ("a%2", "a%2"),
    ("%ZZ", "%ZZ"),
    ("% 1", "% 1"),
]
failed = 0
for escaped, want in vectors:
    got = unescape_field(escaped)
    if got != want:
        print(f"FAIL python unescape {escaped!r}: got {got!r}, want {want!r}")
        failed += 1
if failed:
    sys.exit(1)
print(f"python unescape: {len(vectors)} passed, 0 failed")
EOF
