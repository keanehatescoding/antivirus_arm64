#!/usr/bin/env bash
#
# tests/test_sensitive_proc.sh - static regression checks pinning the
# fixes for #85 (do_load() buffer sized for the longest `sensitive add`
# line; sensitive_proc_write() rejects embedded line terminators).
# Extended by #86 (`avctl save` emits `sensitive del` lines so
# default-entry deletions survive a save -> module reload -> load
# cycle) once that lands.
#
# Pure source-level greps, so unlike most of tests/ this needs no
# root, no ARM64 VM, and no loaded module:
#   tests/test_sensitive_proc.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BEHAVIOR="$REPO_ROOT/av/behavior.c"
AVCTL="$REPO_ROOT/userspace/avctl/avctl.c"

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

section() { echo; echo "== $1 =="; }

# Scoped extraction: every functional assertion below runs against the
# extracted body of the exact function it pins - never the whole file -
# so a matching token elsewhere in the file cannot mask a regression
# at the real site (same convention as test_regression_10_14.sh).
extract_c_func() { # $1 = file, $2 = function name (defined at column 0)
    awk -v fn="$2" '$0 ~ "^static .* " fn "\\(" {in_body=1} in_body{print} in_body && /^}/{exit}' "$1"
}

# --- #85: do_load() can read every line do_save() emits ---

section "#85: do_load() buffer fits the longest sensitive save line"

LOAD_BODY="$(extract_c_func "$AVCTL" do_load)"

# The emitted worst case is "sensitive add substring " (24) + a path up
# to PATH_MAX-1 (kernel accepts rest_len < PATH_MAX in sensitive_proc_
# write) + "\n" = 4120 bytes. do_load()'s buffer must store that whole
# line in one fgets() read; PATH_MAX+32 (= 4128) is the matching ceiling
# SENSITIVE_WRITE_MAXLEN uses on the kernel side. The old PATH_MAX+16
# buffer (4112, fgets usable 4111) truncated substring paths >= 4087
# bytes and prefix paths >= 4090 bytes, which the truncation guard
# then dropped as "line too long".
if echo "$LOAD_BODY" | grep -qE 'char line\[PATH_MAX \+ (3[2-9]|[4-9][0-9]|[1-9][0-9]{2,})\];'; then
    pass "do_load() line buffer is at least PATH_MAX + 32"
else
    fail "do_load() line buffer is still too small for the longest sensitive save line"
fi

if echo "$LOAD_BODY" | grep -q 'char line\[PATH_MAX + 16\];'; then
    fail "regressed: do_load() still has the undersized PATH_MAX+16 buffer"
else
    pass "no undersized PATH_MAX+16 buffer remains"
fi

# --- #85: sensitive_proc_write() rejects embedded \n / \r ---

section "#85: sensitive_proc_write() rejects embedded line terminators"

SPW_BODY="$(extract_c_func "$BEHAVIOR" sensitive_proc_write)"

# strchr(rest, '\n') / strchr(rest, '\r') together cover both standalone
# \n and bare \r. The embedded-NUL guard above the strip is already in
# place via memchr(); this is the parallel guard for the other line
# terminators, which otherwise survive into av_behavior_sensitive_add()
# and come back out of sensitive_proc_show() as a multi-line entry that
# avctl save's per-line sscanf then silently truncates.
if echo "$SPW_BODY" | grep -q "strchr(rest, '\\\\n')" && \
   echo "$SPW_BODY" | grep -q "strchr(rest, '\\\\r')"; then
    pass "sensitive_proc_write() rejects embedded \\n and \\r in rest"
else
    fail "sensitive_proc_write() does not reject embedded line terminators"
fi

# The reject must happen BEFORE the add/del branch dispatches: an
# embedded \n in path has to short-circuit to -EINVAL rather than reach
# strscpy()/av_behavior_sensitive_add().
STRCHR_LINE="$(echo "$SPW_BODY" | grep -n "strchr(rest, '\\\\n')" | head -1 | cut -d: -f1)"
ADD_BRANCH_LINE="$(echo "$SPW_BODY" | grep -n '!strcasecmp(cmd, "add")' | head -1 | cut -d: -f1)"
if [ -n "$STRCHR_LINE" ] && [ -n "$ADD_BRANCH_LINE" ] && [ "$STRCHR_LINE" -lt "$ADD_BRANCH_LINE" ]; then
    pass "embedded-terminator reject precedes the add/del dispatch"
else
    fail "embedded-terminator reject is not positioned before add/del"
fi

echo
if [ "$FAIL" -ne 0 ]; then
    echo "=== $PASS passed, $FAIL failed ==="
    exit 1
fi
echo "=== $PASS passed, 0 failed ==="
exit 0
