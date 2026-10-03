#!/usr/bin/env bash
#
# tests/test_sensitive_proc.sh - static regression checks pinning the
# fixes for #85 (do_load() buffer sized for the longest `sensitive add`
# line; sensitive_proc_write() rejects embedded line terminators) and
# #86 (`avctl save` emits `sensitive del` lines for default entries an
# operator deleted at runtime, so those deletions survive a save ->
# module reload -> load cycle instead of silently resurrecting on the
# reseed; the kernel exposes the compile-time default set via a new
# read-only /proc/kernel_av_sensitive_defaults so save can diff).
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

# --- #86: kernel exposes compile-time defaults via a new /proc entry ---

section "#86: /proc/kernel_av_sensitive_defaults is registered RO"

# proc_create() for the defaults list has to use the exact name
# `kernel_av_sensitive_defaults` (do_save() reads it by that path) and
# mode 0400 (read-only - the entry exposes compile-time constants, no
# runtime management writes, unlike the 0600 sibling kernel_av_
# sensitive / _trusted / _protected entries). A regression that
# renamed the file, dropped the init call, or widened the mode to
# 0444/0600 would be caught here before anything insmods the module.
# The name/mode may wrap onto a second line after the `proc_create(`
# token, so lines are joined for the match (same technique the lint
# comment-stripper in .github/workflows/lint.yml uses).
BEHAVIOR_JOINED="$(tr '\n' ' ' < "$BEHAVIOR")"
if echo "$BEHAVIOR_JOINED" | \
   grep -qE 'proc_create\([[:space:]]*"kernel_av_sensitive_defaults",[[:space:]]+0400[[:space:]]*,'; then
    pass "proc_create() names the defaults file \"kernel_av_sensitive_defaults\" with mode 0400"
else
    fail "defaults proc entry is missing, misnamed, or has the wrong mode"
fi

# --- #86: do_save() reads defaults and emits del lines before adds ---

section "#86: do_save() diffs defaults vs. live and emits del before add"

SAVE_BODY="$(extract_c_func "$AVCTL" do_save)"

# The diff only works if save actually opens the defaults file. Scoped
# to do_save()'s body so the SENSITIVE_DEFAULTS_PROC_PATH macro
# definition at the top of the file does not satisfy this on its own.
if echo "$SAVE_BODY" | grep -q 'open_proc_read(SENSITIVE_DEFAULTS_PROC_PATH)'; then
    pass "do_save() reads SENSITIVE_DEFAULTS_PROC_PATH"
else
    fail "do_save() does not read SENSITIVE_DEFAULTS_PROC_PATH"
fi

# `sensitive del` MUST be printed before `sensitive add` in the dump:
# load replays sequentially against the freshly-reseeded kernel state,
# so emitting an add first and then a del of the same path would just
# undo the add. Both prints live inside do_save() so this check is
# scoped to its body, not the whole file (which also has do_sensitive()
# with its own `del` string).
DEL_LINE="$(echo "$SAVE_BODY" | grep -n '"sensitive del %s' | head -1 | cut -d: -f1)"
ADD_LINE="$(echo "$SAVE_BODY" | grep -n '"sensitive add %s' | head -1 | cut -d: -f1)"
if [ -n "$DEL_LINE" ] && [ -n "$ADD_LINE" ] && [ "$DEL_LINE" -lt "$ADD_LINE" ]; then
    pass "do_save() emits \`sensitive del\` before \`sensitive add\`"
else
    fail "do_save() emits \`sensitive del\` after (or does not emit it before) \`sensitive add\`"
fi

echo
if [ "$FAIL" -ne 0 ]; then
    echo "=== $PASS passed, $FAIL failed ==="
    exit 1
fi
echo "=== $PASS passed, 0 failed ==="
exit 0
