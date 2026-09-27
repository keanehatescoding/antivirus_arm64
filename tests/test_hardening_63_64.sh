#!/usr/bin/env bash
#
# tests/test_hardening_63_64.sh - static regression checks pinning the
# fixes for #63 (behavior_gc_fn() two-pass sweep: no single
# behavior_lock hold across the whole table, with intra-bucket resume
# so overfull bucket tails are eventually sampled) and the remaining #64
# items (item 1: quarantine link/copy/chmod/cleanup/sidecar creation
# through a pinned dirfd;
# item 3: netlink_chan.c UNTESTED banner refresh; item 4: fanotify
# exec-gate counters in STATUS). #64 item 2 (sidecar escaping) already
# landed with its own coverage in tests/test_wire_escape.sh via #68.
#
# Pure source-level greps, so unlike most of tests/ this needs no
# root, no ARM64 VM, and no loaded module:
#   tests/test_hardening_63_64.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BEHAVIOR="$REPO_ROOT/av/behavior.c"
NETLINK_CHAN="$REPO_ROOT/av/netlink_chan.c"
AVD="$REPO_ROOT/userspace/avd/avd.c"
AVD_CLIENT="$REPO_ROOT/userspace/av-gui/av_gui/avd_client.py"
PROTO_DOC="$REPO_ROOT/docs/avd-socket-protocol.md"

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

# --- #63: two-pass sweep, lock released before liveness ---

section "#63: behavior_gc_fn() two-pass sweep"

GC_BODY="$(extract_c_func "$BEHAVIOR" behavior_gc_fn)"

if echo "$GC_BODY" | grep -q "BEHAVIOR_GC_BATCH"; then
    pass "sweep samples in bounded BEHAVIOR_GC_BATCH batches"
else
    fail "BEHAVIOR_GC_BATCH batching missing from behavior_gc_fn()"
fi

# Structural pin of the actual fix: the first mutex_unlock must come
# before the first find_vpid - i.e. liveness is probed with the lock
# dropped, not inside one table-wide critical section.
FIRST_UNLOCK="$(echo "$GC_BODY" | grep -n "mutex_unlock(&behavior_lock)" | head -1 | cut -d: -f1)"
FIRST_LIVENESS="$(echo "$GC_BODY" | grep -n "find_vpid" | head -1 | cut -d: -f1)"
if [ -n "$FIRST_UNLOCK" ] && [ -n "$FIRST_LIVENESS" ] && [ "$FIRST_UNLOCK" -lt "$FIRST_LIVENESS" ]; then
    pass "liveness probe runs after the lock is dropped (two-pass)"
else
    fail "behavior_gc_fn() still probes liveness under a held lock"
fi

if echo "$GC_BODY" | grep -q "start_time == samples"; then
    pass "pass-3 re-verifies pid/start_time before acting"
else
    fail "pass-3 sample revalidation missing from behavior_gc_fn()"
fi

if echo "$GC_BODY" | grep -q "behavior_table_count -= removed"; then
    fail "old single-sweep count epilogue still present"
else
    pass "no single-sweep count epilogue (per-delete accounting)"
fi

# A batch that fills mid-bucket must resume inside that same bucket
# next batch: without an intra-bucket cursor the outer loop advances
# past the bucket's unsampled tail, and every later sweep samples the
# same first BEHAVIOR_GC_BATCH entries - dead entries past them are
# never reclaimed and pin behavior_table_count toward eviction.
if echo "$GC_BODY" | grep -q "cut_short"; then
    pass "sweep resumes inside a partially sampled bucket (no tail skip)"
else
    fail "no intra-bucket resume in behavior_gc_fn() - overfull bucket tails starve"
fi

# --- #64 item 1: quarantine link through a pinned dirfd ---

section "#64 item 1: quarantine creation through pinned dirfd"

QFILE_BODY="$(extract_c_func "$AVD" quarantine_file)"

if echo "$QFILE_BODY" | grep -q "open_quarantine_dir()"; then
    pass "quarantine_file() opens the quarantine dir pinned"
else
    fail "quarantine_file() does not use open_quarantine_dir()"
fi

if echo "$QFILE_BODY" | grep -q 'linkat(fd, "", qdirfd, name, AT_EMPTY_PATH)'; then
    pass "linkat() goes through the pinned dirfd"
else
    fail "linkat() does not go through the pinned dirfd"
fi

if echo "$QFILE_BODY" | grep -qE '(linkat|openat|fchmodat|unlinkat)\([^;]*AT_FDCWD'; then
    fail "quarantine_file() still resolves paths via AT_FDCWD"
else
    pass "no AT_FDCWD path resolution in quarantine_file()"
fi

# The linkat() check above pins only the fast path: the copy
# fallback, the lockdown chmod, and the chmod-failure cleanup must
# stay dirfd-relative too, or a regression in any of them passes
# while linkat() is unchanged. (The original's unlink(path) and the
# restore/delete/list paths are intentionally path-based and are NOT
# covered here - see quarantine_file()'s own comment.)
if echo "$QFILE_BODY" | grep -q "copy_fd_to_at(fd, qdirfd, name)"; then
    pass "copy fallback receives the pinned dirfd"
else
    fail "quarantine_file() does not pass qdirfd to copy_fd_to_at()"
fi

if echo "$QFILE_BODY" | grep -q "fchmodat(qdirfd, name,"; then
    pass "chmod goes through the pinned dirfd"
else
    fail "fchmodat() does not go through the pinned dirfd"
fi

if echo "$QFILE_BODY" | grep -q "unlinkat(qdirfd, name, 0)"; then
    pass "chmod-failure cleanup goes through the pinned dirfd"
else
    fail "cleanup unlinkat() does not go through the pinned dirfd"
fi

COPY_BODY="$(extract_c_func "$AVD" copy_fd_to_at)"

if echo "$COPY_BODY" | grep -q "openat(dirfd, name,"; then
    pass "copy fallback creates through the pinned dirfd"
else
    fail "copy_fd_to_at() does not openat() through the pinned dirfd"
fi

if echo "$COPY_BODY" | grep -q "unlinkat(dirfd, name, 0)"; then
    pass "copy fallback cleans up through the pinned dirfd"
else
    fail "copy_fd_to_at() does not unlinkat() through the pinned dirfd"
fi

# Content and sidecar must land in the same directory object: a
# path-based sidecar could be created in a replacement directory (or
# fail) while the content stays pinned, leaving an unrestorable entry.
META_BODY="$(extract_c_func "$AVD" write_quarantine_meta)"

if echo "$META_BODY" | grep -q "openat(qdirfd, meta_name,"; then
    pass "sidecar is created through the pinned dirfd"
else
    fail "write_quarantine_meta() does not openat() through the pinned dirfd"
fi

# --- #64 item 3: stale UNTESTED banner gone ---

section "#64 item 3: netlink_chan.c banner"

if grep -q "UNTESTED" "$NETLINK_CHAN"; then
    fail "UNTESTED banner still present in netlink_chan.c"
else
    pass "UNTESTED banner removed"
fi

if grep -q "7\.1\.4" "$NETLINK_CHAN"; then
    fail "stale 7.1.4 version list still in netlink_chan.c"
else
    pass "no stale hardcoded kernel versions in banner"
fi

if grep -q "kernel-versions.json" "$NETLINK_CHAN"; then
    pass "banner points at .github/kernel-versions.json"
else
    fail "banner does not reference .github/kernel-versions.json"
fi

# --- #64 item 4: fanotify counters in STATUS ---

section "#64 item 4: fanotify counters visible in STATUS"

STATUS_BODY="$(extract_c_func "$AVD" cmd_status)"

for counter in fanexec_allowed fanexec_denied fanexec_undecided fanexec_overflows; do
    if echo "$STATUS_BODY" | grep -q "$counter"; then
        pass "cmd_status() reports $counter"
    else
        fail "cmd_status() does not report $counter"
    fi
done

if grep -q "fanexec_overflows" "$AVD_CLIENT" && grep -q "fanexec_allowed" "$AVD_CLIENT"; then
    pass "GUI status() accepts the fanotify counter fields"
else
    fail "GUI status() missing fanotify counter fields"
fi

if grep -q "fanexec_overflows" "$PROTO_DOC"; then
    pass "socket protocol doc documents the fanotify fields"
else
    fail "socket protocol doc missing fanotify fields"
fi

echo
echo "test_hardening_63_64.sh: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
