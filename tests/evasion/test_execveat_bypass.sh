#!/usr/bin/env bash
#
# test_execveat_bypass.sh - execveat() coverage test (post-fix
# regression, not really an "evasion" in the adversarial sense the
# other scripts in this dir test - included here because when the hook
# was a kprobe on __arm64_sys_execve alone, calling execveat() instead
# of execve() was a complete, trivial bypass of every exec-based check:
# no hash/signature match, no daemon scan, no av_behavior_record_exec()
# call at all).
#
# Since issue #94 all six cases below are covered by ONE kprobe, on the
# kernel's own exec path - bprm_execve() by preference, with
# security_bprm_check() as the fallback - which runs once the target is
# already open as bprm->file: after every flavour of path resolution has
# happened and before any binfmt loader runs. Nothing here depends on the syscall entry point, the dfd, the
# flags, or on there being a filesystem path at all any more; the hook
# hashes the bprm->file the kernel resolved. That makes these cases
# cheaper to satisfy than they were, and still worth keeping: they are
# the end-to-end proof that each resolution flavour really does reach
# that hook, and the thing that would catch the exec hook being moved
# back to a syscall probe.
#
# Technique: glibc has no execveat() wrapper, so this calls the raw
# syscall directly via syscall(SYS_execveat, ...). Covers six cases
# that mirror bugs already found and fixed elsewhere in this codebase
# for other syscalls (execve's relative-path fix, openat's dfd-ignored
# fix):
#
#   1. AT_FDCWD + absolute path       - the plain case
#   2. AT_FDCWD + relative path       - cwd resolution
#   3. real dfd + relative path       - dfd resolution (openat's bug, for exec)
#   4. memfd_create() + AT_EMPTY_PATH - fileless exec (fexecve()-style):
#      pathname is empty and dfd names the target directly, no
#      filesystem path to resolve at all. Historically the hardest case
#      here: the pathname-copying hook had nothing to open, then had an
#      AT_EMPTY_PATH special case with an empty-string sentinel to carry
#      the dfd's own struct path through. All of that is gone - a memfd
#      exec has a bprm->file like any other, so it needs no special
#      casing at all.
#   5. real dfd + non-empty relative path + AT_EMPTY_PATH set anyway -
#      per execveat(2), AT_EMPTY_PATH only changes anything when the
#      pathname is actually empty; a non-empty pathname resolves
#      exactly as it would without the flag, and that resolution
#      succeeds. Regression case for a bug the old hook briefly had:
#      treating "AT_EMPTY_PATH is set" as "trust the flag, skip
#      scanning" made the flag a free bypass for an otherwise-ordinary
#      dfd-relative exec. The current hook never reads the flag, so this
#      is now a guard against that class of mistake coming back rather
#      than against a live branch. Must be detected exactly like
#      Test 3.
#   6. real dfd + empty pathname, AT_EMPTY_PATH NOT set - the one
#      combination that's genuinely invalid: generic path resolution
#      rejects a zero-length pathname unless LOOKUP_EMPTY is set, so
#      this execveat() fails with ENOENT before executing anything.
#      Must NOT be detected/killed - there is nothing to scan.
#
# All six are real pass/fail assertions now.
#
# NEEDS THE LIVE KERNEL MODULE - run this in your VM, not standalone.
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "This script needs root to check dmesg meaningfully after the test."
	echo "Re-run with sudo."
	exit 1
fi

if [ ! -d /sys/module/av ]; then
	echo "av.ko doesn't appear to be loaded - insmod it first:"
	echo "  sudo insmod av/av.ko"
	exit 1
fi

# mktemp -d gives an unpredictable name with mode 0700 already, so a
# local attacker can't pre-create it or a symlink at this path ahead
# of us the way a fixed /tmp/execveat_test name would allow.
TESTDIR="$(mktemp -d /tmp/execveat_test.XXXXXXXX)"
trap 'rm -rf "$TESTDIR"' EXIT

PASS=0
FAIL=0

echo "=== execveat() coverage test ==="
echo

# ---- build the raw-syscall runner ----

cat >"$TESTDIR/execveat_runner.c" <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>

/* Usage: execveat_runner <dfd-path-or-"AT_FDCWD"-or-"memfd"> <pathname> <flags> */
int main(int argc, char *argv[])
{
    int dfd;
    const char *path = argv[2];
    int flags = atoi(argv[3]);
    char *av_[2] = { NULL, NULL };
    char *const ev_[1] = { NULL };

    if (!strcmp(argv[1], "AT_FDCWD")) {
        dfd = AT_FDCWD;
    } else if (!strcmp(argv[1], "memfd")) {
        /* Fileless exec: copy the EICAR file into an anonymous memfd,
         * exec it via dfd=memfd_fd, pathname="", AT_EMPTY_PATH. */
        FILE *src = fopen(path, "rb");
        char buf[256];
        size_t n;

        if (!src) { perror("fopen"); return 1; }
        dfd = syscall(SYS_memfd_create, "execveat_test", 0);
        if (dfd < 0) { perror("memfd_create"); return 1; }
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
            write(dfd, buf, n);
        fclose(src);
        path = "";
        flags |= 0x1000; /* AT_EMPTY_PATH */
    } else {
        dfd = open(argv[1], O_RDONLY | O_DIRECTORY);
        if (dfd < 0) { perror("open dfd"); return 1; }
    }

    av_[0] = (char *)path;
    syscall(SYS_execveat, dfd, path, av_, ev_, flags);
    /* Only reached if execveat itself failed. Save errno immediately -
     * perror()/stdio can clobber it as a side effect before we get to
     * use it, even on their own success paths - then exit with that
     * saved value (not just a fixed 1) so callers that need to
     * distinguish WHY it failed (e.g. confirming ENOENT rather than
     * some other error, or the helper never reaching the syscall at
     * all) can check $? for the specific errno value instead of just
     * "nonzero". */
    {
        int saved_errno = errno;
        perror("execveat");
        return saved_errno;
    }
}
EOF
gcc -o "$TESTDIR/execveat_runner" "$TESTDIR/execveat_runner.c"

# ---- shared EICAR fixture ----

# Single quotes are intentional: this string has literal $ characters
# that must NOT be shell-expanded (with set -u active, an unquoted/
# double-quoted $EICAR here is an unbound-variable error, not just a
# wrong-content bug) - same reasoning as tests/test_detection.sh's
# identical EICAR fixture.
# shellcheck disable=SC2016
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' >"$TESTDIR/eicar.com"
chmod +x "$TESTDIR/eicar.com"

# av_kill()'s log format is structured key=value (see main.c's
# v1.0.0-merge comment): "event=detected action=kill type=...
# path="...". Match on that instead of the old free-form
# 'DETECTED "..."' sentence format, which this check predates and no
# longer appears anywhere in the module.
check_detected() {
	local expect_path="$1"
	if dmesg | tail -20 | grep -q "event=detected.*action=kill.*path=\"$expect_path\""; then
		return 0
	fi
	return 1
}

# ---- Test 1: AT_FDCWD + absolute path ----

echo "-- Test 1: AT_FDCWD + absolute path --"
dmesg -C
"$TESTDIR/execveat_runner" AT_FDCWD "$TESTDIR/eicar.com" 0 || true
sleep 1
if check_detected "$TESTDIR/eicar.com"; then
	echo "PASS: detected via AT_FDCWD + absolute path"
	PASS=$((PASS + 1))
else
	echo "FAIL: no detection - check the exec kprobe registered at all"
	echo "      first: dmesg logs 'exec hook registered on <symbol>' at"
	echo "      insmod, and the symbol it names should appear in"
	echo "      /sys/kernel/debug/kprobes/list. av.ko tries bprm_execve"
	echo "      first and security_bprm_check as a fallback."
	FAIL=$((FAIL + 1))
fi
echo

# ---- Test 2: AT_FDCWD + relative path ----

echo "-- Test 2: AT_FDCWD + relative path --"
dmesg -C
# Status intentionally ignored: a detection kill exits nonzero, and the
# verdict comes from check_detected() below, not this exit status.
# (An if rather than `A && B || true` - that is not if-then-else.)
if (cd "$TESTDIR" && "$TESTDIR/execveat_runner" AT_FDCWD eicar.com 0); then
	:
fi
sleep 1
if check_detected "$TESTDIR/eicar.com"; then
	echo "PASS: relative path resolved against cwd correctly"
	PASS=$((PASS + 1))
else
	echo "FAIL: relative path not resolved (or logged under the wrong name) -"
	echo "      the hook hashes bprm->file, so resolution itself cannot be wrong"
	echo "      here; check av_work_fn()'s d_path() of aw->file->f_path instead"
	FAIL=$((FAIL + 1))
fi
echo

# ---- Test 3: real dfd + relative path ----

echo "-- Test 3: real dfd + relative path --"
mkdir -p "$TESTDIR/subdir"
cp "$TESTDIR/eicar.com" "$TESTDIR/subdir/eicar.com"
dmesg -C
"$TESTDIR/execveat_runner" "$TESTDIR/subdir" eicar.com 0 || true
sleep 1
if check_detected "$TESTDIR/subdir/eicar.com"; then
	echo "PASS: dfd-relative path resolved correctly"
	PASS=$((PASS + 1))
else
	echo "FAIL: a dfd-relative exec reached no verdict. Since #94 the hook"
	echo "      cannot mishandle a dfd (it never sees one) - so either the"
	echo "      probed exec function was not reached, or the work item was"
	echo "      dropped; check dmesg for an av_work_admit() cap or a hash error"
	FAIL=$((FAIL + 1))
fi
echo

# ---- Test 4: memfd + AT_EMPTY_PATH (fileless exec) ----

echo "-- Test 4: memfd + AT_EMPTY_PATH (fileless exec) --"
dmesg -C
"$TESTDIR/execveat_runner" memfd "$TESTDIR/eicar.com" 0 || true
sleep 1
# An anonymous memfd has no real dentry in any mounted filesystem, so
# d_path() reports it the same way the kernel always names memfds:
# "/memfd:<name> (deleted)" (the name given to memfd_create(), plus
# the same "(deleted)" suffix d_path() appends for any unlinked-but-
# still-open file). That is not a bug or a loose match - it is the
# correct, expected representation of a fileless exec target.
if dmesg | tail -10 | grep -q 'event=detected.*action=kill.*path="/memfd:execveat_test'; then
	echo "PASS: fileless exec (memfd + AT_EMPTY_PATH) detected and killed"
	PASS=$((PASS + 1))
else
	echo "FAIL: fileless exec (memfd + AT_EMPTY_PATH) was not detected. The"
	echo "      hook needs no special case for this - a memfd exec has a"
	echo "      bprm->file like any other - so suspect d_path() on an anonymous"
	echo "      dentry, or the exec never reaching the probed function"
	dmesg | tail -10
	FAIL=$((FAIL + 1))
fi
echo

# ---- Test 5: real dfd + non-empty relative path + AT_EMPTY_PATH set anyway ----

# 0x1000 = AT_EMPTY_PATH. Setting it here does NOT make the pathname
# argument optional/ignored - execveat(2) only special-cases an empty
# pathname. With a non-empty pathname the flag is inert and resolution
# proceeds exactly like Test 3 (relative to dfd), so this must still
# be detected. A hook that trusts the flag alone and skips scanning
# whenever it's set would silently miss this.
echo "-- Test 5: real dfd + relative path + AT_EMPTY_PATH set anyway --"
dmesg -C
"$TESTDIR/execveat_runner" "$TESTDIR/subdir" eicar.com 4096 || true
sleep 1
if check_detected "$TESTDIR/subdir/eicar.com"; then
	echo "PASS: AT_EMPTY_PATH + non-empty path still resolved/detected normally"
	PASS=$((PASS + 1))
else
	echo "FAIL: AT_EMPTY_PATH + non-empty path was NOT detected. The current"
	echo "      hook does not read execveat() flags at all, so if this fails"
	echo "      something has reintroduced flag-dependent logic on the exec path"
	FAIL=$((FAIL + 1))
fi
echo

# ---- Test 6: real dfd + empty pathname, AT_EMPTY_PATH NOT set ----

# Without AT_EMPTY_PATH, an empty pathname is invalid (ENOENT) - the
# syscall fails before executing anything, so no kill event should
# ever appear for it. Absence of a kill event alone doesn't prove
# that, though - the helper could have died before ever reaching the
# syscall, or the syscall could have unexpectedly succeeded without
# being detected.
# execveat_runner exits with errno itself on failure (see the C source
# above), so assert the specific failure this case requires: ENOENT
# (value 2 on Linux - see errno-base.h), not just "something nonzero".
echo "-- Test 6: real dfd + empty path, AT_EMPTY_PATH NOT set --"
dmesg -C
rc=0
"$TESTDIR/execveat_runner" "$TESTDIR/subdir" "" 0 || rc=$?
sleep 1
ENOENT=2
if [ "$rc" -ne "$ENOENT" ]; then
	echo "FAIL: execveat_runner exited $rc, expected ENOENT ($ENOENT) - either it never"
	echo "      reached the syscall, or the syscall didn't fail the way this case requires"
	FAIL=$((FAIL + 1))
elif dmesg | tail -10 | grep -q 'event=detected.*action=kill'; then
	echo "FAIL: a kill event fired for a syscall that should have failed with ENOENT -"
	echo "      path resolution rejected the empty pathname, so the exec never"
	echo "      reached the probed exec function and nothing should have been scanned"
	dmesg | tail -10
	FAIL=$((FAIL + 1))
else
	echo "PASS: execveat() failed with ENOENT as expected, and no kill event fired"
	PASS=$((PASS + 1))
fi
echo

# ---- summary ----
# (cleanup of $TESTDIR happens via the EXIT trap set above)

echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
exit 0
