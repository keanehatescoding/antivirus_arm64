#!/usr/bin/env bash
#
# tests/test_fanotify_exec_gate.sh - covers the fanotify exec gate that
# closes issue #2's two exec-time gaps (discussion #33, option C):
# avd's fanexec_* block in userspace/avd/avd.c.
#
# Two parts, deliberately separate because they cover different things:
#
#   1. STATIC invariants on avd's integration. The single property the
#      whole redesign rests on is "the exec verdict is computed from
#      the file object the kernel resolved, never from a pathname we
#      re-opened ourselves". That is a source-level invariant, so it is
#      pinned like one - same approach as test_regression_10_14.sh. No
#      root, no VM, no module.
#
#   2. LIVE mechanism checks (tests/fanotify_exec_gate.c), which
#      actually exercise FAN_OPEN_EXEC_PERM against a real kernel with
#      the same flags and call sequence avd uses, including a
#      deterministic rename-swap that demonstrates #2's gap 1 and its
#      fix side by side. Needs root, so this half self-elevates via
#      pkexec exactly as tests/run_all.sh does.
#
# WHAT THIS DOES NOT COVER, stated up front because #34's lesson here
# was that a quiet gap is worse than a loud one: neither half runs avd
# itself with the gate switched on. avd refuses to start without the av
# kernel module, which is arm64-only, so the integrated path cannot be
# exercised on an ordinary development host at all. Part 1 pins the
# integration's shape and part 2 proves the mechanism it sits on; the
# seam between them - avd's own event loop, wired end to end - belongs
# to the QEMU boot job, where there is a real kernel with av.ko loaded.
# That case lives in tests/qemu-boot/init.c (issue #48), and several
# checks here exist only because it found the corresponding bug: a
# static check is cheap to run on every commit, a VM boot is not.
#
# Usage:
#   tests/test_fanotify_exec_gate.sh
#   AV_FANOTIFY_LIVE_REQUIRED=1 tests/test_fanotify_exec_gate.sh   # CI
#
# AV_FANOTIFY_LIVE_REQUIRED=1 turns a skipped live half - no root, or a
# kernel without CONFIG_FANOTIFY_ACCESS_PERMISSIONS - from a loud
# warning into a failure, for any caller that is supposed to be able to
# run it and wants to know if it silently stopped doing so. Without it
# those two cases skip loudly and a genuinely failing harness still
# fails: an unsupported kernel is not evidence about avd's code, but a
# harness that ran and disagreed is.
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AVD="$REPO_ROOT/userspace/avd/avd.c"
LIVE_REQUIRED="${AV_FANOTIFY_LIVE_REQUIRED:-0}"

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
section() { echo; echo "== $1 =="; }

# Same scoped-extraction discipline as test_regression_10_14.sh: every
# assertion runs against the body of the exact function it pins, never
# the whole file, so a matching token elsewhere cannot mask a
# regression at the real site.
extract_c_func() { # $1 = file, $2 = function name
    awk -v fn="$2" 'index($0, fn "(") && /^static/ {in_body=1} in_body{print} in_body && /^}/{exit}' "$1"
}

# Comments are stripped before any assertion runs. This is not
# tidiness: this file's functions are heavily commented and several
# comments legitimately name the very tokens being asserted on (they
# explain why FAN_CLASS_NOTIF is wrong, and why handle_scan_request()'s
# open(path) is what we are moving away from). Without stripping, a
# "must not contain" check false-positives on prose, and - worse - a
# "must contain" check could pass on a comment while the code that was
# supposed to do the thing had been deleted.
strip_c_comments() {
    awk '
    {
        line = $0; out = ""
        while (length(line) > 0) {
            if (in_c) {
                idx = index(line, "*/")
                if (idx == 0) { line = "" }
                else { line = substr(line, idx + 2); in_c = 0 }
            } else {
                idx = index(line, "/*")
                if (idx == 0) { out = out line; line = "" }
                else { out = out substr(line, 1, idx - 1); line = substr(line, idx + 2); in_c = 1 }
            }
        }
        sub(/\/\/.*/, "", out)
        print out
    }'
}

# --- part 1: the invariant that is the entire point of the redesign ---

section "#2: the exec verdict comes from the kernel's fd, not a re-opened path"

HANDLE_BODY="$(extract_c_func "$AVD" fanexec_handle_event | strip_c_comments)"

if [ -z "$HANDLE_BODY" ]; then
    fail "fanexec_handle_event() not found in avd.c - the gate is gone?"
else
    if grep -q 'perform_scan(md->fd,' <<<"$HANDLE_BODY"; then
        pass "fanexec_handle_event() scans the event fd the kernel supplied"
    else
        fail "fanexec_handle_event() no longer feeds perform_scan() the event fd"
    fi

    # The regression this guards against is the exec verdict drifting
    # back onto a self-resolved pathname - which is exactly what
    # av_work_fn()'s open_exec_target() does and what #2 is about. A
    # bare open()/openat() of the recovered path here would silently
    # reintroduce gap 1 while every other test kept passing.
    if grep -qE '\<open(at)?\(' <<<"$HANDLE_BODY"; then
        fail "fanexec_handle_event() re-opens a path - gap 1 (TOCTOU) is back"
    else
        pass "fanexec_handle_event() never re-opens a path (no second inode to swap)"
    fi

    # perform_scan() fails OPEN on a YARA timeout, a failed rewind and
    # a failed hash: the verdict stays CLEAN even though nothing was
    # concluded. A fail-closed gate that only looks at `verdict` would
    # therefore allow exactly the execs it was turned on to stop, and
    # an attacker who can make a scan time out would have a reliable
    # way to reach that. The handler has to consult the incomplete
    # flag, not just the verdict.
    if grep -q 'result.incomplete' <<<"$HANDLE_BODY"; then
        pass "an incomplete scan is distinguished from a clean one"
    else
        fail "handler trusts CLEAN alone - a timed-out scan reads as a pass"
    fi
    # Blank lines first: strip_c_comments blanks comment lines rather
    # than deleting them, so a -A window on the raw body lands inside
    # the comment instead of on the code under it.
    HANDLE_CODE="$(grep -v '^[[:space:]]*$' <<<"$HANDLE_BODY")"
    if grep -A3 'result.incomplete' <<<"$HANDLE_CODE" \
        | grep -q 'fanexec_fail_closed ? FAN_DENY : FAN_ALLOW'; then
        pass "AVD_FANOTIFY_FAIL_CLOSED governs incomplete scans, as documented"
    else
        fail "incomplete scans ignore AVD_FANOTIFY_FAIL_CLOSED"
    fi
    # Both no-verdict paths - "cannot scan this" and "did not finish
    # scanning" - must consult the flag, not just whichever one was
    # written first.
    if [ "$(grep -c 'fanexec_fail_closed ? FAN_DENY : FAN_ALLOW' <<<"$HANDLE_CODE")" -ge 2 ]; then
        pass "every no-verdict path in the handler honours fail-closed"
    else
        fail "only one no-verdict path honours fail-closed - the other silently allows"
    fi

    if grep -q 'getpid()' <<<"$HANDLE_BODY"; then
        pass "self-originated execs are filtered (listener self-deadlock guard)"
    else
        fail "no self-pid filter in fanexec_handle_event() - avd can wedge itself"
    fi

    if grep -q 'FAN_DENY' <<<"$HANDLE_BODY" && grep -q 'FAN_ALLOW' <<<"$HANDLE_BODY"; then
        pass "both FAN_ALLOW and FAN_DENY are reachable verdicts"
    else
        fail "fanexec_handle_event() cannot both allow and deny"
    fi
fi

section "#2: the gate asks the kernel for a class that can actually deny"

INIT_BODY="$(extract_c_func "$AVD" fanexec_init | strip_c_comments)"

if [ -z "$INIT_BODY" ]; then
    fail "fanexec_init() not found in avd.c"
else
    # FAN_CLASS_NOTIF can watch execs but can never refuse one, so this
    # is not a style preference: the wrong class turns the gate into a
    # logger that reports "denied" and blocks nothing. (There is no
    # FAN_CLASS_PERM, despite #33's original writeup naming one.)
    if grep -q 'FAN_CLASS_CONTENT' <<<"$INIT_BODY"; then
        pass "fanotify_init() asks for a permission-capable class"
    else
        fail "fanotify_init() is not using FAN_CLASS_CONTENT - it cannot deny"
    fi
    if grep -q 'FAN_CLASS_NOTIF' <<<"$INIT_BODY"; then
        fail "fanotify_init() uses FAN_CLASS_NOTIF, which can only observe"
    else
        pass "no notify-only class in fanexec_init()"
    fi
    if grep -q 'FAN_OPEN_EXEC_PERM' <<<"$INIT_BODY"; then
        pass "the mark requests FAN_OPEN_EXEC_PERM"
    else
        fail "fanexec_init() does not mark for FAN_OPEN_EXEC_PERM"
    fi
    # A mark scope default would mean an upgrade could silently start
    # suspending every exec on a machine until avd answered.
    if grep -q 'AVD_FANOTIFY_MARK' <<<"$INIT_BODY"; then
        pass "mark scope is operator-supplied (AVD_FANOTIFY_MARK)"
    else
        fail "mark scope is no longer read from AVD_FANOTIFY_MARK"
    fi
    # main() unblocks SIGINT/SIGTERM in the main thread BEFORE calling
    # fanexec_init(), so responders spawned without re-blocking inherit
    # them unblocked and a process-directed SIGTERM can run the handler
    # on a responder - on its stack, while it holds an unanswered
    # FAN_OPEN_EXEC_PERM event. main()'s loop polls, so running = 0 is
    # still seen within an interval; this is no longer a hang by
    # itself, but it was one before that loop polled and it is not a
    # place we want a handler. Found by the #48 QEMU case.
    if grep -q 'pthread_sigmask' <<<"$INIT_BODY"; then
        pass "responders are spawned with termination signals blocked"
    else
        fail "fanexec_init() spawns responders without blocking SIGINT/SIGTERM - the handler could run on a responder holding an unanswered exec event"
    fi
fi

# Not gate code, but the gate is what makes it critical. libnl retries
# EINTR inside its own recvmsg(), so a signal cannot break
# nl_recvmsgs_default() out and a handler setting running = 0 has
# nothing to wake the loop. avd then waits for the next netlink message
# to notice it was asked to stop - never, on a quiet system - and with
# the gate on it holds the mark the whole time, suspending every exec
# on the marked mount. The loop must poll with a timeout instead.
if grep -q 'AVD_NL_POLL_MS' "$AVD"; then
    pass "the netlink receive loop re-checks running on a timer"
else
    fail "main()'s netlink loop no longer polls - libnl swallows EINTR, so SIGTERM would not be noticed until the next message and the gate would hold its mark meanwhile"
fi

section "#2: the gate stays off unless it is asked for, and fails loudly"

if grep -q 'fanexec_enabled = avd_env_flag("AVD_FANOTIFY_EXEC")' "$AVD"; then
    pass "the gate is opt-in via AVD_FANOTIFY_EXEC"
else
    fail "AVD_FANOTIFY_EXEC no longer gates the feature"
fi
if grep -q 'startup_failed = true' "$AVD"; then
    pass "a requested-but-unstartable gate aborts avd instead of running open"
else
    fail "avd no longer fails startup when a requested gate cannot start"
fi

MAIN_BODY="$(extract_c_func "$AVD" fanexec_main | strip_c_comments)"
if grep -q 'FAN_NOFD' <<<"$MAIN_BODY" && grep -q 'QUEUE OVERFLOW' <<<"$MAIN_BODY"; then
    pass "FAN_Q_OVERFLOW is reported loudly (the one fail-open surface left)"
else
    fail "queue overflow is not surfaced - execs can pass unchecked in silence"
fi

# The shared abort path every unrecoverable responder failure routes
# through. Checked as its own function because a responder that exits
# without it is not merely one fewer scanner: a permission-event gate
# is a chokepoint, every exec on a marked mount is suspended by the
# kernel until someone answers it, and the kernel imposes no timeout of
# its own. Lose the last responder quietly and those mounts wedge
# indefinitely while avd still reports itself up.
ABORT_BODY="$(extract_c_func "$AVD" fanexec_abort | strip_c_comments)"
if [ -z "$ABORT_BODY" ]; then
    fail "fanexec_abort() not found - responders have no shared abort path"
else
    if grep -q 'fanexec_aborted = 1' <<<"$ABORT_BODY"; then
        pass "the abort path retires the other responders too"
    else
        fail "fanexec_abort() no longer sets fanexec_aborted - the other responders keep spinning"
    fi
    if grep -q 'kill(getpid()' <<<"$ABORT_BODY"; then
        pass "an unrecoverable gate failure signals the process to shut down"
    else
        fail "no process-directed signal - an unrecoverable gate failure cannot reach main()"
    fi
fi

# An answer that never reaches the kernel is the same wedge as a
# responder that stops reading, arriving one exec at a time: the event
# stays pending, the exec stays suspended, and the kernel imposes no
# timeout. So the write side has to reach the same abort - and it has
# to keep EINTR out of that, since retrying a signal as though the exec
# were unanswerable would take the daemon down for nothing.
RESPOND_BODY="$(extract_c_func "$AVD" fanexec_respond | strip_c_comments)"
if [ -z "$RESPOND_BODY" ]; then
    fail "fanexec_respond() not found - the gate cannot answer anything"
else
    if grep -q 'fanexec_abort(' <<<"$RESPOND_BODY"; then
        pass "an undeliverable verdict routes through the abort path"
    else
        fail "fanexec_respond() only reports a failed answer - the exec stays suspended"
    fi
    if grep -q 'errno == EINTR' <<<"$RESPOND_BODY"; then
        pass "an interrupted response is retried, not treated as unanswerable"
    else
        fail "fanexec_respond() does not retry EINTR - a signal would kill the daemon"
    fi
fi

# All three bodies, because any one of them could reintroduce these.
RESPONDER_BODY="$MAIN_BODY
$ABORT_BODY
$RESPOND_BODY"

# A responder thread must never drive the scan pipeline's drain flag
# itself. shutting_down retires every scan worker and makes
# enqueue_scan_task() drop each later kernel request, but it does not
# touch `running`, so the main thread stays parked in
# nl_recvmsgs_default(): avd would sit there alive and registered,
# holding the module's single daemon slot (which av_nl_register_doit()
# will not hand to a replacement - -EBUSY, the #10 fix) while answering
# nothing. Silent, and unrecoverable without a manual kill, so it is
# pinned here rather than left to review.
if grep -q 'shutting_down *=' <<<"$RESPONDER_BODY"; then
    fail "a responder thread assigns shutting_down - kills scanning while avd stays up"
else
    pass "responders never set the scan pipeline's drain flag themselves"
fi
# raise() is pthread_kill() on the calling thread, and main() blocks
# SIGINT/SIGTERM before spawning any thread so that only the main
# thread can receive them - so a raised signal would sit pending in the
# responder forever and shut nothing down.
if grep -qE '\<raise\(' <<<"$RESPONDER_BODY"; then
    fail "raise() from a responder: SIGINT/SIGTERM are blocked there, so it never lands"
else
    pass "termination is process-directed, not raised on a thread that blocks it"
fi
# The four ways a responder stops being one: the buffer it needs before
# entering the loop, poll(), read()/EOF, and an ABI mismatch. Counted
# rather than eyeballed because a route deleted here does not look like
# a bug at the call site - it looks like an ordinary `break`, and the
# wedge above is what it actually is.
n_abort="$(grep -c 'fanexec_abort(' <<<"$MAIN_BODY" || true)"
if [ "$n_abort" -ge 4 ]; then
    pass "every unrecoverable responder exit routes through the abort path ($n_abort sites)"
else
    fail "fanexec_main() routes only $n_abort failure(s) through fanexec_abort() - expected >= 4"
fi

# The flag is only meaningful if perform_scan() actually raises it on
# the paths that fail open. Checked against the real function body so
# that deleting one of these branches shows up here rather than as a
# quietly-permissive gate.
SCAN_BODY="$(awk '/^static void perform_scan\(/{in_body=1} in_body{print} in_body && /^}/{exit}' "$AVD" | strip_c_comments)"
n_incomplete="$(grep -c 'incomplete = true' <<<"$SCAN_BODY" || true)"
if [ "$n_incomplete" -ge 6 ]; then
    pass "perform_scan() flags its fail-open paths as incomplete ($n_incomplete sites)"
else
    fail "perform_scan() flags only $n_incomplete fail-open path(s) - expected >= 6"
fi
# The size gates are policy, not failure: YARA still scans an
# over-cap file, and treating it as inconclusive would make
# fail-closed deny every large binary on a marked mount.
if grep -B3 'incomplete = true' <<<"$SCAN_BODY" | grep -qE 'size_ok|== -2'; then
    fail "a size gate is flagged incomplete - fail-closed would deny large binaries"
else
    pass "size gates are not treated as scan failures"
fi
# Every other caller must keep the old fail-open behaviour: the field
# is additive, and reading it anywhere else would change verdicts on
# the netlink and on-demand paths.
for fn in handle_scan_request cmd_scan; do
    body="$(extract_c_func "$AVD" "$fn" | strip_c_comments)"
    if [ -n "$body" ] && grep -q 'incomplete' <<<"$body"; then
        fail "$fn() reads .incomplete - changes fail-open behaviour outside the gate"
    else
        pass "$fn() is unchanged by the incomplete flag (still fails open)"
    fi
done

# The QEMU fail-closed case (issue #51) forces an incomplete scan by
# running avd with a 1s YARA budget. That only works if the budget is
# runtime-tunable: a hardcoded SCAN_TIMEOUT_SECS would make the case
# unstageable without a rebuild, and a tunable that nothing reads is
# a flag-shaped no-op. The call is matched in full - default plus both
# bound macros - so passing 0, a literal, or a wider max still fails
# here even though the bound macros exist separately below.
TUNABLE_CALL="$(grep -A3 'parse_tunable_env("AVD_SCAN_TIMEOUT_SECS"' "$AVD" || true)"
if grep -q 'parse_tunable_env("AVD_SCAN_TIMEOUT_SECS"' <<<"$TUNABLE_CALL" \
    && grep -qE '^[[:space:]]*SCAN_TIMEOUT_SECS,$' <<<"$TUNABLE_CALL" \
    && grep -qE '^[[:space:]]*AVD_SCAN_TIMEOUT_MIN,$' <<<"$TUNABLE_CALL" \
    && grep -qE '^[[:space:]]*AVD_SCAN_TIMEOUT_MAX\)' <<<"$TUNABLE_CALL"; then
    pass "YARA scan budget is tunable via AVD_SCAN_TIMEOUT_SECS (default + both bounds)"
else
    fail "AVD_SCAN_TIMEOUT_SECS is not wired with its default and bounds - the fail-closed QEMU case cannot set its budget"
fi
if grep -q 'yr_rules_scan_fd(compiled_rules, fd, 0, yara_callback, &ctx,' <<<"$SCAN_BODY" \
    && grep -q 'avd_scan_timeout_secs' <<<"$SCAN_BODY" \
    && ! grep -q 'SCAN_TIMEOUT_SECS)' <<<"$SCAN_BODY"; then
    pass "perform_scan() scans under the tunable budget, not the compiled-in default"
else
    fail "perform_scan() does not use avd_scan_timeout_secs as its YARA budget"
fi
# 0 would disable YARA's timeout entirely (verified: timeout=0 means no
# limit), turning a typo into an unbounded scan holding a suspended
# exec indefinitely - so the tunable must refuse it. The upper bound is
# the compiled-in default, not an arbitrary large value: lengthening
# past it breaks av/main.c's daemon_timeout_ms headroom and avctl's
# slow-verb budget, so the tunable only shortens. Both halves pinned
# here so neither rots.
if grep -q 'AVD_SCAN_TIMEOUT_MIN 1' "$AVD"; then
    pass "the timeout tunable refuses 0 (YARA's 'no timeout' value)"
else
    fail "AVD_SCAN_TIMEOUT_MIN is not 1 - AVD_SCAN_TIMEOUT_SECS=0 would disable the scan budget"
fi
if grep -q 'AVD_SCAN_TIMEOUT_MAX SCAN_TIMEOUT_SECS' "$AVD"; then
    pass "the timeout tunable only shortens (max is the compiled-in default)"
else
    fail "AVD_SCAN_TIMEOUT_MAX is not SCAN_TIMEOUT_SECS - a longer budget would outrun daemon_timeout_ms/avctl"
fi

# The fail-closed QEMU case (issue #51) only exercises the flag if its
# second avd actually sets it: the verdict case above starts avd
# without AVD_FANOTIFY_FAIL_CLOSED, so a dropped setenv here silently
# turns the whole phase into a second fail-open gate (slow file
# ALLOWED, "never denied" FAIL every run). dfd3553 did exactly this -
# a comment reword in the same hunk deleted the setenv line, and the
# 33/33 local run stayed green because nothing here reads init.c's
# setenv calls. Counted, not just present: the verdict case must NOT
# set it (fail-open control) and the fail-closed block must set it
# exactly once.
INIT="$REPO_ROOT/tests/qemu-boot/init.c"
n_fc_setenv="$(grep -c 'setenv("AVD_FANOTIFY_FAIL_CLOSED", "1", 1)' "$INIT" || true)"
if [ "$n_fc_setenv" -eq 1 ]; then
    pass "the fail-closed QEMU phase arms its flag (exactly one setenv)"
else
    fail "expected exactly one AVD_FANOTIFY_FAIL_CLOSED setenv in init.c (fail-closed phase), found $n_fc_setenv"
fi

STOP_BODY="$(extract_c_func "$AVD" fanexec_stop | strip_c_comments)"
# Closing the fanotify fd releases every still-pending permission event
# as allowed, so it must not happen while a responder still holds one.
JOIN_LINE="$(grep -n 'pthread_join' <<<"$STOP_BODY" | head -1 | cut -d: -f1)"
CLOSE_LINE="$(grep -n 'close(fanexec_fd)' <<<"$STOP_BODY" | head -1 | cut -d: -f1)"
if [ -n "$JOIN_LINE" ] && [ -n "$CLOSE_LINE" ] && [ "$JOIN_LINE" -lt "$CLOSE_LINE" ]; then
    pass "responder threads are joined before the fanotify fd is closed"
else
    fail "fanexec_stop() closes the fanotify fd before joining responders"
fi

# --- part 2: the mechanism, against a real kernel ---

section "#2: live FAN_OPEN_EXEC_PERM behaviour"

BUILD_DIR="$(mktemp -d -- "${TMPDIR:-/tmp}/av_fanotify_gate.XXXXXX")" || exit 1
trap 'rm -rf -- "$BUILD_DIR"' EXIT HUP INT TERM

CC_BIN="${CC:-gcc}"
if ! "$CC_BIN" -Wall -Wextra -O2 -o "$BUILD_DIR/fanotify_exec_gate" \
        "$REPO_ROOT/tests/fanotify_exec_gate.c" 2>"$BUILD_DIR/build.log" \
   || ! "$CC_BIN" -Wall -Wextra -O2 -o "$BUILD_DIR/fanotify_cold_child" \
        "$REPO_ROOT/tests/fanotify_cold_child.c" 2>>"$BUILD_DIR/build.log"; then
    fail "could not build the live harness"
    sed 's/^/    /' "$BUILD_DIR/build.log"
else
    # 0755: the harness is run as root via pkexec, which resets the
    # environment and runs from a different context - it has to be
    # readable and executable by the elevated process.
    chmod 755 "$BUILD_DIR" "$BUILD_DIR/fanotify_exec_gate" \
        "$BUILD_DIR/fanotify_cold_child"

    RUNNER=()
    RUNNER_LABEL="directly as root"
    if [ "$(id -u)" -ne 0 ]; then
        if command -v pkexec >/dev/null 2>&1; then
            # pkexec, not sudo - same reasoning as tests/run_all.sh's
            # header comment.
            RUNNER=(pkexec)
            RUNNER_LABEL="via pkexec"
        fi
    fi

    if [ "$(id -u)" -ne 0 ] && [ "${#RUNNER[@]}" -eq 0 ]; then
        echo
        echo "  ############################################################"
        echo "  # LIVE CHECKS SKIPPED - not root and no pkexec available.  #"
        echo "  # The static invariants above passed, but NOTHING here     #"
        echo "  # confirmed FAN_OPEN_EXEC_PERM actually behaves as #2's    #"
        echo "  # fix assumes. Do not read this run as evidence that the   #"
        echo "  # gap is closed.                                           #"
        echo "  ############################################################"
        echo
        if [ "$LIVE_REQUIRED" = "1" ]; then
            fail "live checks were required (AV_FANOTIFY_LIVE_REQUIRED=1) but skipped"
        fi
    else
        echo "  running the live harness $RUNNER_LABEL..."
        # PIPESTATUS, not the pipeline's own status: piping through sed
        # for indentation would otherwise report sed's exit code, so a
        # failing harness would read as a pass. That is precisely the
        # silent-pass failure #34 landed on, and it is not worth
        # reintroducing for prettier output.
        "${RUNNER[@]}" "$BUILD_DIR/fanotify_exec_gate" \
            "$BUILD_DIR/fanotify_cold_child" 2>&1 | sed 's/^/    /'
        rc="${PIPESTATUS[0]}"
        if [ "$rc" -eq 0 ]; then
            pass "live FAN_OPEN_EXEC_PERM checks (see output above)"
        else
            if [ "$rc" -eq 77 ] || [ "$rc" -eq 78 ]; then
                # 77 = could not get root, 78 = this kernel has no
                # permission-event support (no
                # CONFIG_FANOTIFY_ACCESS_PERMISSIONS, or pre-5.0). Both
                # are skips rather than failures - neither says anything
                # about avd's code - but both are still failures when a
                # caller asserted the live half would run.
                echo
                echo "  ############################################################"
                echo "  # LIVE CHECKS SKIPPED - see the harness output above.      #"
                echo "  # The static invariants passed, but nothing here confirmed #"
                echo "  # FAN_OPEN_EXEC_PERM behaves as #2's fix assumes.          #"
                echo "  ############################################################"
                echo
                if [ "$LIVE_REQUIRED" = "1" ]; then
                    fail "live checks were required (AV_FANOTIFY_LIVE_REQUIRED=1) but the harness skipped (exit $rc)"
                fi
            else
                fail "live FAN_OPEN_EXEC_PERM checks failed"
            fi
        fi
    fi
fi

echo
echo "=== $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
