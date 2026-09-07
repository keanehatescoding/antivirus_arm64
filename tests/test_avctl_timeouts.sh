#!/usr/bin/env bash
#
# tests/test_avctl_timeouts.sh - regression tests for avctl's control-socket
# timeouts (issue #5: userspace/avctl/avctl.c's control_request()).
#
# Covers three fake-server cases against a throwaway AF_UNIX socket path:
#   1. wedged server (accepts, never replies) -> must fail within the 5s
#      fast-verb budget, not hang forever (the original issue #5 bug).
#   2. trickle server (one byte per second, never closes) -> must still
#      fail at the 5s ABSOLUTE deadline. SO_RCVTIMEO alone only bounds
#      each individual read() call, so without the CLOCK_MONOTONIC +
#      poll() deadline each 1-byte read would succeed and the client
#      could stay connected until the 16MB response cap - effectively
#      unbounded. This is the exact failure the absolute deadline exists
#      to catch, so this case asserts a tight wall-clock bound.
#   3. well-behaved server (OK/COUNT/END, then close) -> must succeed.
#
# Pure userspace, no kernel module or root needed - unlike most of
# tests/, safe to run standalone:
#   tests/test_avctl_timeouts.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AVCTL_DIR="$REPO_ROOT/userspace/avctl"
AVCTL="$AVCTL_DIR/avctl"

TEST_TMP_DIR="$(mktemp -d -- /tmp/av_test_avctl_timeouts.XXXXXX)" || exit 1
# shellcheck disable=SC2317,SC2329
# False positive, same pattern as tests/test_sha256.sh: cleanup() is
# invoked via the trap on the next line, which the linter cannot see.
cleanup() { rm -rf "$TEST_TMP_DIR"; }
trap cleanup EXIT

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 not found (needed for the fake control-socket servers)"
    exit 0
fi

# (Re)build avctl so the test exercises the working tree, not a stale
# binary - same rationale as tests/test_avd_socket.sh building the
# module and avd itself before exercising them.
if ! make -C "$AVCTL_DIR" >/dev/null 2>&1; then
    echo "FAIL: could not build avctl"
    exit 1
fi

# Runs one case: $1 = mode (wedged|trickle|ok), $2 = max wall seconds
# the client may take, $3.. = avctl args. Prints the client's elapsed
# time, return code and first stderr line for the assertions below.
run_case() {
    local mode="$1" max_secs="$2"
    shift 2
    local sock="$TEST_TMP_DIR/$mode.sock"
    rm -f "$sock" "$sock.ready"
    AVD_SOCK_PATH="$sock" TEST_TMP_DIR="$TEST_TMP_DIR" MODE="$mode" \
        python3 - "$sock" "$mode" <<'EOF' &
import os, socket, time
path, mode = __import__("sys").argv[1], __import__("sys").argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(1)
# Readiness marker AFTER listen(): bind() alone already creates the
# socket path, so polling for the path cannot distinguish "bound" from
# "listening" - a client connecting in that gap gets ECONNREFUSED.
open(path + ".ready", "w").close()
conn, _ = s.accept()
data = b""
while not data.endswith(b"\n"):
    chunk = conn.recv(4096)
    if not chunk:
        break
    data += chunk
if mode == "wedged":
    time.sleep(30)
elif mode == "trickle":
    for _ in range(30):
        try:
            conn.sendall(b"x")
        except BrokenPipeError:
            break
        time.sleep(1)
elif mode == "ok":
    conn.sendall(b"OK\nCOUNT 0\nEND\n")
conn.close()
s.close()
EOF
    local server_pid=$!
    # Wait for the server to be listening before connecting (poll for
    # the readiness marker rather than a fixed sleep, so a loaded CI
    # machine cannot flake here). The marker is created after listen(),
    # unlike the socket path itself, which already exists after bind().
    local tries=0
    while [ ! -f "$sock.ready" ] && [ "$tries" -lt 50 ]; do
        sleep 0.1
        tries=$((tries + 1))
    done
    local start end elapsed rc
    start=$(date +%s)
    # `timeout` guards the assertion itself: even if the deadline
    # regresses, this script always terminates instead of hanging.
    if AVD_SOCK_PATH="$sock" timeout "$max_secs" "$AVCTL" "$@" \
            >"$TEST_TMP_DIR/$mode.out" 2>"$TEST_TMP_DIR/$mode.err"; then
        rc=0
    else
        rc=$?
    fi
    end=$(date +%s)
    elapsed=$((end - start))
    kill "$server_pid" 2>/dev/null
    wait "$server_pid" 2>/dev/null
    echo "$elapsed $rc"
}

echo "== wedged server fails within the 5s fast-verb budget =="
# 8s bound = 5s budget + scheduling slack (same as the trickle case
# below): a regression that idles 10-14s before reporting failure must
# not pass. The `timeout 15` inside run_case stays as the outer hang
# guard so the script itself always terminates.
read -r elapsed rc <<<"$(run_case wedged 15 quarantine list)"
if [ "$rc" -ne 0 ] && grep -q "within 5 seconds" "$TEST_TMP_DIR/wedged.err" \
        && [ "$elapsed" -lt 8 ]; then
    pass "wedged server failed after ${elapsed}s with timeout message (rc=$rc)"
else
    fail "wedged server: elapsed=${elapsed}s rc=$rc err=$(head -c 200 "$TEST_TMP_DIR/wedged.err")"
fi

echo "== trickle server fails at the 5s absolute deadline =="
# The point of this case: at 1 byte/sec the per-read SO_RCVTIMEO never
# fires, so only the absolute deadline can stop the client. 8s bound =
# 5s budget + scheduling slack; without the deadline this would run
# until the 16MB cap (hours at this rate) or the 15s `timeout` kill.
read -r elapsed rc <<<"$(run_case trickle 15 quarantine list)"
if [ "$rc" -ne 0 ] && grep -q "within 5 seconds" "$TEST_TMP_DIR/trickle.err" \
        && [ "$elapsed" -lt 8 ]; then
    pass "trickle server failed after ${elapsed}s with timeout message (rc=$rc)"
else
    fail "trickle server: elapsed=${elapsed}s rc=$rc err=$(head -c 200 "$TEST_TMP_DIR/trickle.err")"
fi

echo "== well-behaved server still succeeds =="
read -r elapsed rc <<<"$(run_case ok 15 quarantine list)"
if [ "$rc" -eq 0 ]; then
    pass "normal response succeeded (rc=0)"
else
    fail "normal response: rc=$rc err=$(head -c 200 "$TEST_TMP_DIR/ok.err")"
fi

echo
echo "test_avctl_timeouts: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
