#!/usr/bin/env bash
#
# tests/run_all.sh - builds everything and runs both test scripts.
# Used by .githooks/pre-push, and safe to run manually any time:
#   tests/run_all.sh
#
# Self-elevates via pkexec only on a native aarch64 host (the only case
# where anything here actually insmod's av.ko into this machine) - no
# root needed anywhere else, so don't run this with sudo yourself; let
# it ask for a pkexec prompt if and when it actually needs one.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_ARCH="$(uname -m)"

# Root is only needed for the insmod/rmmod-based tests below, and those
# only make sense on a native aarch64 host - av.ko is arm64-only, so it
# can never load on anything else regardless of privilege. Self-elevate
# via pkexec (not sudo - see .githooks/pre-push's header comment on why)
# only in the one case that actually needs it, instead of demanding root
# unconditionally: on a non-aarch64 host this whole run is unprivileged.
if [ "$HOST_ARCH" = "aarch64" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        exec pkexec "$0" "$@"
    fi
else
    echo "run_all.sh: host is $HOST_ARCH, not aarch64 - av.ko can't be insmod'd"
    echo "  here. test_detection.sh will cross-compile + QEMU-boot-test it"
    echo "  instead (no root needed); test_sigtable.sh/test_avd_socket.sh/"
    echo "  test_netlink.sh need a module actually loaded on this host and"
    echo "  will be skipped."
fi

FAIL=0

echo "### building avctl ###"
make -C "$REPO_ROOT/userspace/avctl" || FAIL=1

echo
echo "### test_sha256.sh (known-answer tests for userspace/avd/sha256.c) ###"
# No kernel module/root needed for this one, unlike everything else
# here - it just doesn't hurt to run it under the same sudo invocation.
"$REPO_ROOT/tests/test_sha256.sh" || FAIL=1

echo
echo "### test_tlsh_core.sh (known-answer tests for userspace/avd/tlsh_core.c) ###"
# Same no-root-needed reasoning as test_sha256.sh above.
"$REPO_ROOT/tests/test_tlsh_core.sh" || FAIL=1

echo
echo "### test_avd_sigroute.sh (SIGINT/SIGTERM routing to avd main thread) ###"
# Same no-root-needed reasoning as test_sha256.sh above.
"$REPO_ROOT/tests/test_avd_sigroute.sh" || FAIL=1

echo
echo "### test_detection.sh (build av/, load, exercise clean+EICAR, unload) ###"
"$REPO_ROOT/tests/test_detection.sh" || FAIL=1

echo
echo "### test_sigtable.sh (avctl/proc protocol) ###"
if [ "$HOST_ARCH" = "aarch64" ]; then
    # test_detection.sh unloads the module as part of its own cleanup, so
    # reload it here for the sigtable protocol tests.
    insmod "$REPO_ROOT/av/av.ko" 2>/dev/null || true
    "$REPO_ROOT/tests/test_sigtable.sh" || FAIL=1
    rmmod av 2>/dev/null || true
else
    echo "SKIPPED: needs a native aarch64 host with av.ko loaded - not run on $HOST_ARCH"
fi

echo
echo "### test_avd_socket.sh (avd control socket / avctl scan+quarantine) ###"
if [ "$HOST_ARCH" = "aarch64" ]; then
    # Builds+loads/unloads the module and starts/stops avd itself - no
    # reload dance needed here, unlike test_sigtable.sh above.
    "$REPO_ROOT/tests/test_avd_socket.sh" || FAIL=1
else
    echo "SKIPPED: needs a native aarch64 host with av.ko loaded - not run on $HOST_ARCH"
fi

echo
echo "### test_netlink.sh (kernel<->avd Generic Netlink channel) ###"
if [ "$HOST_ARCH" = "aarch64" ]; then
    # Builds+loads/unloads the module and starts/stops avd itself, same
    # shape as test_avd_socket.sh above.
    "$REPO_ROOT/tests/test_netlink.sh" || FAIL=1
else
    echo "SKIPPED: needs a native aarch64 host with av.ko loaded - not run on $HOST_ARCH"
fi

echo
if [ "$FAIL" -ne 0 ]; then
    echo "run_all.sh: one or more test suites FAILED"
    exit 1
fi

echo "run_all.sh: all test suites passed"
exit 0
