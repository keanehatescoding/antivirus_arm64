#!/usr/bin/env bash
#
# tests/test_regression_10_14.sh - static regression checks pinning the
# fixes for #10 (netlink REGISTER hijack rejection, world-readable /proc
# IOC lists) and #14 (runtime-tunable kernel thresholds, YARA compound-rule
# weight double-count).
#
# Both issues' code fixes already landed (#31/#32 for #10, #26/#37 for
# #14), but nothing asserted the resulting source invariants - #32 noted
# explicitly that no test covers the /proc modes. These are pure
# source-level greps, so unlike most of tests/ this needs no root, no
# ARM64 VM, and no loaded module:
#   tests/test_regression_10_14.sh
#
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETLINK_CHAN="$REPO_ROOT/av/netlink_chan.c"
BEHAVIOR="$REPO_ROOT/av/behavior.c"
MAIN="$REPO_ROOT/av/main.c"
SIGTABLE="$REPO_ROOT/av/sigtable.c"
HEURISTICS="$REPO_ROOT/rules/heuristics.yar"
AVD="$REPO_ROOT/userspace/avd/avd.c"

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

section() { echo; echo "== $1 =="; }

# --- #10 item 1: second REGISTER while a daemon is live is rejected ---

section "#10: netlink REGISTER hijack rejection"
if grep -q 'return -EBUSY' "$NETLINK_CHAN"; then
    pass "register path rejects a live-daemon takeover with -EBUSY"
else
    fail "no -EBUSY rejection in av_nl_register_doit()"
fi
if grep -q 'pr_alert("kernel-av: netlink REGISTER from portid' "$NETLINK_CHAN"; then
    pass "rejected REGISTER is logged at pr_alert"
else
    fail "pr_alert REGISTER-rejection log line missing"
fi
if grep -q 'GENL_ADMIN_PERM' "$NETLINK_CHAN"; then
    pass "register/verdict ops still gated on CAP_NET_ADMIN"
else
    fail "GENL_ADMIN_PERM gating missing from netlink ops"
fi

# --- #10 item 2: IOC /proc entries are owner-only reads ---

section "#10: IOC /proc entries are 0600"
for entry in "kernel_av_signatures:$SIGTABLE" \
             "kernel_av_trusted:$BEHAVIOR" \
             "kernel_av_protected:$BEHAVIOR"; do
    name="${entry%%:*}"
    file="${entry##*:}"
    if grep -q "proc_create(\"$name\", 0600" "$file"; then
        pass "$name is created 0600"
    else
        fail "$name is not created 0600"
    fi
    if grep -q "proc_create(\"$name\", 0644" "$file"; then
        fail "$name still has a world-readable 0644 creation"
    else
        pass "$name has no world-readable 0644 creation"
    fi
done
# kernel_av_daemon_policy is the deliberate exception (#32): a single
# fail-open/fail-closed bit, not IOCs, and unprivileged `avctl policy get`
# plus the GUI's unauthenticated read path depend on reading it.
if grep -q '"kernel_av_daemon_policy", 0644' "$MAIN"; then
    pass "kernel_av_daemon_policy stays 0644 (documented exception)"
else
    fail "kernel_av_daemon_policy 0644 exception missing from av/main.c"
fi

# --- #14 item 2: compound-rule weight is not double-counted ---

section "#14: YARA private sub-rules, single compound weight"
if grep -q '^private rule Imports_Ptrace' "$HEURISTICS"; then
    pass "Imports_Ptrace is private"
else
    fail "Imports_Ptrace lost its private modifier"
fi
if grep -q '^private rule Imports_Memfd_Create' "$HEURISTICS"; then
    pass "Imports_Memfd_Create is private"
else
    fail "Imports_Memfd_Create lost its private modifier"
fi
if grep -q '^rule Multiple_Suspicious_Imports' "$HEURISTICS" \
    && grep -q 'weight = 40' "$HEURISTICS"; then
    pass "Multiple_Suspicious_Imports stays public at weight 40"
else
    fail "compound rule is not public at weight 40"
fi
if grep -q 'RULE_IS_PRIVATE' "$AVD"; then
    pass "avd.c skips private matches when summing weights"
else
    fail "RULE_IS_PRIVATE guard missing from avd.c scoring"
fi
if command -v yara >/dev/null 2>&1; then
    if yara "$HEURISTICS" /bin/true >/dev/null 2>&1; then
        pass "heuristics.yar still compiles"
    else
        fail "heuristics.yar fails to compile"
    fi
else
    echo "  SKIP: yara CLI not installed - skipping rule compile check"
fi

# --- #14 item 1: hardcoded #defines are load-time module params ---

section "#14: detection thresholds are 0444 module params"
for param in read_chunk_size max_hash_file_size daemon_timeout_ms \
             av_max_inflight_work; do
    if grep -q "module_param($param, int, 0444)" "$MAIN"; then
        pass "av/main.c exposes $param"
    else
        fail "av/main.c lost module_param for $param"
    fi
done
for param in write_open_window_ms write_open_threshold \
             rename_window_ms rename_threshold; do
    if grep -q "module_param($param, int, 0444)" "$BEHAVIOR"; then
        pass "av/behavior.c exposes $param"
    else
        fail "av/behavior.c lost module_param for $param"
    fi
done

echo
echo "==================================="
echo "10/14 regression tests: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
