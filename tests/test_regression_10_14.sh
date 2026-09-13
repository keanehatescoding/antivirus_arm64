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

# Scoped-extraction helpers: every functional assertion below runs
# against the extracted body of the exact function/rule/table entry it
# pins - never the whole file - so a matching token elsewhere in the
# file cannot mask a regression at the real site.
extract_c_func() { # $1 = file, $2 = function name (defined at column 0)
    awk -v fn="$2" '$0 ~ "^static int " fn "\\(" {in_body=1} in_body{print} in_body && /^}/{exit}' "$1"
}
extract_yara_rule() { # $1 = file, $2 = rule name
    awk -v rule="$2" '$0 ~ "^(private )?rule " rule "$" {in_body=1} in_body{print} in_body && /^}/{exit}' "$1"
}
extract_genl_op() { # $1 = file, $2 = .cmd constant, e.g. AV_C_REGISTER
    awk -v cmd="$2" '$0 ~ "\\.cmd = " cmd "," {in_entry=1} in_entry{print} in_entry && /^ *\},/ {exit}' "$1"
}

# --- #10 item 1: second REGISTER while a daemon is live is rejected ---

section "#10: netlink REGISTER hijack rejection"
REGISTER_BODY="$(extract_c_func "$NETLINK_CHAN" av_nl_register_doit)"
REGISTER_OP="$(extract_genl_op "$NETLINK_CHAN" AV_C_REGISTER)"
if grep -q 'return -EBUSY' <<<"$REGISTER_BODY"; then
    pass "av_nl_register_doit() rejects a live-daemon takeover with -EBUSY"
else
    fail "no -EBUSY rejection in av_nl_register_doit()"
fi
if grep -q 'pr_alert("kernel-av: netlink REGISTER from portid' <<<"$REGISTER_BODY"; then
    pass "rejected REGISTER is logged at pr_alert"
else
    fail "pr_alert REGISTER-rejection log line missing from av_nl_register_doit()"
fi
if grep -q '\.doit = av_nl_register_doit' <<<"$REGISTER_OP" \
    && grep -q 'GENL_ADMIN_PERM' <<<"$REGISTER_OP"; then
    pass "AV_C_REGISTER op entry wires av_nl_register_doit with GENL_ADMIN_PERM"
else
    fail "AV_C_REGISTER op entry lost its doit handler or CAP_NET_ADMIN gating"
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
COMPOUND_BODY="$(extract_yara_rule "$HEURISTICS" Multiple_Suspicious_Imports)"
if ! grep -q '^private rule Multiple_Suspicious_Imports' "$HEURISTICS" \
    && grep -q 'weight = 40' <<<"$COMPOUND_BODY"; then
    pass "Multiple_Suspicious_Imports stays public at weight 40"
else
    fail "compound rule is not public at weight 40"
fi
if grep -q 'Imports_Ptrace and Imports_Memfd_Create' <<<"$COMPOUND_BODY"; then
    pass "compound rule condition combines both private sub-rules"
else
    fail "compound rule no longer combines Imports_Ptrace and Imports_Memfd_Create"
fi
YARA_CB="$(extract_c_func "$AVD" yara_callback)"
PRIV_LINE="$(grep -n 'RULE_IS_PRIVATE' <<<"$YARA_CB" | head -1 | cut -d: -f1)"
SUM_LINE="$(grep -n 'ctx->score +=' <<<"$YARA_CB" | head -1 | cut -d: -f1)"
if [ -n "$PRIV_LINE" ] && [ -n "$SUM_LINE" ] && [ "$PRIV_LINE" -lt "$SUM_LINE" ]; then
    pass "yara_callback() skips private matches before summing weights"
else
    fail "RULE_IS_PRIVATE guard missing or not ahead of weight summation in yara_callback()"
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
for spec in "read_chunk_size:$MAIN:READ_CHUNK_SIZE" \
            "max_hash_file_size:$MAIN:MAX_HASH_FILE_SIZE" \
            "daemon_timeout_ms:$MAIN:DAEMON_TIMEOUT_MS" \
            "av_max_inflight_work:$MAIN:AV_MAX_INFLIGHT_WORK" \
            "write_open_window_ms:$BEHAVIOR:WRITE_OPEN_WINDOW_MS" \
            "write_open_threshold:$BEHAVIOR:WRITE_OPEN_THRESHOLD" \
            "rename_window_ms:$BEHAVIOR:RENAME_WINDOW_MS" \
            "rename_threshold:$BEHAVIOR:RENAME_THRESHOLD"; do
    param="${spec%%:*}"
    rest="${spec#*:}"
    file="${rest%%:*}"
    base="${rest##*:}"
    short="$(basename "$file")"
    if grep -q "module_param($param, int, 0444)" "$file"; then
        pass "$short exposes $param"
    else
        fail "$short lost module_param for $param"
    fi
    # A declaration alone proves nothing if the detection path still
    # reads a hard constant: require a real code reference to the
    # variable (the declaration, MODULE_PARM_DESC, and comment lines
    # don't count as uses).
    uses=$(grep -n "\<${param}\>" "$file" \
        | grep -v "module_param(${param}," \
        | grep -v "MODULE_PARM_DESC(${param}" \
        | grep -v "static int ${param} " \
        | grep -v ': *\*' \
        | grep -v ': */\*' || true)
    if [ -n "$uses" ]; then
        pass "$param is referenced outside its own declaration"
    else
        fail "$param is declared but never used"
    fi
    # And the old bare hardcode must be gone, not just shadowed: only
    # the _DEFAULT/_MIN/_MAX scaffolding around the param may remain.
    if grep -qE "^#define ${base}( |$)" "$file"; then
        fail "$short still defines a hardcoded $base"
    else
        pass "$short has no hardcoded $base"
    fi
done

echo
echo "==================================="
echo "10/14 regression tests: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
