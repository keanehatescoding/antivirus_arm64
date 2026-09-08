#!/usr/bin/env bash
#
# test_dynamic_symbol_evasion.sh - v0.9.0 evasion test 1.
#
# Technique: resolve ptrace() via dlopen()+dlsym() at runtime instead of
# linking it directly. This removes the direct dynamic-symbol-table
# entry that rules/heuristics.yar's Imports_Ptrace rule checks for
# (elf.dynsym), while the actual behavior (calling ptrace) is identical.
#
# Runs standalone - no kernel module needed, just the yara CLI.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RULES="$REPO_ROOT/rules/heuristics.yar"

echo "=== Evasion test: dynamic symbol resolution (dlopen/dlsym) ==="

# Private mktemp -d, not fixed /tmp/dynsym_evasion.* paths: predictable
# world-writable-directory names let another local user pre-plant a symlink
# that this script's compiler output would then follow. Same pattern as
# tests/test_netlink.sh.
EVASION_TMP_DIR="$(mktemp -d -- /tmp/dynsym_evasion.XXXXXX)" || exit 1
trap 'rm -rf "$EVASION_TMP_DIR"' EXIT

cat > "$EVASION_TMP_DIR/dynsym_evasion.c" << 'EOF'
#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>

int main(void) {
    void *libc = dlopen("libc.so.6", RTLD_LAZY);
    long (*ptrace_fn)(int, pid_t, void *, void *);

    if (!libc) {
        fprintf(stderr, "dlopen failed\n");
        return 1;
    }

    ptrace_fn = dlsym(libc, "ptrace");
    if (ptrace_fn)
        ptrace_fn(16 /* PTRACE_ATTACH */, 1234, NULL, NULL);

    printf("done\n");
    return 0;
}
EOF
gcc -o "$EVASION_TMP_DIR/dynsym_evasion" "$EVASION_TMP_DIR/dynsym_evasion.c" -ldl

# Positive control: a binary importing ptrace AND memfd_create directly
# must still trip the (public) compound rule - guards against this test
# going green just because the rule set itself is broken.
cat > "$EVASION_TMP_DIR/direct_imports.c" << 'EOF'
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <stddef.h>
int main(void) {
    int fd = memfd_create("jit", 0);
    ptrace(PTRACE_ATTACH, 1234, NULL, NULL);
    return (fd < 0);
}
EOF
gcc -o "$EVASION_TMP_DIR/direct_imports" "$EVASION_TMP_DIR/direct_imports.c"

echo
echo "--- dynamic symbol table (confirming ptrace is NOT a direct import) ---"
objdump -T "$EVASION_TMP_DIR/dynsym_evasion" | grep -i ptrace && \
    echo "UNEXPECTED: ptrace found as a direct import - evasion technique failed to build correctly" || \
    echo "confirmed: no direct ptrace import (as intended)"

echo
echo "--- control: direct ptrace+memfd_create imports (must be detected) ---"
CONTROL_MATCHES="$(yara "$RULES" "$EVASION_TMP_DIR/direct_imports" || true)"
echo "$CONTROL_MATCHES"
if echo "$CONTROL_MATCHES" | grep -q "^Multiple_Suspicious_Imports"; then
    echo "control OK: compound rule fires on direct imports"
else
    echo "CONTROL FAILED: compound rule did not fire - rule set itself is broken"
    exit 1
fi

echo
echo "--- running heuristics.yar ---"
MATCHES="$(yara "$RULES" "$EVASION_TMP_DIR/dynsym_evasion" || true)"
echo "$MATCHES"

echo
# Imports_Ptrace/Imports_Memfd_Create are private building blocks since the
# double-count fix - only Multiple_Suspicious_Imports surfaces, so a failed
# evasion shows up as the compound rule, not the sub-rule.
if echo "$MATCHES" | grep -q "^Multiple_Suspicious_Imports"; then
    echo "RESULT: compound rule still fired - evasion FAILED"
    exit 1
else
    echo "RESULT: compound rule evaded successfully"
    if echo "$MATCHES" | grep -q "^Imports_Dlopen"; then
        echo "  (but Imports_Dlopen fired instead - the evasion TECHNIQUE itself"
        echo "   is a weak signal, even though the specific API it hides is not)"
    fi
fi
