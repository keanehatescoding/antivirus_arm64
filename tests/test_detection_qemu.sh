#!/usr/bin/env bash
#
# tests/test_detection_qemu.sh - cross-compiles av.ko for arm64 and boot-
# tests it in QEMU (qemu-system-aarch64 -M virt), instead of insmod'ing
# it on the host. av.ko is arm64-only (hooks __arm64_sys_* symbols, reads
# arm64 pt_regs) - it can never be loaded on a non-aarch64 dev machine,
# so test_detection.sh delegates here when uname -m != aarch64.
#
# This is the same build-a-kernel/boot/check-dmesg approach as
# .github/workflows/qemu-boot-test.yml, just run locally with a
# cross-compiler (CROSS_COMPILE=aarch64-linux-gnu-) instead of that
# workflow's native arm64 runner, and with the resulting kernel tree
# cached locally (see CACHE_ROOT below) instead of actions/cache - a
# from-scratch arm64 defconfig build takes several minutes, and this
# script can run on every `git push` that touches av/.
#
# The cache lives outside the checkout, in
# ${XDG_CACHE_HOME:-~/.cache}/antivirus_arm64/qemu-kernel (override with
# AV_KERNEL_CACHE), so every clone and `git worktree` of this repo shares
# one kernel build instead of each paying for its own. A lock serializes
# runs, so two worktrees can't build the same tree at once.
#
# No root needed: nothing here insmod's into the host kernel - av.ko
# only ever gets loaded inside the QEMU guest, by tests/qemu-boot/init.c
# acting as the guest's PID 1.
#
# Usage: tests/test_detection_qemu.sh
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QDIR="$REPO_ROOT/tests/qemu-boot"
CACHE_ROOT="${AV_KERNEL_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/antivirus_arm64/qemu-kernel}"

MISSING=()
command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 || MISSING+=("aarch64-linux-gnu-gcc")
command -v qemu-system-aarch64 >/dev/null 2>&1 || MISSING+=("qemu-system-aarch64")
command -v curl >/dev/null 2>&1 || MISSING+=("curl")
command -v cpio >/dev/null 2>&1 || MISSING+=("cpio")
command -v sha256sum >/dev/null 2>&1 || MISSING+=("sha256sum")
command -v gpg >/dev/null 2>&1 || MISSING+=("gpg")
command -v flock >/dev/null 2>&1 || MISSING+=("flock (util-linux)")
if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "test_detection_qemu.sh: missing required tool(s): ${MISSING[*]}"
    echo "  Arch/CachyOS: sudo pacman -S aarch64-linux-gnu-gcc qemu-system-aarch64 cpio curl gnupg util-linux"
    echo "  Debian/Ubuntu: sudo apt install gcc-aarch64-linux-gnu qemu-system-arm cpio curl gnupg util-linux"
    exit 1
fi

# Same list build-matrix.yml/qemu-boot-test.yml read via
# .github/kernel-versions.json - use the newest entry. This is a local
# pre-push smoke test, not a substitute for CI's full matrix, so testing
# one (the newest) version is enough here.
if command -v jq >/dev/null 2>&1; then
    KERNEL_VERSION="$(jq -r '.versions[-1]' "$REPO_ROOT/.github/kernel-versions.json")"
else
    KERNEL_VERSION="$(grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' "$REPO_ROOT/.github/kernel-versions.json" | tail -1 | tr -d '"')"
fi
if [ -z "$KERNEL_VERSION" ]; then
    echo "test_detection_qemu.sh: couldn't determine a kernel version from .github/kernel-versions.json"
    exit 1
fi

case "$CACHE_ROOT" in
    *[[:space:]]*)
        # kbuild can't build out of a path containing whitespace (KDIR and
        # M= are word-split by its makefiles), so fail clearly up front.
        echo "test_detection_qemu.sh: the kernel cache path '$CACHE_ROOT' contains whitespace, which kbuild can't handle - set AV_KERNEL_CACHE to a path without spaces"
        exit 1 ;;
esac
KDIR="$CACHE_ROOT/linux-$KERNEL_VERSION"
mkdir -p "$CACHE_ROOT" || exit 1
# The cache is shared by every clone and worktree: never touch it unlocked.
exec 9>"$CACHE_ROOT/.lock" || exit 1
if ! flock -n 9; then
    echo "test_detection_qemu.sh: waiting for another run using $CACHE_ROOT"
    flock 9 || { echo "test_detection_qemu.sh: couldn't lock $CACHE_ROOT/.lock"; exit 1; }
fi
if [ -d "$QDIR/.kernel-cache" ] && [ "$(realpath "$QDIR/.kernel-cache")" != "$(realpath "$CACHE_ROOT")" ]; then
    echo "test_detection_qemu.sh: note: $QDIR/.kernel-cache is the old, per-checkout cache location and is no longer used - delete it to free the space"
fi
# The cached tree is keyed on what actually shapes it - the build block
# below (between the >>> and <<< markers: defconfig, the scripts/config
# enables, the make targets) plus the download/verify helper and its
# key - not on this whole script, so editing a message or the lock
# handling doesn't throw away a kernel build. Same reasoning as
# qemu-boot-test.yml's cache key including hashFiles(workflow file):
# a config or verification change must invalidate the cache, or it'll
# keep serving a tree built with the old config (or verified the old
# way) forever.
VERIFY_HASH="$(cat "$REPO_ROOT/.github/scripts/verify-kernel-tarball.sh" "$REPO_ROOT/.github/scripts/kernel-autosigner.asc" | sha256sum | awk '{print $1}')"
BUILD_BLOCK="$(sed -n '/^ *# >>> kernel build/,/^ *# <<< kernel build/p' "$0")"
if [ -z "$BUILD_BLOCK" ]; then
    echo "test_detection_qemu.sh: the '# >>> kernel build' / '# <<< kernel build' markers are missing - the cache key needs them"
    exit 1
fi
SELF_HASH="$(printf '%s\n%s\n' "$BUILD_BLOCK" "$VERIFY_HASH" | sha256sum | awk '{print $1}')"
STAMP="$KDIR/.hyprav-cache-stamp"

if [ -f "$KDIR/arch/arm64/boot/Image" ] && [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$SELF_HASH" ]; then
    echo "test_detection_qemu.sh: using cached arm64 $KERNEL_VERSION kernel at $KDIR"
else
    echo "test_detection_qemu.sh: (re)building arm64 $KERNEL_VERSION kernel - this takes several minutes but is cached at $KDIR for next time"
    rm -rf "$KDIR"
    mkdir -p "$CACHE_ROOT"
    # The verified tarball is kept next to the tree (~150 MB), so a
    # rebuild doesn't download it again. Its .sha256 file records the
    # tarball's hash at verification time and VERIFY_HASH: it is reused
    # only while both still match, i.e. the file is byte-identical to
    # what the helper verified and the helper/key haven't changed since.
    # Otherwise it's fetched and verified again, the same way as
    # .github/workflows/qemu-boot-test.yml (issue #6): PGP-verified sums
    # plus sha256, via the shared helper so the logic can't drift
    # between CI and this script.
    TARBALL="$CACHE_ROOT/linux-$KERNEL_VERSION.tar.xz"
    TARBALL_SUM="$TARBALL.sha256"
    for old in "$CACHE_ROOT"/linux-*.tar.xz; do
        [ -e "$old" ] && [ "$old" != "$TARBALL" ] && rm -f "$old" "$old.sha256"
    done
    if [ -f "$TARBALL" ] && [ -f "$TARBALL_SUM" ] &&
       [ "$(cat "$TARBALL_SUM")" = "$(sha256sum "$TARBALL" | awk '{print $1}') $VERIFY_HASH" ]; then
        echo "test_detection_qemu.sh: reusing the verified linux-$KERNEL_VERSION.tar.xz in $CACHE_ROOT"
    else
        rm -f "$TARBALL_SUM"
        "$REPO_ROOT/.github/scripts/verify-kernel-tarball.sh" "$KERNEL_VERSION" "$TARBALL" || exit 1
        echo "$(sha256sum "$TARBALL" | awk '{print $1}') $VERIFY_HASH" > "$TARBALL_SUM"
    fi
    mkdir -p "$KDIR"
    tar -xf "$TARBALL" -C "$KDIR" --strip-components=1 || { rm -rf "$KDIR"; exit 1; }
    # >>> kernel build: everything from here to the <<< marker is hashed
    # into the cache stamp (SELF_HASH above).
    (
        set -e
        cd "$KDIR"
        # Same config as qemu-boot-test.yml's "Download and build a
        # bootable kernel" step (defconfig for GIC/PSCI/timer/virtio-mmio,
        # plus the explicit enables needed to actually boot to a working
        # init) - see that workflow for the full per-option rationale.
        make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
        ./scripts/config --enable CONFIG_MODULES
        ./scripts/config --enable CONFIG_KPROBES
        ./scripts/config --enable CONFIG_CRYPTO
        ./scripts/config --enable CONFIG_CRYPTO_HASH
        ./scripts/config --enable CONFIG_CRYPTO_MD5
        ./scripts/config --enable CONFIG_CRYPTO_SHA1
        ./scripts/config --enable CONFIG_CRYPTO_SHA256
        ./scripts/config --enable CONFIG_PROC_FS
        ./scripts/config --enable CONFIG_NET
        ./scripts/config --enable CONFIG_BINFMT_ELF
        ./scripts/config --enable CONFIG_BLK_DEV_INITRD
        ./scripts/config --enable CONFIG_DEVTMPFS
        ./scripts/config --enable CONFIG_DEVTMPFS_MOUNT
        ./scripts/config --enable CONFIG_SHMEM
        ./scripts/config --enable CONFIG_TMPFS
        ./scripts/config --enable CONFIG_TTY
        ./scripts/config --enable CONFIG_SERIAL_AMBA_PL011
        ./scripts/config --enable CONFIG_SERIAL_AMBA_PL011_CONSOLE
        ./scripts/config --enable CONFIG_PRINTK
        make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig
        make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc -j"$(nproc)" Image modules
    ) || { echo "test_detection_qemu.sh: kernel build failed"; rm -rf "$KDIR"; exit 1; }
    # <<< kernel build
    echo "$SELF_HASH" > "$STAMP"
fi

echo "test_detection_qemu.sh: building av.ko against $KDIR"
# CC=... is required, not optional, despite CROSS_COMPILE already being
# set: av/Makefile only does `CC ?= cc`, which is a no-op against GNU
# Make's own built-in default (CC = cc) - without an explicit CC= here
# this silently falls back to the host's native compiler and fails with
# arm64-specific flag errors (-mstack-protector-guard=sysreg etc.).
if ! make -C "$REPO_ROOT/av" KDIR="$KDIR" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc clean >/dev/null; then
    echo "test_detection_qemu.sh: 'make clean' failed"
    exit 1
fi
if ! make -C "$REPO_ROOT/av" KDIR="$KDIR" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc; then
    echo "test_detection_qemu.sh: av.ko build failed"
    exit 1
fi

echo "test_detection_qemu.sh: assembling initramfs"
cd "$QDIR" || exit 1
aarch64-linux-gnu-gcc -Wall -Wextra -static -O2 -o init init.c || exit 1
aarch64-linux-gnu-gcc -Wall -Wextra -static -O2 -o cold_launcher cold_launcher.c || exit 1
rm -rf root
mkdir -p root/proc root/dev root/tmp root/sys
cp init root/init
chmod 755 root/init
cp cold_launcher root/cold_launcher
chmod 755 root/cold_launcher
cp "$REPO_ROOT/av/av.ko" root/av.ko
# -R root:root: cpio otherwise stamps the archive with this machine's
# ownership, giving the guest a "/" owned by an unprivileged uid. The
# CI initramfs is packed the same way so the two harnesses agree on
# what the guest rootfs looks like. In copy-out mode this only sets
# header values, so it needs no privilege.
( cd root && find . -print0 \
    | cpio --null -o -H newc -R root:root 2>/dev/null \
    | gzip -9 ) > initramfs.cpio.gz

echo "test_detection_qemu.sh: booting in QEMU"
# TCG (software emulation) unless this happens to already be a native
# aarch64 host with a usable /dev/kvm - same fallback logic as
# qemu-boot-test.yml's "Boot in QEMU" step. On the ordinary case (x86_64
# dev machine, arm64 guest) KVM isn't an option at all - cross-arch
# virtualization acceleration isn't a thing - so this is TCG-only there.
ACCEL_ARGS=(-accel tcg -cpu max)
if [ "$(uname -m)" = "aarch64" ] && [ -w /dev/kvm ] 2>/dev/null; then
    ACCEL_ARGS=(-enable-kvm -cpu host)
    echo "test_detection_qemu.sh: native aarch64 host with /dev/kvm - using KVM acceleration"
fi

timeout 90 qemu-system-aarch64 \
    -M virt \
    -kernel "$KDIR/arch/arm64/boot/Image" \
    -initrd initramfs.cpio.gz \
    -append "console=ttyAMA0 panic=-1" \
    -display none \
    -serial file:serial.log \
    -no-reboot \
    -m 512M \
    "${ACCEL_ARGS[@]}" \
    || true # timeout/halt-instead-of-poweroff exit is expected - see qemu-boot-test.yml

rc=0
if grep -q "QEMU_TEST: PASS" serial.log; then
    echo "test_detection_qemu.sh: PASS"
else
    echo "test_detection_qemu.sh: FAIL - QEMU_TEST: PASS marker not found in serial.log"
    echo "--- serial.log ---"
    cat serial.log
    rc=1
fi

rm -f init cold_launcher initramfs.cpio.gz
rm -rf root
exit "$rc"
