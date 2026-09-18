# Kernel-Level Linux Antivirus — Final Year Project

A Linux kernel-level antivirus built incrementally: starting from bare LKM
basics, through kprobe-based syscall hooking, to signature-based detection,
YARA/heuristic/entropy/fuzzy-hash scanning, and behavioral heuristics. `av/`
is the single evolving kernel module — milestones are marked with git tags,
not parallel folders. Four components: the kernel module (`av/`), a root
scanning/quarantine daemon (`avd`), a CLI (`avctl`), and a GTK4 GUI
(`av-gui`).

**📖 Full documentation lives in the [project wiki](../../wiki)** — architecture,
per-component internals, the detection engine, protocol specs, every manual
test walkthrough, evasion-testing findings, and CI/packaging details. This
README only covers what you need to get a build running.

**All development and testing happens inside a VM.** Kernel modules can and
will crash your kernel while you learn — snapshot your VM before every test
run.

```
snapshot the VM
insmod av.ko
test
dmesg | tail -50
rmmod av
# if it panics/hangs: restore snapshot, fix, repeat
```

## Repo layout

```
av/                  the kernel module — see wiki: Kernel-Module
rules/               YARA rule tiers — see wiki: Detection-Rules
corpus/              fuzzy-hash corpora (ssdeep + TLSH) — see wiki: Detection-Rules
userspace/avctl/     CLI — see wiki: avctl-CLI
userspace/avd/       scanning/quarantine daemon — see wiki: avd-Daemon
userspace/av-gui/    GTK4 management console — see wiki: av-gui
docs/                protocol specs + evasion findings (mirrored in the wiki)
packaging/           systemd unit, polkit policy, Flatpak/AppImage manifests
debian/, packaging/{arch,fedora}/  distro packages — see wiki: CI-and-Packaging
tests/               automated + evasion + QEMU-boot CI tests — see wiki: Testing
scripts/             setup-hooks.sh, av-reload.sh
```

## Prerequisites (inside the VM)

```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r) git
```

## Building

```bash
cd av
make
sudo insmod av.ko
dmesg | tail -20
sudo rmmod av
```

Targets arm64 (aarch64) kernels 5.7+ only (hooks `__arm64_sys_execve` by
symbol name — see the wiki's **Kernel Module** page for why x86_64 isn't
supported). `make CC=clang LLVM=1` builds against a Clang-built kernel.
Behavioral thresholds are load-time module params; see the wiki's
**Behavioral Heuristics** page.

## Running the full stack

```bash
# daemon (root, scans/quarantines files)
cd userspace/avd && make && sudo make install
sudo systemctl enable --now avd.service

# CLI (manages signatures/trust/protected-paths/policy, talks to avd)
cd ../avctl && make && sudo make install

# GUI (optional, talks to avd + avctl, never touches the kernel module directly)
cd ../av-gui && make && sudo make install
av-gui
```

See the wiki's **Building and Running**, **avd Daemon**, **avctl CLI**, and
**av-gui** pages for install-path overrides (`PREFIX`/`SYSCONFDIR`/`UNITDIR`/
`DESTDIR`), the systemd unit's security model, and the Flatpak/AppImage
builds.

`avd` can additionally run a fanotify `FAN_OPEN_EXEC_PERM` exec gate, which
scans the kernel-supplied fd instead of a pathname and so closes the kprobe
path's TOCTOU/cold-page gaps on the mounts it covers. It is **off by
default** and opt-in per deployment — see the wiki's **Fanotify Exec Gate**
page for its tunables and for what fail-closed does and doesn't cover.

## Testing

```bash
tests/run_all.sh
```

Runs nine suites in a fixed order: the four that need neither root nor a
loaded module first, then the exec gate, then the ones that insmod `av.ko`.
On a non-aarch64 host the module-dependent ones skip loudly and
`test_detection.sh` cross-compiles and QEMU-boot-tests instead. Two scripts
are deliberately **not** in `run_all.sh` (`test_avctl_timeouts.sh` and
`benchmark.sh`); the wiki's **Testing** page says why, covers what each
suite checks, and has manual, step-by-step walkthroughs of every detection
layer (signatures, YARA, ELF analysis, entropy, fuzzy hashing, behavioral
heuristics, quarantine/TOCTOU). The EICAR antivirus test file — a standard,
harmless 68-byte string every real AV vendor uses for exactly this purpose —
is used throughout instead of real malware.

## CI

Eight workflows, four of them tiers that run on every push and PR:
shellcheck/cppcheck/yamllint lint, a compile matrix (gcc/clang × 3 kernel
versions), a QEMU boot test with real runtime detection, and a packaging
build (deb/Arch/Fedora). The rest: a weekly kernel-matrix refresh, tagged
releases, and two Claude Code integrations. Everything module-related runs
on native arm64 runners. Details in the wiki's **CI and Packaging** page.

## Documentation index

Start at the wiki's [Home](../../wiki) page, which groups all of the below
and carries an honest-status section (what works, what's opt-in, what is
still a known gap).

**Design**
- [Architecture](../../wiki/Architecture) — kernel vs. userspace split, the two exec paths, kernel taint checks
- [Kernel Module](../../wiki/Kernel-Module) / [avd Daemon](../../wiki/avd-Daemon) / [avctl CLI](../../wiki/avctl-CLI) / [av-gui](../../wiki/av-gui) — per-component internals
- [Fanotify Exec Gate](../../wiki/Fanotify-Exec-Gate) — the opt-in `FAN_OPEN_EXEC_PERM` path, and the limits of its fail-closed mode

**Detection**
- [Detection Rules](../../wiki/Detection-Rules) — weighted YARA scoring, entropy/ELF tiers, fuzzy-hash corpora
- [Behavioral Heuristics](../../wiki/Behavioral-Heuristics) — the kernel-side ransomware/self-delete/sensitive-path engine and its four real false-positive incidents
- [Evasion Findings](../../wiki/Evasion-Findings) — adversarial testing against the engine itself

**Protocols**
- [Netlink Protocol](../../wiki/Netlink-Protocol) / [avd Socket Protocol](../../wiki/avd-Socket-Protocol) — the two IPC channels (mirrors of `docs/`)

**Operations**
- [Building and Running](../../wiki/Building-and-Running) — install-path overrides, the systemd unit, distro packages
- [Testing](../../wiki/Testing) — automated suites and manual walkthroughs
- [CI and Packaging](../../wiki/CI-and-Packaging) — the four tiers and the per-packaging-file gotchas

## Security

See [SECURITY.md](SECURITY.md) for scope, already-accepted tradeoffs
(fail-open by default, a documented kernel TOCTOU gap, arm64-only), and how
to report a vulnerability privately.
