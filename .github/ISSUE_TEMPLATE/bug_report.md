---
name: Bug report
about: Something behaves wrong, crashes, or disagrees with its own docs
title: ''
labels: bug
assignees: ''
---

<!--
Before filing, two quick checks:

 1. **Is this security-sensitive?** A crash reachable from an unprivileged
    process, a privilege-escalation path, auth bypass on netlink or the
    control socket, a quarantine escape — those go through SECURITY.md
    (private reporting), not here. See the "What counts" section there if
    you're unsure.
 2. **Have you tested it in a VM, snapshotted first?** Kernel-module bugs
    can hang or crash the host. The project itself is only developed and
    tested in VMs — please do the same before filing.
-->

## What happened

<!-- One or two sentences. What you did, what the result was, what you
expected instead. File:line references welcome if you've already read the
code. -->

## Which component

<!-- Tick the ones that apply. Delete the rest. Multiple can apply (a
netlink regression is both av/ and avd/, for example). -->

- [ ] `av/` — kernel module (`av.ko`, kprobes, netlink, `/proc` interfaces)
- [ ] `userspace/avd/` — root daemon (scan pipeline, quarantine, fanotify gate, control socket)
- [ ] `userspace/avctl/` — CLI and its polkit actions
- [ ] `userspace/av-gui/` — GTK4 console
- [ ] `rules/` or `corpus/` — detection content (YARA rules, ssdeep/TLSH corpora)
- [ ] `tests/` — a test is wrong, flaky, or asserting the wrong thing
- [ ] `debian/` / `packaging/` — distro package build or install scripts
- [ ] `.github/workflows/` — CI
- [ ] Docs — README / wiki / `docs/` / `SECURITY.md`
- [ ] Other / unsure

## Reproduction

<!-- Minimal steps someone else can run in a VM to see the same thing.
Prefer actual commands over prose. If it needs a specific file (e.g. an
EICAR sample, a crafted ELF, a particular rules dir), say how to produce
it — do NOT attach real malware. -->

```
# commands here
```

## Observed vs. expected

<!-- The actual output / dmesg lines / stderr, and what you expected
instead. Trim long logs to the relevant window — a 2000-line dmesg paste
is harder to act on than the 20 lines around the event. -->

**Observed:**

```
```

**Expected:**

```
```

## Environment

- Commit SHA tested against: <!-- `git rev-parse HEAD` -->
- Kernel: <!-- `uname -r` and distro, e.g. `6.12.1-arch1-1 (Arch)` -->
- Architecture: <!-- `uname -m` — `aarch64` or `x86_64`; see README for arm64-only pieces -->
- VM or bare metal: <!-- this project is developed and tested exclusively in VMs; say so if you hit it on bare metal -->
- Install method: <!-- `insmod` directly from `av/`, DKMS via one of the packages, Flatpak/AppImage for the GUI, etc. -->
- Daemon policy: <!-- `avctl policy get` — fail-open (default) or fail-closed; omit if the bug is clearly unrelated -->
- Fanotify exec gate: <!-- `AVD_FANOTIFY_MARK` value if set, or "unset (gate inactive)"; omit if unrelated -->

## Possible fix / notes

<!-- Optional. If you've looked at the code, point at the file:line you
suspect. A guess that turns out to be wrong is still useful — it
narrows the search for whoever picks this up. -->

<!-- CI logs: if the failure is on a PR, link the specific job run rather
than pasting the full log. -->
