# Security Policy

This is a kernel module (`av.ko`) paired with a root-privileged userspace
daemon (`avd`), a polkit-gated CLI (`avctl`), and a GTK4 GUI (`av-gui`). Bugs
here can mean kernel panics, privilege escalation, or a root daemon acting on
the wrong file — please report privately rather than opening a public issue
or PR.

## Supported versions

Tags exist for past milestones (`v0.1.0` through `v0.9.0`), but `master`
is currently well over a hundred commits ahead of the latest one. Only
current `master` HEAD is supported.

| Version                    | Supported |
| ---------------------------- | :-------: |
| `master` (HEAD)               | ✅ |
| `v0.9.0` and earlier tags     | ❌ |

When you report something, include the commit SHA you tested against
(`git rev-parse HEAD`).

## Scope

**In scope:**

- `av/` — the kernel module: kprobe hooks on execve/openat/unlink/rename and
  friends, signature matching, behavioral heuristics, and the netlink
  channel to `avd`
- `userspace/avd/` — the root-privileged scanning/quarantine daemon and its
  Unix control socket (`/run/avd/control.sock`)
- `userspace/avctl/` — the CLI and its polkit policy (`org.hyprav.avctl.policy`,
  the per-verb `org.hyprav.avctl.*` actions)
- `userspace/av-gui/` — the GTK4 console and its `pkexec` bridge to `avctl`
- Packaging under `debian/` and `packaging/` — the DKMS `postinst`/`prerm`
  scripts run as root, so a bad one is a real finding, not just a build issue

**Out of scope:**

- Bugs in YARA, libfuzzy (ssdeep), or the vendored TLSH code itself —
  report those upstream, unless the issue is specifically in how this
  project calls them
- "You didn't catch my sample" — detection/evasion gaps in the rules
  themselves are tracked in `docs/evasion-findings.md`, not security bugs

## What counts as a security issue

For a kernel-level tool the bar is wider than for typical userspace
software. All of the following are in scope:

- Kernel panics, hangs, or memory corruption reachable from an unprivileged
  process — a crafted syscall sequence, a malformed netlink message, or a
  file that triggers a bug during scanning
- Privilege escalation, whether through the kernel module, `avd` running
  as root, or `avctl`/polkit (e.g. a privileged verb running without going
  through the real, *installed*, polkit-gated path)
- Auth bypass on either IPC channel — the netlink `genl` channel (should
  require `CAP_NET_ADMIN` and be pinned to the registered daemon's portid)
  or `avd`'s control socket (authenticated via `SO_PEERCRED`)
- Quarantine bugs — path traversal, symlink races, or anything that makes
  quarantine act on a file other than the one that was actually scanned
- Anything that leaves the system fail-open after an operator has
  explicitly set `avctl policy set fail-closed`

`docs/netlink-protocol.md`'s "Known limitations" section and the README's
"TOCTOU protection" section are the closest thing this project has to a
running threat-model doc, and worth a skim before reporting — daemon
impersonation, forged scan requests, and a module-unload use-after-free
were all real findings there, already patched, not hypotheticals. That's
the caliber of report this section is asking for.

## Already-known, already-accepted tradeoffs

Please don't file a report for these — they're deliberate and documented,
not oversights. A *new* way to defeat one of them is still very welcome:

- **Fail-open by default.** If `avd` is unreachable or times out, the
  kernel module lets the exec through rather than blocking it, so a
  crashed daemon can't become a system-wide DoS. `avctl policy set
  fail-closed` opts out of this. See `docs/netlink-protocol.md`.
- **Kill-after-exec, not exec-time blocking** (kernel side). The module's
  exec hook is a kprobe pre-handler on the kernel's own exec path
  (`bprm_execve`, or `security_bprm_check`), and a kprobe cannot change
  the probed function's return value, so it cannot veto an exec. It hashes asynchronously on a workqueue and `SIGKILL`s what
  matched, which means a flagged image has usually already started running
  — briefly — by the time the kill lands. Exec-time *prevention* is `avd`'s
  fanotify gate, below.

  This is what is left of issue #2 after #94. Until then the hook probed
  `__arm64_sys_execve`/`execveat` and copied the pathname argument out of
  userspace, which carried two real bypasses, both now closed:

  - **Cold pages.** `strncpy_from_user()` in atomic/kprobe context cannot
    sleep to fault in a non-resident page, so a pathname on a genuinely
    cold page returned `-EFAULT` and the hook skipped the exec silently.
  - **Exec-time TOCTOU** (issue #45). The hash came from a *separate,
    later* `open()` of that pathname on the workqueue; renaming a clean
    decoy over the path in between got the decoy hashed while the real
    image ran.

  Both had one cause — the verdict was computed from a pathname the module
  copied itself rather than from the file the kernel had already resolved —
  and both are gone now that the hook pins `bprm->file`, the exact `struct
  file` the kernel is about to execute, and hashes that. Note this is *not*
  an LSM hook: `security_add_hooks()` is `__init` and unexported, so
  nothing loaded with `insmod` can ever register `bprm_check_security`.
  The kprobe only *observes* a function the kernel's own exec path calls,
  which gets the kernel's resolved file without registering anything — but
  also without the ability to deny, hence the first paragraph.

  Which function is a load-time decision (`av_exec_hook_candidates[]` in
  `av/main.c`), because neither candidate is probeable everywhere:
  `bprm_execve()` is the single caller of the binfmt search, entered with
  `bprm->file` already set, but it is file-local to `fs/exec.c` and a
  compiler free to inline or clone it would take the name away;
  `security_bprm_check()` is global and cannot be renamed, but since the
  LSM layer moved hook dispatch to static calls its entry is a jump-label
  patch site, and `register_kprobe()` rejects those with `-EINVAL`. The
  module tries `bprm_execve` first, falls back, logs which one it got, and
  refuses to load if neither works rather than scanning no execs at all.

  Both former bypasses stay closed by regression cases that assert
  unconditionally on every CI run.
  `tests/qemu-boot/cold_launcher.c` still execve()s from a pathname page
  it guarantees is cold (fresh file-backed mapping, never faulted,
  `MADV_DONTNEED`'d before exec) and now *requires* that exec to be
  detected and killed. The batch case in `tests/qemu-boot/init.c` renames
  a clean decoy over an EICAR exec target strictly *after* exec entry
  (ordered by a sync pipe, with the deferred hash parked by
  `av_toctou_test_delay_ms` so the rename always lands mid-scan) and
  requires that no attempt gets the decoy hashed and that the swaps are
  killed on the EICAR that actually executed, with an interleaved no-swap
  control detected and killed every time.

  `avd`'s **fanotify exec gate** (`FAN_OPEN_EXEC_PERM`, discussion #33
  option C) is the preventive half: it scans the kernel-supplied event fd
  and answers allow/deny *before* the exec proceeds. The gate is **on by
  default and activates as soon as
  `AVD_FANOTIFY_MARK=<mountpoint>[:...]` names at least one mount** —
  there is deliberately no default mark set, since marking a mount
  suspends every exec on it until `avd` answers, so the scope is the
  operator's call. `AVD_FANOTIFY_EXEC=0` turns the gate off entirely.
  On an install with no `AVD_FANOTIFY_MARK` set the gate is inactive and
  the kprobe path is the only exec check, so execs on that install are
  detected-and-killed rather than blocked — don't report that, but a way
  to defeat the *gate* on a mount it covers (or to evade it via a mount
  it does not cover) is very much in scope.
- **arm64 only.** The behavioral hooks resolve `__arm64_sys_*` syscall
  symbols by name and the module will not build or load on x86_64. (The
  exec hook itself is arch-independent — `bprm_execve` /
  `security_bprm_check` — but the rest is not.)

## Reporting

Preferred: GitHub's private vulnerability reporting on this repo
(Security tab → **Report a vulnerability**). If that isn't turned on,
email **159132270+keanehatescoding@users.noreply.github.com**.

Please include:

- The commit SHA you tested against
- Kernel version and distro (`uname -r`), and whether you installed via
  `insmod` directly or one of the DKMS packages
- Repro steps or a PoC, and what you expected vs. what actually happened
- Whether this was in a VM or on bare metal — this project is developed
  and tested exclusively in VMs, snapshotted before every run. If you hit
  a kernel panic on bare metal, say so up front.

## What to expect

This is a solo, final-year-project maintainer, not a security team, so
please don't expect a corporate SLA. I'll aim to acknowledge reports within
about a week and keep you posted while I work through it. There's no bug
bounty. I'd ask for reasonable time to land a fix before any public
disclosure — happy to agree a specific timeline once I understand the
report.

## Good-faith testing

If you're testing kernel-panic or privilege-escalation scenarios, please
do it in a VM you control — the same way this project's own test suite
does — not against a shared or production machine.
