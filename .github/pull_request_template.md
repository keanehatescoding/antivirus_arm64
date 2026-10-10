<!--
Before opening:

 - Target branch is `master` — there is no separate release branch.
 - Kernel-side changes must come with a VM run; please don't develop
   kernel-module code against hardware you can't afford to lose.
 - Security-sensitive fixes go through SECURITY.md (private), not here.
 - `tests/run_all.sh` is the pre-push gate. If you had to skip it with
   `--no-verify`, say why in the body.
-->

## Summary

<!-- 2-4 bullets. What this changes and why — the "why" matters more
than the "what", since the diff already shows the what. Link the issue
it fixes if there is one (e.g. `Closes #NN`). -->

-
-

## Component(s) touched

<!-- Tick the ones that apply. Each ticked box auto-applies the matching
label via `.github/workflows/label-components.yml`. -->

- [ ] `component:kernel` — `av/`
- [ ] `component:daemon` — `userspace/avd/`
- [ ] `component:cli` — `userspace/avctl/`
- [ ] `component:gui` — `userspace/av-gui/`
- [ ] `component:rules` — `rules/` or `corpus/`
- [ ] `component:tests` — `tests/`
- [ ] `component:packaging` — `debian/` or `packaging/`
- [ ] `component:ci` — `.github/workflows/`
- [ ] `component:docs` — README / wiki / `docs/` / `SECURITY.md`

## Test plan

<!-- The test matrix at the top of CONTRIBUTING.md names the minimum for
each component. Tick what you actually ran, and include enough context
that someone else could re-run it. "Ran run_all.sh" with no output is
not reproducible. -->

- [ ]
- [ ]

<!-- For kernel-side changes, include at minimum:
       - `sudo tests/test_detection.sh` (or the QEMU-boot run)
       - `sudo tests/test_sigtable.sh`
       - `dmesg` output around the behaviour you touched
     For `userspace/avd/`:
       - `sudo tests/test_avd_socket.sh`
     For hashing/scanning:
       - `tests/test_sha256.sh` / `tests/test_tlsh_core.sh` (no root)
     For rule changes:
       - sample that triggers the new/changed rule
       - negative controls against ordinary system binaries
         (/bin/ls, /bin/bash, …) — see rules/elf_analysis.yar for the
         bar `confidence` is held to. -->

## Risks / things reviewers should look at

<!-- Optional but welcome. Anything you're uncertain about, places you'd
want a second pair of eyes, assumptions you made that could be wrong,
backwards-compat concerns, or follow-ups that would be out of scope for
this PR. -->

<!--
Checks that run automatically (nothing to do here, just so you know):
  - CodeRabbit and Claude both leave inline review comments.
  - `.github/workflows/claude.yml` responds to `@claude` in a PR comment.
  - `build-matrix.yml`, `qemu-boot-test.yml`, `build-packages.yml` and
    `lint.yml` run on every push.
-->
