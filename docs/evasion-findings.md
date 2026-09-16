# Evasion Resistance Findings

## 1. Dynamic symbol resolution vs. API import heuristics

`rules/heuristics.yar`'s `Imports_Ptrace` rule checks YARA's `elf.dynsym`
table — the binary's static dynamic-symbol imports. Resolving `ptrace`
at runtime via `dlopen("libc.so.6")` + `dlsym(handle, "ptrace")` instead
of linking it directly means there's no direct import entry to find.

Verified: `objdump -T` on the evasion binary shows no `ptrace` entry, and
`yara rules/heuristics.yar` reports no `Multiple_Suspicious_Imports` match
(the only public rule that could fire - the `Imports_*` sub-rules are
`private` building blocks and never surface in CLI output or `avd` scoring).

**Interesting nuance**: the evasion technique itself isn't free —
`Imports_Dlopen` (a rule explicitly marked "very low confidence, do not
alert on this alone" since `dlopen` is ubiquitous in legitimate
software) still fires. This doesn't mean the evasion failed — `dlopen`
alone is far too common to act on — but it's a reminder that evasion
techniques can leave their own fingerprints, and a more sophisticated
engine could build a meta-heuristic specifically for "uses dynamic
symbol resolution instead of static linking for a small number of
specific functions" as its own (still weak, but non-zero) signal.

**Mitigation directions** (not implemented, discussion only): scanning
`.rodata`/string sections for the literal string `"ptrace"` alongside
the import check would catch this specific case (the string still has
to appear somewhere for `dlsym` to look it up) — though that's
defeatable too (string obfuscation, building the name character-by-
character at runtime). This is a genuine cat-and-mouse dynamic, worth
stating plainly rather than implying any static analysis is airtight.

## 2. Substantial modification vs. fuzzy hashing

Fuzzy hashing (CTPH/ssdeep) is explicitly designed to tolerate *minor*
changes — the v0.7.0 testing already showed a few appended bytes
scoring 100/100 similarity. This test checked the boundary: how much
change breaks it?

Verified: appending 50KB of random data to a ~16KB binary (roughly
tripling its size with unrelated content) dropped the similarity score
to 0/100 — full evasion, using the exact `fuzzy_compare()` call `avd.c`
uses.

**This is expected, not a bug.** CTPH is a rolling-hash, block-based
similarity measure — it's designed to detect "this is basically the
same file with small edits," not "this file shares some heritage with
that one." A well-known, honest limitation of the technique, not
specific to this implementation. Real-world malware families that get
substantially repacked/recompiled between variants will evade a
fuzzy-hash corpus check the same way, which is exactly why this project
treats fuzzy hashing as one signal among several rather than a
standalone detector.

## 3. Entropy dilution vs. entropy analysis — testing defense-in-depth

This is the most important finding of the four, because it tests the
project's core design premise directly: **does evading one layer mean
evading the engine?** The answer changed twice as the project evolved,
and the full sequence is worth documenting rather than just the final
state.

**Original result (any-match-convicts era)**: padding a UPX-packed
binary with 500KB of zero bytes dilutes the *whole-file* Shannon
entropy average below the 7.0 threshold — `entropy.yar`'s
`High_Overall_Entropy` no longer fires on the padded file. But the
same padded file was still caught by `elf_analysis.yar`
(`No_Section_Headers` + `Entry_Point_Outside_Text`), since padding with
zero bytes doesn't restore the section headers UPX stripped. **Evading
the entropy check did not evade the engine.**

**Regression (v0.9.1 weighted-scoring era)**: after real testing killed
`zsh`/`sh`/`uwsm` on single weak matches and the detection logic moved
to summed rule weights against a 100-point threshold, the same
evasion sample was re-scored: `No_Section_Headers`(55) +
`Entry_Point_Outside_Text`(30) = **85**, below the new threshold. The
fix for one real problem (false positives from single weak matches)
silently broke this finding — evading entropy analysis now evaded the
*whole pipeline*, not just one layer. This is a direct, mechanical
tradeoff, not a coincidence: making conviction harder in general makes
every individual evasion easier by the same amount.

**Fix (override tier)**: rather than choosing between "some false
positives" and "some false negatives" as a global setting, a small,
deliberately narrow set of rules — verified against both real positive
and negative samples, with no known false-positive history —
now carry `override = true` and convict on their own regardless of
aggregate score. `No_Section_Headers` and `Executable_Stack` qualify;
`Entry_Point_Outside_Text` (the rule that actually false-positived on
`uwsm`) and `Has_RWX_Segment` (never verified against a real sample)
deliberately do not. Re-scored: `No_Section_Headers` alone now
convicts via override, restoring the original conclusion — the
numeric score is still 85/100 (override doesn't change the weight
sum), but `override=1` means it convicts regardless of the number.

The real lesson here isn't "the engine is robust" — it's that a fix
for one failure mode (false positives) can silently reintroduce a
different one (false negatives) if you don't re-run your adversarial
tests after every change to the scoring logic. Evasion testing is not
a one-time checkbox; it needs to be re-run whenever detection logic
changes, and this finding is the concrete proof of why.

## 4. Slow-drip modification vs. rapid-write behavioral heuristic

**Update (post-`v0.8.1`/`sliding_window_note()`): re-verified live
against the current module. The specific discrete-reset bug described
below is fixed. A related but distinct evasion — deliberately pacing
bursts with gaps beyond the window size — still succeeds in the tested
configuration, and, unlike the bug, is not fixable by any finite
windowed counter. Both results below are from real `dmesg` captures,
not code-path inference.**

`behavior.c`'s rapid-write counter originally used a **fixed window**,
not a true sliding window:

```c
if (e->window_start_jiffies == 0 || window_ms > WRITE_OPEN_WINDOW_MS) {
    e->window_start_jiffies = jiffies;  /* window resets ENTIRELY */
    e->write_open_count = 1;
} else {
    e->write_open_count++;
    ...
}
```

Once more than 2 seconds had passed since the window started, the
counter reset to 1 regardless of how many writes happened, discarding
even genuinely recent activity the instant a reset landed. This wasn't
only an adversarial-pacing problem: a steady, non-adversarial write
stream that happened to straddle a reset boundary could lose its own
accumulated progress with no deliberate evasion involved.

**This part is now fixed.** `sliding_window_note()` replaced the
discrete reset with a real trailing window — each tracked write now
carries its own timestamp and individually ages out after
`WRITE_OPEN_WINDOW_MS`, rather than the whole window being wiped in
bulk on a boundary crossing. Verified live (see the fix's own PR): a
steady ~66 files/sec stream (150 distinct files, ~15ms apart, spanning
past the old 2000ms reset point with no pauses) now correctly trips at
exactly the 51st distinct file — the old implementation could not have
caught this, since it would have reset mid-stream and needed 50 fresh
events after the reset within the little time remaining.

**What's still not fixed — and can't be, by a windowed counter alone**:
re-running `tests/evasion/test_slow_drip_evasion.sh` (40-file bursts,
5 bursts, paced 2.1s apart — 100ms *beyond* the 2-second window, not
merely at it) against the current sliding-window implementation still
produces **no** `rapid file modification` kill in `dmesg`, despite 200
files modified in total. This is not the discrete-reset bug
reappearing: `sliding_window_note()` retains an entry while
`age <= window_ms` (inclusive - see its comment/implementation in
`behavior.c`), so it legitimately forgets a write only once that
write's age strictly exceeds `WRITE_OPEN_WINDOW_MS`. That's what makes
it a rate counter instead of a lifetime counter, and it means this
specific finding is narrower than "pacing at or above the window
evades" - it's specifically pacing *beyond* the window that does, in
this tested configuration (this 2.1s gap, `WRITE_OPEN_THRESHOLD`'s
current value); an adversary pacing exactly at the boundary would
still land inside the inclusive `<=` and get counted. The generalizable
point isn't about this exact configuration, though: it's that *any*
positive, finite window/threshold pair - sliding or fixed, whatever
their specific values - remains evadable by pacing slowly enough
relative to *that* configuration. No amount of window-size or
threshold tuning closes this off entirely, only shifts where the
evasion threshold sits; doing so would require a different class of
mechanism (e.g. tracking total volume over a much longer horizon, or a
behavioral signal beyond simple event counting). Worth stating
precisely: the implementation bug is gone; the inherent limitation of
finite counting-based rate limiting is not, and isn't something this
design can fully close.

## 5. Pathname games vs. the exec hook — and what actually closes them

The first four findings are all about *what* gets scanned. This one is
about *which file* gets scanned, and it defeats every layer above at
once: if the verdict is computed against the wrong bytes, the quality of
the analysis applied to them is irrelevant.

`av/main.c`'s kprobe handler reads the exec'd pathname out of userspace
with `strncpy_from_user()` and `av_work_fn()` later re-opens that
pathname. Both halves of that are evadable, and issue #2 tracks both:

- **Cold pathname page.** The pre-handler runs in atomic context and
  cannot sleep to fault a page in, so a pathname on a genuinely
  non-resident page returns `-EFAULT` and the handler allows the exec
  without scanning anything. `tests/qemu-boot/cold_launcher.c`
  reproduces this on every CI run. Note the measured nuance: a plain
  `.rodata` string literal did *not* reproduce it — fault-around pulls
  the literal's page in alongside `.text`. Coldness has to be
  constructed (file-backed `MAP_PRIVATE` mapping, `MADV_DONTNEED`,
  never touched), which is a real constraint on an attacker but not a
  meaningful one.
- **TOCTOU on the re-open.** `open_exec_target()` is a second, later
  open of the same name. Swapping what that name resolves to between
  the kernel's own resolution and ours means the verdict describes a
  file that is not the one executing.

Unlike findings #1, #2 and #4, this one is **not** an inherent limit of
the technique — it is an artifact of *where the hook sits*. The verdict
is derived from a pathname the module copied itself rather than from the
file object the kernel had already resolved. Given the resolved file,
neither evasion has anything to work with: there is no pathname copy to
leave cold, and no second lookup to race.

Reaching that file object from a loadable module turns out to be
impossible, which is the genuinely interesting constraint here:
`security_add_hooks()` is `__init` and unexported, and the active LSM
set is fixed at boot by `CONFIG_LSM=`/`lsm=`, so an `insmod`'d module
can never register `bprm_check_security` no matter how it is written.
The fix therefore has to leave the module — discussion #33 weighs an
in-tree LSM (correct, unshippable), a BPF LSM (needs `lsm=...,bpf` at
boot), and fanotify `FAN_OPEN_EXEC_PERM` in `avd`, which is what
shipped.

Verified side by side in `tests/fanotify_exec_gate.c`: with a target
whose content reads `SPIKE-PAYLOAD-MALICIOUS` and a rename-swap
performed while the exec is suspended awaiting a verdict, the
kernel-supplied event fd names the inode that is actually executing
while re-opening the pathname sees the decoy — the two disagree, and
the fd-derived `FAN_DENY` is what the kernel enforces. The cold-pathname
launcher is likewise delivered and blocked, because no pathname was
copied in atomic context for it to defeat.

**Worth being precise about the residual risk**, since this is the one
finding here with a fix rather than an acceptance: the gate is off
unless `AVD_FANOTIFY_EXEC=1`, covers only the mounts named in
`AVD_FANOTIFY_MARK`, and the kprobe path it sits beside is unchanged
and still has both gaps. Its own remaining fail-open surface is queue
overflow (`FAN_Q_OVERFLOW`), where events are dropped and the execs
behind them proceed unchecked — logged loudly rather than silently
tolerated, but a real ceiling set by `fs/fanotify/max_queued_events`.
The other no-verdict paths (unscannable file, scan that does not
conclude) are governed by `AVD_FANOTIFY_FAIL_CLOSED` and exercised at
runtime by the QEMU gate case (issue #51); the per-scan YARA budget
behind that case is tunable via `AVD_SCAN_TIMEOUT_SECS`.

One methodological note that generalizes past this finding: because a
permission event *suspends* the exec until the listener answers, the
swap window is open for as long as the test wants it. The TOCTOU here
is normally a race to demonstrate; against a permission-event listener
it is deterministic, which is what makes it usable as a regression
guard rather than a flaky one.

## Overall takeaways for the report

- Every individual detection layer has a known, demonstrable evasion.
  This is expected and honest — no single technique here is claimed to
  be unbeatable, and presenting them as if they were would be the
  wrong takeaway.
- Finding #5 is the sharpest version of the "we ran out of scope" vs.
  "this is as good as this approach gets" distinction below, and it
  lands on a third answer neither phrase covers: *this is as good as
  this approach gets, so the approach had to move*. The evasion was not
  a limit of the scanning at all — it was a limit of where the hook
  could sit, and a loadable module provably cannot sit anywhere better.
  That is worth separating from #1/#2/#4's genuinely inherent limits,
  because it is the one case where the right answer was to change the
  mechanism rather than accept the finding.
- The one deliberately-designed defense (layering independent checks)
  held up under direct testing (finding #3) — evading entropy analysis
  did not evade the structural analysis running alongside it.
- Finding #4 is the one case where re-testing after a fix actually
  changed the picture, and it changed it in an instructive way: the
  *implementation* half (discrete-reset window) had a known, named
  structural fix (true sliding window) and re-verification confirmed
  it closed - but doing so exposed the *inherent* half underneath
  (deliberate pacing at or under the rate limit) as the same category
  of unfixable-by-this-technique-alone limitation as #1 and #2, not
  something the sliding-window fix was ever going to reach. Worth
  distinguishing "we ran out of scope" from "this is as good as this
  approach gets" when discussing each finding - and, per #4, worth
  re-checking that distinction after a fix lands rather than assuming
  it once and leaving it stated.
