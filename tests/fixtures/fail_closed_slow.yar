/*
 * fail_closed_slow.yar - TEST FIXTURE ONLY, never installed to production.
 * Staged into the QEMU initramfs alongside tests/fixtures/test.yar (see
 * .github/workflows/qemu-boot-test.yml) and never into a production rules
 * dir, for the same reason as that file: it exists to make a test do
 * something, not to detect anything real.
 *
 * Single rule with an expensive nested quantifier over a uniform input
 * (`/(a|aa)+b/` against a file of all 'a's with no trailing 'b'): the
 * engine must explore an exponential backtrack tree before failing the
 * match, so the scan takes seconds instead of milliseconds while matching
 * NOTHING (no 'b' present, so no conviction regardless of score).
 * Calibrated on libyara 4.5.x: an 8KB all-'a' file needs ~6s and returns
 * ERROR_SCAN_TIMEOUT under timeout=1 deterministically (3/3 trials), and
 * completes under timeout=10. That gap is what the QEMU gate case uses:
 * with AVD_SCAN_TIMEOUT_SECS=1 the scan always times out (incomplete=1)
 * while small clean/malicious files still scan in ~1ms, so the exec
 * outcome reads the fail-closed flag and nothing else. Under TCG the
 * guest is slower, which only widens the margin (timeout more certain,
 * small files still far under 1s).
 *
 * The rule CAN match ordinary binaries (any "ab" byte pair satisfies
 * it) - that is harmless, not a false positive: weight = 1 with no
 * override can never convict alone (1 + Entry_Point_Outside_Text's 30
 * = 31, far below MALICIOUS_SCORE_THRESHOLD), and on the staged
 * all-'a' slow file there is no 'b' at all, so nothing matches there.
 * The slowness is the fixture; conviction must never come from it.
 */

rule Slow_Calibration_Backtrack
{
    meta:
        description = "CALIBRATION ONLY - expensive nested quantifier for fail-closed timeout testing, never a real detector"
        weight = 1
    strings:
        $a = /(a|aa)+b/
    condition:
        $a
}
