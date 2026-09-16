/*
 * fail_closed_slow.yar - TEST FIXTURE ONLY, never installed to production.
 * Staged into the QEMU initramfs alongside tests/fixtures/test.yar (see
 * .github/workflows/qemu-boot-test.yml) and never into a production rules
 * dir, for the same reason as that file: it exists to make a test do
 * something, not to detect anything real.
 *
 * Three rules with distinct exponential-backtrack patterns (`/(a|aa)+b/`,
 * `/(a|aaa)+b/`, `/(aa|aaa)+b/`) over a uniform all-'a' input with no
 * trailing 'b': each rule explores its own backtrack tree before failing,
 * and the costs ADD (YARA checks every rule until the timeout fires), so
 * a 1.5KB file needs ~1.35s while matching NOTHING (no 'b' present, so no
 * conviction regardless of score).
 *
 * Calibrated on libyara 4.5.x: a 1.5KB all-'a' file returns
 * ERROR_SCAN_TIMEOUT under timeout=1 deterministically (3/3 trials),
 * while small clean/malicious files scan in ~1ms. That gap is what the
 * QEMU gate case uses: with AVD_SCAN_TIMEOUT_SECS=1 the scan always
 * times out (incomplete=1) and the exec outcome reads the fail-closed
 * flag and nothing else. Under TCG the guest is slower, which only
 * widens the margin (timeout more certain, small files still far under
 * 1s).
 *
 * Every rule is weight = 1 with no override: even if a future input
 * accidentally matches one, it scores 1 + Entry_Point_Outside_Text's
 * 30 = 31, far below MALICIOUS_SCORE_THRESHOLD. The slowness is the
 * fixture; conviction must never come from it.
 */

rule Slow_Calibration_00
{
    meta:
        description = "CALIBRATION ONLY - exponential backtrack for fail-closed timeout testing, never a real detector"
        weight = 1
    strings:
        $a = /(a|aa)+b/
    condition:
        $a
}

rule Slow_Calibration_01
{
    meta:
        description = "CALIBRATION ONLY - exponential backtrack for fail-closed timeout testing, never a real detector"
        weight = 1
    strings:
        $a = /(a|aaa)+b/
    condition:
        $a
}

rule Slow_Calibration_02
{
    meta:
        description = "CALIBRATION ONLY - exponential backtrack for fail-closed timeout testing, never a real detector"
        weight = 1
    strings:
        $a = /(aa|aaa)+b/
    condition:
        $a
}
