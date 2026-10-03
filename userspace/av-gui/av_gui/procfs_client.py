"""Reads signatures/trust/protected-paths/policy via `avctl save -`
(stdout mode - see do_save() in userspace/avctl/avctl.c) rather than
reading /proc/kernel_av_* directly: this reuses avctl's existing,
already-tested line format instead of a second parser in Python. Note
this needs root: the IOC entries have been 0600 owner-only reads
since #32, so a non-root `avctl save -` fails with EACCES (surfaced
here as ProcfsError) and only the 0644 daemon-policy entry stays
world-readable. See docs/avd-socket-protocol.md's note on why the GUI
reuses this format instead of adding a second read protocol.
"""
import os
import subprocess

from . import avctl_path, host_exec


class ProcfsError(Exception):
    """Raised when `avctl save -` can't be run or exits non-zero -
    either the kernel module isn't loaded (see avctl's own "is the av
    module loaded?" hint in its error output, passed through here via
    stderr) or the caller isn't root (the IOC entries are 0600
    owner-only since #32, so avctl reports a permission hint instead)."""


def read_state():
    """Returns a dict: signatures (list of {algo, hash, name}), trust
    (list of {hash, name}), protected (list of path strings), policy
    (str, "fail-open"/"fail-closed", or None if unavailable)."""
    try:
        # Capture raw bytes: os.fsdecode below preserves non-UTF-8 names
        # without replacement characters, and skipping text= avoids the
        # universal-newline conversion that would turn a literal \r or
        # \r\n inside a filename into the protocol's record separator.
        result = subprocess.run(
            host_exec.host_argv(
                [avctl_path.resolve_unprivileged_avctl_path(), "save", "-"]
            ),
            capture_output=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProcfsError(f"could not run avctl: {exc}") from exc

    if result.returncode != 0:
        raise ProcfsError(os.fsdecode(result.stderr).strip() or "avctl save - failed")

    signatures = []
    trust = []
    protected = []
    policy = None

    # Split only on the protocol's LF. str.splitlines() also treats legal
    # filename codepoints (\r, \v, \f, \x1c-\x1e, \x85, U+2028, U+2029,
    # lone surrogates) as record boundaries, which silently drops the
    # remainder of any record whose name contains one (issue #80).
    for line in os.fsdecode(result.stdout).split("\n"):
        if not line or line.startswith("#"):
            continue
        if line.startswith("sig add "):
            parts = line[len("sig add "):].split(" ", 2)
            if len(parts) == 3:
                signatures.append({"algo": parts[0], "hash": parts[1], "name": parts[2]})
        elif line.startswith("trust add "):
            parts = line[len("trust add "):].split(" ", 1)
            if len(parts) == 2:
                trust.append({"hash": parts[0], "name": parts[1]})
        elif line.startswith("protect add "):
            protected.append(line[len("protect add "):])
        elif line.startswith("policy "):
            policy = line[len("policy "):]

    return {
        "signatures": signatures,
        "trust": trust,
        "protected": protected,
        "policy": policy,
    }
