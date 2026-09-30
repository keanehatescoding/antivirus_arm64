"""Incremental-build regressions; no compiler or avd libraries required.

Run: python3 -m unittest discover -s tests -p test_build_dependencies.py
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class HeaderDependenciesTest(unittest.TestCase):
    def check_wire_dependency(self, component, target, compile_fragment):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dest = root / "userspace" / component
            dest.mkdir(parents=True)
            shutil.copyfile(ROOT / "userspace" / component / "Makefile", dest / "Makefile")
            files = ["userspace/avctl/avctl.c", "userspace/avd/avd.c",
                     "userspace/avd/sha256.h", "userspace/avd/tlsh_shim.h",
                     "userspace/avd/wire_escape.h", "av/netlink_proto.h"]
            for name in files:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
                os.utime(path, (100, 100))
            product = dest / target
            product.touch()
            os.utime(product, (200, 200))

            def dry_run():
                return subprocess.run(
                    ["make", "--no-print-directory", "-n", "-C", str(dest), target,
                     "PKG_CONFIG=true", "LIBNL_LIBS=-lnl", "YARA_LIBS=-lyara",
                     "FUZZY_LIBS=-lfuzzy"],
                    capture_output=True, text=True, check=True,
                ).stdout

            self.assertNotIn(compile_fragment, dry_run(), "unchanged sources rebuild")
            os.utime(root / "userspace/avd/wire_escape.h", (300, 300))
            self.assertIn(compile_fragment, dry_run(), "changed wire header did not rebuild")

    def test_avctl_rebuilds_after_wire_header_change(self):
        self.check_wire_dependency("avctl", "avctl", "-o avctl avctl.c")

    def test_avd_rebuilds_after_wire_header_change(self):
        self.check_wire_dependency("avd", "avd.o", "-c avd.c -o avd.o")


if __name__ == "__main__":
    unittest.main()
