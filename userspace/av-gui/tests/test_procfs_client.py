"""procfs_client regressions: run without GTK, root, or a running avd."""
import sys
import unittest
from unittest.mock import patch

from av_gui import procfs_client


class ProcfsRecordsTest(unittest.TestCase):
    def test_only_lf_separates_records(self):
        # These are all legal bytes/codepoints within Linux filenames.
        # str.splitlines() incorrectly splits each one into a new record.
        for separator in ("\r", "\v", "\f", "\x1c", "\x1d", "\x1e",
                          "\x85", " ", " ", "\udc80"):
            with self.subTest(separator=repr(separator)):
                name = "before" + separator + "after"
                path = "/tmp/" + name
                output = (f"sig add sha256 abc {name}\n"
                          f"trust add def {name}\n"
                          f"protect add {path}\npolicy fail-open\n")
                payload = output.encode("utf-8", "surrogateescape")
                command = [sys.executable, "-c",
                           f"import sys; sys.stdout.buffer.write({payload!r})"]
                with patch.object(procfs_client.avctl_path,
                                  "resolve_unprivileged_avctl_path", return_value="avctl"), \
                        patch.object(procfs_client.host_exec, "host_argv", return_value=command):
                    state = procfs_client.read_state()
                self.assertEqual(state["signatures"][0]["name"], name)
                self.assertEqual(state["trust"][0]["name"], name)
                self.assertEqual(state["protected"], [path])
                self.assertEqual(state["policy"], "fail-open")


if __name__ == "__main__":
    unittest.main()
