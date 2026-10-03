"""avd_client regressions: run without GTK, root, or a running avd."""
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from av_gui import avd_client


class ResponseDeadlineTest(unittest.TestCase):
    def request_from_peer(self, send_response):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "control.sock")
            stop = threading.Event()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(1)
                listener.settimeout(2)

                def serve():
                    try:
                        conn, _ = listener.accept()
                        with conn:
                            conn.settimeout(2)
                            while conn.recv(4096):
                                pass
                            send_response(conn, stop)
                    except (OSError, TimeoutError):
                        pass  # Deadline tests intentionally close the peer early.

                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                try:
                    with patch.dict(os.environ, {"AVD_SOCK_PATH": path}), \
                            patch.object(avd_client, "SOCKET_TIMEOUT_SECS", 0.2):
                        return avd_client._request("STATUS")
                finally:
                    stop.set()
                    worker.join(3)
                    self.assertFalse(worker.is_alive(), "mock daemon did not exit")

    def test_trickle_has_total_deadline(self):
        def trickle(conn, stop):
            # Every chunk arrives inside the idle timeout, but the whole
            # response takes much longer than the response budget.
            for _ in range(40):
                conn.sendall(b"x")
                if stop.wait(0.025):
                    break

        start = time.monotonic()
        with self.assertRaises(avd_client.AvdError):
            self.request_from_peer(trickle)
        self.assertLess(time.monotonic() - start, 0.8)

    def test_idle_peer_times_out(self):
        with self.assertRaises(avd_client.AvdError):
            self.request_from_peer(lambda conn, stop: stop.wait(1))

    def test_complete_response_preserves_filename_bytes(self):
        payload = b"OK\nCOUNT 1\n/tmp/\x80\nEND\n"
        self.assertEqual(
            self.request_from_peer(lambda conn, stop: conn.sendall(payload)),
            payload.decode("utf-8", "surrogateescape"),
        )

    def test_response_size_limit_still_enforced(self):
        with patch.object(avd_client, "MAX_RESPONSE_BYTES", 4):
            with self.assertRaisesRegex(avd_client.AvdError, "too large"):
                self.request_from_peer(lambda conn, stop: conn.sendall(b"12345"))


if __name__ == "__main__":
    unittest.main()
