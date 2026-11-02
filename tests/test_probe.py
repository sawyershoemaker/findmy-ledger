import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from research.connect_probe import ProbeServer, apple_host, parse_connect


class ProbeTests(unittest.TestCase):
    def test_exact_apple_domain_boundary(self):
        self.assertTrue(apple_host("p123-fmfmobile.icloud.com"))
        self.assertTrue(apple_host("gateway.icloud.com"))
        self.assertFalse(apple_host("apple.com.attacker.example"))
        self.assertFalse(apple_host("fakeapple.com"))
        self.assertFalse(apple_host("name@icloud.com"))

    def test_destination_and_port_are_restricted(self):
        self.assertEqual(parse_connect("gateway.icloud.com:443"), "gateway.icloud.com")
        for target in ("localhost:443", "10.1.1.1:443", "apple.com:22", "example.com:443"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                parse_connect(target)

    def test_health_and_header_redaction(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "metadata.jsonl"
            with ProbeServer(("127.0.0.1", 0), "127.0.0.1", path, 60) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    with socket.create_connection(server.server_address) as client:
                        client.sendall(b"GET /health HTTP/1.1\r\nAuthorization: private-token\r\n\r\n")
                        response = client.recv(4096)
                    self.assertIn(b"200 OK", response)
                    text = path.read_text()
                    self.assertNotIn("private-token", text)
                    self.assertNotIn("Authorization", text)
                    self.assertEqual(json.loads(text)["event"], "health_check")
                finally:
                    server.stopping.set()
                    server.shutdown()
                    thread.join(2)

    def test_client_allowlist(self):
        with tempfile.TemporaryDirectory() as temp:
            with ProbeServer(("127.0.0.1", 0), "10.36.48.109", Path(temp) / "log", 10) as server:
                self.assertFalse(server.verify_request(None, ("127.0.0.1", 9)))
                self.assertTrue(server.verify_request(None, ("10.36.48.109", 9)))


if __name__ == "__main__":
    unittest.main()
