"""Temporary Apple-only CONNECT probe. TLS remains end-to-end encrypted.

No request paths, headers, payloads, credentials, or coordinates are recorded.
This is a transport diagnostic, not a Find My collector.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import select
import socket
import socketserver
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

APPLE_SUFFIXES = ("apple.com", "icloud.com", "apple-cloudkit.com",
                  "apple-dns.net", "icloud-content.com", "cdn-apple.com")


def apple_host(host: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9.-]{1,253}", host)) and any(
        host == suffix or host.endswith("." + suffix) for suffix in APPLE_SUFFIXES
    )


def parse_connect(target: str) -> str:
    host, sep, port = target.rpartition(":")
    host = host.lower().rstrip(".")
    if not sep or port != "443" or not apple_host(host):
        raise ValueError("Only Apple HTTPS destinations on port 443 are permitted")
    return host


class ProbeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, client_ip, output, duration):
        self.client_ip = str(ipaddress.IPv4Address(client_ip))
        self.output = Path(output)
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.log_lock = threading.Lock()
        self.stopping = threading.Event()
        self.deadline = time.monotonic() + duration
        super().__init__(address, ProbeHandler)

    def verify_request(self, request, client_address):
        return client_address[0] == self.client_ip

    def record(self, event, host=None):
        # Never pass exceptions or arbitrary request strings to this logger.
        record = {"observed_at": int(time.time()), "event": event}
        if host and apple_host(host):
            record["host"] = host
        with self.log_lock:
            with self.output.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, separators=(",", ":")) + "\n")

    def handle_error(self, request, client_address):
        self.record("connection_error")


class ProbeHandler(socketserver.BaseRequestHandler):
    def answer(self, status, body=b""):
        header = (f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\n"
                  f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        self.request.sendall(header + body)

    def handle(self):
        self.request.settimeout(10)
        head = bytearray()
        while b"\r\n\r\n" not in head:
            chunk = self.request.recv(1)  # Bound header without consuming TLS bytes.
            if not chunk:
                return
            head.extend(chunk)
            if len(head) > 8192:
                self.answer("431 Request Header Fields Too Large")
                return
        try:
            method, target, version = bytes(head).split(b"\r\n", 1)[0].decode("ascii").split()
        except (UnicodeError, ValueError):
            self.answer("400 Bad Request")
            return
        del head
        if method == "GET":
            # Local connectivity check; never forwards plain HTTP.
            parsed = urlsplit(target)
            own_hosts = (self.server.server_address[0], "127.0.0.1", "localhost")
            if parsed.path == "/health" and (not parsed.hostname or parsed.hostname in own_hosts):
                self.server.record("health_check")
                self.answer("200 OK", b"Find My transport probe is reachable. TLS stays encrypted.\n")
                return
        if method != "CONNECT":
            self.answer("405 Method Not Allowed")
            return
        try:
            host = parse_connect(target)
        except ValueError:
            self.answer("403 Forbidden")
            return
        try:
            addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            # Do not permit a DNS response to turn this into a private-network proxy.
            addresses = [item for item in addresses if ipaddress.ip_address(item[4][0]).is_global]
            if not addresses:
                raise OSError("No public address")
            upstream = None
            for family, kind, proto, _, address in addresses:
                candidate = socket.socket(family, kind, proto)
                candidate.settimeout(10)
                try:
                    candidate.connect(address)
                    upstream = candidate
                    break
                except OSError:
                    candidate.close()
            if upstream is None:
                raise OSError("Connect failed")
        except OSError:
            self.server.record("upstream_failed", host)
            self.answer("502 Bad Gateway")
            return
        with upstream:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.server.record("tls_tunnel_opened", host)
            try:
                while not self.server.stopping.is_set() and time.monotonic() < self.server.deadline:
                    readable, _, _ = select.select([self.request, upstream], [], [], 1)
                    for source in readable:
                        payload = source.recv(65536)
                        if not payload:
                            return
                        destination = upstream if source is self.request else self.request
                        destination.sendall(payload)
            except OSError:
                pass
            finally:
                self.server.record("tls_tunnel_closed", host)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True, help="This PC's LAN IPv4 address")
    parser.add_argument("--client-ip", required=True, help="Only accept this iPhone IPv4 address")
    parser.add_argument("--port", type=int, default=8877)
    parser.add_argument("--seconds", type=int, default=600)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bind = ipaddress.IPv4Address(args.bind)
    if not bind.is_private or bind.is_unspecified:
        parser.error("Bind to a specific private or loopback address")
    if not 1 <= args.seconds <= 1800:
        parser.error("Test duration must be between 1 and 1800 seconds")
    with ProbeServer((str(bind), args.port), args.client_ip, args.output, args.seconds) as server:
        def stop():
            server.stopping.set()
            server.shutdown()
        timer = threading.Timer(args.seconds, stop)
        timer.daemon = True
        timer.start()
        server.record("probe_started")
        print(json.dumps({"bind": str(bind), "port": args.port,
                          "client_ip": args.client_ip, "expires_in_seconds": args.seconds}), flush=True)
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            server.stopping.set()
        finally:
            timer.cancel()
            server.record("probe_stopped")


if __name__ == "__main__":
    main()
