"""InstanceScanner — find running Ghidra instances on the loopback TCP range.

The plugin binds 8089 and, if taken, walks up to 8089+15. Each instance
answers /mcp/instance_info with project + open programs.
"""

from __future__ import annotations

import http.client
import json
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Callable
from urllib.parse import urlparse

from .config import DEFAULT_PORT, PORT_SCAN_SPAN

# project-name matchers, tried in order
_MATCHERS: list[Callable[[str, str], bool]] = [
    lambda want, have: want == have,
    lambda want, have: want.lower() == have.lower(),
    lambda want, have: want.lower() in have.lower(),
]


class InstanceScanner:
    def __init__(self, host: str = "127.0.0.1", base_port: int = DEFAULT_PORT,
                 span: int = PORT_SCAN_SPAN, probe_timeout: float = 0.4):
        self.host, self.base_port, self.span, self.probe_timeout = host, base_port, span, probe_timeout

    def covers(self, url: str) -> bool:
        """True if `url` is a loopback port inside the scanned range."""
        u = urlparse(url)
        return (u.hostname or "").lower() in {"127.0.0.1", "localhost", "::1"} and             self.base_port <= (u.port or 0) < self.base_port + self.span

    def _port_open(self, port: int) -> bool:
        try:
            with socket.create_connection((self.host, port), timeout=self.probe_timeout):
                return True
        except OSError:
            return False

    def _info(self, port: int) -> dict | None:
        conn = http.client.HTTPConnection(self.host, port, timeout=2)
        try:
            conn.request("GET", "/mcp/instance_info")
            r = conn.getresponse()
            if r.status != 200:
                return None
            data = json.loads(r.read().decode("utf-8"))
            data = data.get("data", data) if isinstance(data, dict) else {}
            return data if isinstance(data, dict) else None
        except Exception:
            return None
        finally:
            conn.close()

    def scan(self) -> list[dict]:
        ports = range(self.base_port, self.base_port + self.span)
        with ThreadPoolExecutor(max_workers=len(ports)) as pool:   # Windows: closed ports eat the full timeout
            open_flags = list(pool.map(self._port_open, ports))
        found = []
        for port, is_open in zip(ports, open_flags):
            if not is_open:
                continue
            info = self._info(port) or {}
            info.setdefault("project", "")
            info["url"] = f"http://{self.host}:{port}"
            info["transport"] = "tcp"
            found.append(info)
        return found

    def find(self, project: str, instances: list[dict] | None = None) -> dict | None:
        instances = self.scan() if instances is None else instances
        for match in _MATCHERS:
            for inst in instances:
                if match(project, inst.get("project", "")):
                    return inst
        return None
