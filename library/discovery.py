"""InstanceScanner — find running Ghidra instances, over UDS and TCP.

The plugin writes one `ghidra-<pid>.sock` per instance into a per-user runtime
directory AND binds 8089 (walking up to 8089+15 if taken). UDS is scanned first
because it is unambiguous and portless; the TCP range is scanned too, and any
TCP instance that is the same process as one already found over UDS is dropped
(same pid, or same project + program list). Each instance answers
/mcp/instance_info with project + open programs.
"""

from __future__ import annotations

import http.client
import json
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Callable
from urllib.parse import urlparse

from .config import DEFAULT_PORT, PORT_SCAN_SPAN
from .uds import UnixHTTPConnection, is_uds_url, sockets, uds_supported, url_for

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
        """True if `url` is something scan() would have found: a socket URL, or a
        loopback port inside the scanned range."""
        if is_uds_url(url):
            return True
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

    def _info_uds(self, socket_path: str) -> dict | None:
        conn = UnixHTTPConnection(socket_path, timeout=2)
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
            try:
                conn.close()
            except Exception:
                pass

    def scan_uds(self) -> list[dict]:
        """Live instances reachable over a Unix domain socket."""
        if not uds_supported():
            return []
        found = []
        for sock, pid in sockets():
            info = self._info_uds(str(sock)) or {}
            info.setdefault("project", "")
            info.setdefault("pid", pid)
            info["socket"] = str(sock)
            info["url"] = url_for(sock)
            info["transport"] = "uds"
            found.append(info)
        return found

    @staticmethod
    def _identity(inst: dict) -> tuple:
        """What makes two records the same running Ghidra. pid when both report one,
        else project + open-program list, which is as close as the server gets."""
        programs = inst.get("programs")
        if isinstance(programs, list):
            names = tuple(sorted(p.get("name", "") if isinstance(p, dict) else str(p)
                                 for p in programs))
        else:
            names = ()
        return (inst.get("project", ""), names)

    def scan(self) -> list[dict]:
        """UDS instances first, then any TCP instance that is not already one of them."""
        found = self.scan_uds()
        pids = {i.get("pid") for i in found if i.get("pid")}
        identities = {self._identity(i) for i in found}
        for inst in self.scan_tcp():
            pid = inst.get("pid")
            if pid and pid in pids:
                continue                       # same process, already reachable over UDS
            if not pid and self._identity(inst) in identities:
                continue                       # no pid to compare: fall back to project+programs
            found.append(inst)
        return found

    def scan_tcp(self) -> list[dict]:
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
