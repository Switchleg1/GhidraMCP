"""UDS transport — HTTP over a Unix domain socket, and where to find the sockets.

The Ghidra plugin writes one socket per instance, `ghidra-<pid>.sock`, into a
per-user runtime directory, and (still) binds a TCP fallback port. UDS is the
preferred local transport: it needs no port, cannot collide, and the file name
carries the pid so dead instances are detectable.

    socket_dirs()        every plausible runtime dir, most-likely first
    sockets()            live `ghidra-<pid>.sock` paths (stale ones unlinked)
    pid_alive(pid)       liveness probe (Windows OpenProcess / POSIX signal 0)
    UnixHTTPConnection   http.client connection whose transport is AF_UNIX
    uds_supported()      False on hosts without AF_UNIX (Windows pre-1803)

Directory search mirrors the plugin's `ServerManager.getSocketDir()`
(XDG_RUNTIME_DIR -> TMPDIR -> /tmp, user component from the OS user name) and
adds the locations `$TMPDIR` can *resolve to* when the bridge is spawned
without inheriting it — notably the macOS per-user temp under /var/folders and
its /private symlink.
"""

from __future__ import annotations

import http.client
import logging
import os
import socket
from pathlib import Path

log = logging.getLogger("ghidra-mcp")

SOCKET_GLOB = "*.sock"
URL_SCHEME = "unix:"          # bridge-internal URL form: unix:/abs/path/ghidra-123.sock


def uds_supported() -> bool:
    """AF_UNIX exists on Linux/macOS and on Windows 10 1803+."""
    return hasattr(socket, "AF_UNIX")


def _user() -> str:
    return os.getenv("USER") or os.getenv("USERNAME") or "unknown"


def socket_dirs() -> list[Path]:
    """Every plausible socket runtime directory, most-likely first, de-duplicated."""
    user = _user()
    out: list[Path] = []

    def add(p) -> None:
        if p is None:
            return
        p = Path(p)
        if p not in out:
            out.append(p)

    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        add(Path(xdg) / "ghidra-mcp")
    getuid = getattr(os, "getuid", None)
    if callable(getuid):
        run_user = Path(f"/run/user/{getuid()}")
        try:
            if run_user.exists():
                add(run_user / "ghidra-mcp")
        except OSError:
            pass

    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        add(Path(tmpdir) / f"ghidra-mcp-{user}")

    # macOS: $TMPDIR is /var/folders/<hash>/<id>/T/ and /var is a symlink to /private/var,
    # so a socket can surface under either prefix depending on how the path was walked.
    for prefix in ("/var/folders", "/private/var/folders"):
        root = Path(prefix)
        try:
            if root.exists():
                for hit in root.glob(f"*/*/T/ghidra-mcp-{user}"):
                    add(hit)
        except OSError:
            pass

    add(Path(f"/tmp/ghidra-mcp-{user}"))

    win_temp = os.environ.get("TEMP") or os.environ.get("TMP")
    if win_temp:
        add(Path(win_temp) / f"ghidra-mcp-{user}")
    return out


def pid_alive(pid: int) -> bool:
    """True if the process still exists. Never raises for a plainly invalid pid."""
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32
        # PROCESS_QUERY_LIMITED_INFORMATION: enough for a liveness probe, and avoids
        # the POSIX-only os.kill(pid, 0) path which is unreliable on Windows.
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return kernel32.GetLastError() == 5          # ACCESS_DENIED: alive, not queryable
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                                  # alive, owned by another user
    except OSError as e:
        if getattr(e, "winerror", None) == 87:        # invalid parameter == no such pid
            return False
        raise


def _pid_of(sock: Path) -> int | None:
    name = sock.stem                                  # ghidra-<pid>
    dash = name.rfind("-")
    if dash < 0:
        return None
    try:
        return int(name[dash + 1:])
    except ValueError:
        return None


def sockets(cleanup: bool = True) -> list[tuple[Path, int]]:
    """[(socket_path, pid)] for every live instance. Stale sockets are unlinked."""
    if not uds_supported():
        return []
    found: list[tuple[Path, int]] = []
    seen: set[str] = set()
    for d in socket_dirs():
        try:
            if not d.exists():
                continue
            entries = sorted(d.glob(SOCKET_GLOB))
        except OSError:
            continue
        for sock in entries:
            try:
                key = str(sock.resolve())
            except OSError:
                key = str(sock)
            if key in seen:
                continue
            seen.add(key)
            pid = _pid_of(sock)
            if pid is None:
                continue
            if not pid_alive(pid):
                if cleanup:
                    try:
                        sock.unlink(missing_ok=True)
                        log.debug(f"removed stale socket {sock}")
                    except OSError:
                        pass
                continue
            found.append((sock, pid))
    return found


def is_uds_url(url: str) -> bool:
    return str(url).startswith(URL_SCHEME)


def url_for(socket_path) -> str:
    return f"{URL_SCHEME}{socket_path}"


def path_from_url(url: str) -> str:
    return str(url)[len(URL_SCHEME):]


class UnixHTTPConnection(http.client.HTTPConnection):
    """http.client over AF_UNIX. Same interface as HTTPConnection, so the keep-alive,
    locking and retry logic in GhidraClient works unchanged across both transports."""

    def __init__(self, socket_path: str, timeout: float = 30):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        if not uds_supported():
            raise OSError("AF_UNIX unavailable on this host")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
        except OSError:
            sock.close()
            raise
        self.sock = sock
