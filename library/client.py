"""GhidraClient — keep-alive HTTP to the GhidraMCP plugin.

One persistent connection, reopened on failure; all calls serialised through
a lock (concurrent MCP calls otherwise interleave on the plugin side).
Timeouts and retry policy are tables.
"""

from __future__ import annotations

import http.client
import json
import logging
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse

log = logging.getLogger("ghidra-mcp")

DEFAULT_TIMEOUT = 30
TIMEOUTS: dict[str, int] = {
    "rename_variables": 120, "batch_rename_variables": 120, "batch_set_comments": 120,
    "analyze_function_complete": 120, "batch_rename_function_components": 120,
    "batch_set_variable_types": 90, "analyze_data_region": 90,
    "batch_create_labels": 60, "batch_delete_labels": 60, "disassemble_bytes": 120,
    "bulk_fuzzy_match": 180, "find_similar_functions_fuzzy": 60, "import_file": 300,
    "run_ghidra_script": 1800, "run_script_inline": 1800,
    "decompile_function": 45, "set_function_prototype": 45,
    "rename_function": 45, "rename_function_by_address": 45,
    "consolidate_duplicate_types": 60, "batch_analyze_completeness": 120,
    "apply_function_documentation": 60,
}
# endpoint -> (payload keys whose length scales the timeout, seconds per item)
TIMEOUT_SCALING: dict[str, tuple[tuple[str, ...], int]] = {
    "rename_variables":       (("variable_renames",), 38),
    "batch_rename_variables": (("variable_renames",), 38),
    "batch_set_comments":     (("decompiler_comments", "disassembly_comments", "plate_comment"), 8),
}
MAX_TIMEOUT = 600


@dataclass(frozen=True)
class RetryPolicy:
    attempts: int
    retry_5xx: bool          # writes must never be re-sent once the server saw them


class SendFailed(OSError):
    """Transport failed while SENDING the request: the server never saw it, so
    even a POST is safe to resend (typically a stale keep-alive socket)."""


RETRY: dict[str, RetryPolicy] = {
    "GET":  RetryPolicy(attempts=3, retry_5xx=True),
    "POST": RetryPolicy(attempts=2, retry_5xx=False),   # 2nd attempt only after a SendFailed
}


def _count(v) -> int:
    if isinstance(v, (list, dict)):
        return len(v)
    return 1 if v else 0


def timeout_for(endpoint: str, payload: dict | None = None) -> int:
    name = endpoint.strip("/").split("/")[-1]
    base = TIMEOUTS.get(name, DEFAULT_TIMEOUT)
    if payload and name in TIMEOUT_SCALING:
        keys, per_item = TIMEOUT_SCALING[name]
        return min(base + per_item * sum(_count(payload.get(k)) for k in keys), MAX_TIMEOUT)
    return base


class GhidraClient:
    def __init__(self, base_url: str):
        u = urlparse(base_url)
        if (u.hostname or "").lower() not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError(f"Refusing non-local Ghidra URL: {base_url}")
        self.base_url = base_url
        self.host, self.port = u.hostname, u.port or 80
        self._conn: http.client.HTTPConnection | None = None
        self._lock = threading.Lock()

    # -- connection ----------------------------------------------------------

    def _connection(self, timeout: int) -> http.client.HTTPConnection:
        if self._conn is None:
            self._conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        else:
            self._conn.timeout = timeout
            if self._conn.sock:
                self._conn.sock.settimeout(timeout)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    # -- requests ------------------------------------------------------------

    def _once(self, method: str, path: str, body: bytes | None, timeout: int) -> tuple[str, int]:
        headers = {"Connection": "keep-alive"}
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
        conn = self._connection(timeout)
        try:
            try:
                conn.request(method, path, body=body, headers=headers)
            except (ConnectionError, OSError, http.client.HTTPException) as e:
                self.close()
                raise SendFailed(str(e)) from e
            resp = conn.getresponse()
            text = resp.read().decode("utf-8")
            if resp.getheader("Connection", "").lower() == "close":
                self.close()
            return text, resp.status
        except Exception:
            self.close()          # stale keep-alive; next call reopens
            raise

    def request(self, method: str, endpoint: str, params: dict | None = None,
                json_data: dict | None = None, timeout: int | None = None) -> tuple[str, int]:
        """Returns (body, status). Raises OSError on transport failure after retries."""
        path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        if params:
            path = f"{path}?{urlencode({k: str(v) for k, v in params.items()})}"
        body = json.dumps(json_data).encode("utf-8") if json_data is not None else None
        timeout = timeout or timeout_for(endpoint, json_data)
        policy = RETRY.get(method, RETRY["GET"])
        with self._lock:
            last: Exception | None = None
            for attempt in range(policy.attempts):
                try:
                    text, status = self._once(method, path, body, timeout)
                except SendFailed as e:
                    last = e
                    if attempt == 0:          # never reached the server: one clean resend, any method
                        continue
                    raise
                except (ConnectionError, OSError, http.client.HTTPException) as e:
                    last = e                  # failed after send: only idempotent GETs may resend
                    if policy.retry_5xx and attempt + 1 < policy.attempts:
                        time.sleep(0.2 * (attempt + 1))
                        continue
                    raise
                if status >= 500 and policy.retry_5xx and attempt + 1 < policy.attempts:
                    time.sleep(2 ** attempt)
                    continue
                return text, status
            raise OSError(str(last) if last else "request failed")

    def get_json(self, endpoint: str, params: dict | None = None, timeout: int = 5) -> dict | None:
        """Convenience for bridge-internal probes; None on any failure."""
        try:
            text, status = self.request("GET", endpoint, params, timeout=timeout)
            if status != 200:
                return None
            data = json.loads(text)
            return data.get("data", data) if isinstance(data, dict) else None
        except Exception:
            return None
