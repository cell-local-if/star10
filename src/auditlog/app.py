"""Verifiable audit log: the baseline service.

Public contract is README.md. Entries are chained (each entry commits to the previous entry hash) and the
log publishes a Merkle root with inclusion proofs so a third party can verify a single entry offline.
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class AuditError(Exception):
    code = "internal_error"
    status = 500


class InvalidRequest(AuditError):
    code, status = "invalid_request", 400


class EntryNotFound(AuditError):
    code, status = "not_found", 404


def sha256_hex(*parts: bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.hexdigest()


def leaf_hash(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256_hex(b"\x00", canonical)


def node_hash(left: str, right: str) -> str:
    return sha256_hex(b"\x01", left.encode(), right.encode())


def merkle_root(leaves: list[str]) -> str:
    """Bitcoin-style: a level with an odd node duplicates its last node. Empty log has the zero root."""
    if not leaves:
        return "0" * 64
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def inclusion_proof(leaves: list[str], index: int) -> list[dict[str, str]]:
    if not 0 <= index < len(leaves):
        raise EntryNotFound(f"no entry at index {index}")
    proof: list[dict[str, str]] = []
    level, position = list(leaves), index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling = position + 1 if position % 2 == 0 else position - 1
        proof.append({"position": "right" if position % 2 == 0 else "left", "hash": level[sibling]})
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        position //= 2
    return proof


def verify_inclusion(entry_hash: str, proof: list[dict[str, str]], root: str) -> bool:
    if not isinstance(entry_hash, str) or len(entry_hash) != 64 or not isinstance(proof, list) or not isinstance(root, str):
        return False
    current = entry_hash
    for step in proof:
        if not isinstance(step, dict) or step.get("position") not in {"left", "right"} or not isinstance(step.get("hash"), str):
            return False
        current = node_hash(current, step["hash"]) if step["position"] == "right" else node_hash(step["hash"], current)
    return current == root


@dataclass(frozen=True)
class Entry:
    index: int
    hash: str
    prev_hash: str
    payload: Any

    def as_json(self) -> dict[str, Any]:
        return {"index": self.index, "hash": self.hash, "prev_hash": self.prev_hash, "payload": self.payload}


ZERO = "0" * 64


# Strict decimal: one or more ASCII digits only — no sign, whitespace, fraction, exponent or other radix.
def _decimal_int(raw: str, name: str) -> int:
    if not raw or not all("0" <= ch <= "9" for ch in raw):
        raise InvalidRequest(f"{name} must be a non-negative decimal integer")
    return int(raw)


def parse_proofs_query(query: str) -> tuple[int, int, int]:
    """Parse the proofs query string: exactly one snapshot_size/start/limit and nothing else."""
    if not query:
        raise InvalidRequest("snapshot_size, start and limit are required")
    values: dict[str, str] = {}
    for pair in query.split("&"):
        if not pair or "=" not in pair:
            raise InvalidRequest("malformed query string")
        key, value = pair.split("=", 1)
        if key not in {"snapshot_size", "start", "limit"}:
            raise InvalidRequest(f"unknown query parameter: {key}")
        if key in values:
            raise InvalidRequest(f"query parameter {key} must appear exactly once")
        values[key] = value
    missing = {"snapshot_size", "start", "limit"} - values.keys()
    if missing:
        raise InvalidRequest("snapshot_size, start and limit are required")
    return (_decimal_int(values["snapshot_size"], "snapshot_size"),
            _decimal_int(values["start"], "start"),
            _decimal_int(values["limit"], "limit"))


class AuditLog:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: list[Entry] = []

    def append(self, payload: Any) -> Entry:
        if payload is None or (isinstance(payload, (str, bytes)) and not payload):
            raise InvalidRequest("payload is required")
        if isinstance(payload, (bytes, bytearray)) or isinstance(payload, (int, float, bool)):
            raise InvalidRequest("payload must be a JSON object or array")
        with self._lock:
            index = len(self._entries)
            prev = self._entries[-1].hash if self._entries else ZERO
            entry_hash = sha256_hex(prev.encode(), leaf_hash(payload).encode())
            entry = Entry(index, entry_hash, prev, payload)
            self._entries.append(entry)
            return entry

    def entry(self, index: Any) -> Entry:
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise InvalidRequest("index must be a non-negative integer")
        with self._lock:
            if index >= len(self._entries):
                raise EntryNotFound(f"no entry at index {index}")
            return self._entries[index]

    def root(self) -> dict[str, Any]:
        with self._lock:
            leaves = [e.hash for e in self._entries]
            return {"root": merkle_root(leaves), "size": len(leaves)}

    def proof(self, index: Any) -> dict[str, Any]:
        with self._lock:
            leaves = [e.hash for e in self._entries]
            entry = self.entry(index)
            return {"index": entry.index, "entry_hash": entry.hash, "size": len(leaves),
                    "root": merkle_root(leaves), "proof": inclusion_proof(leaves, entry.index)}

    def proofs_page(self, snapshot_size: Any, start: Any, limit: Any) -> dict[str, Any]:
        """Inclusion proofs for one page of a fixed entry prefix.

        The prefix (its leaves, root and every proof) is determined under a single lock acquisition,
        so concurrent appends can only enlarge the log; they never change an existing snapshot.
        """
        if not all(isinstance(value, int) and not isinstance(value, bool)
                   for value in (snapshot_size, start, limit)):
            raise InvalidRequest("snapshot_size, start and limit must be integers")
        if snapshot_size < 0 or start < 0:
            raise InvalidRequest("snapshot_size and start must be non-negative integers")
        if not 1 <= limit <= 100:
            raise InvalidRequest("limit must be between 1 and 100")
        with self._lock:
            if snapshot_size > len(self._entries):
                raise InvalidRequest(f"log has fewer than {snapshot_size} entries")
            if start > snapshot_size:
                raise InvalidRequest("start must not exceed snapshot_size")
            leaves = [entry.hash for entry in self._entries[:snapshot_size]]
            root = merkle_root(leaves)
            end = min(start + limit, snapshot_size)
            proofs = [
                {"index": index, "entry_hash": leaves[index], "size": snapshot_size,
                 "root": root, "proof": inclusion_proof(leaves, index)}
                for index in range(start, end)
            ]
            count = end - start
            cursor = start + count
            return {"snapshot_size": snapshot_size, "root": root, "start": start, "count": count,
                    "next_start": cursor if cursor < snapshot_size else None, "proofs": proofs}

    def size(self) -> int:
        with self._lock:
            return len(self._entries)


def make_handler(log: AuditLog) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "audit-log/0.1"
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:
            return

        def _send(self, status: int, body: dict[str, Any]) -> None:
            raw = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _read_json(self) -> Any:
            length = self.headers.get("Content-Length")
            if length is None:
                raise InvalidRequest("Content-Length is required")
            try:
                size = int(length)
            except ValueError as error:
                raise InvalidRequest("Content-Length must be an integer") from error
            if size < 0 or size > 1_048_576:
                raise InvalidRequest("Content-Length must be between 0 and 1 MiB")
            if size == 0:
                return None
            try:
                return json.loads(self.rfile.read(size).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise InvalidRequest("body must be valid UTF-8 JSON") from error

        def _parts(self) -> list[str]:
            return [p for p in self.path.split("?")[0].split("/") if p]

        def do_GET(self) -> None:  # noqa: N802
            try:
                parts = self._parts()
                if parts == ["health"]:
                    return self._send(200, {"status": "ok"})
                if parts == ["v1", "root"]:
                    return self._send(200, log.root())
                if len(parts) == 3 and parts[:2] == ["v1", "entries"]:
                    return self._send(200, log.entry(int(parts[2]) if parts[2].isdigit() else parts[2]).as_json())
                if len(parts) == 4 and parts[:3] == ["v1", "proof", "inclusion"]:
                    return self._send(200, log.proof(int(parts[3]) if parts[3].isdigit() else parts[3]))
                if self.path.split("?", 1)[0] == "/v1/proofs/inclusion":
                    snapshot_size, start, limit = parse_proofs_query(self.path.split("?", 1)[1] if "?" in self.path else "")
                    return self._send(200, log.proofs_page(snapshot_size, start, limit))
                return self._send(404, {"error": {"code": "not_found"}})
            except AuditError as error:
                return self._send(error.status, {"error": {"code": error.code, "message": str(error)}})
            except Exception:
                return self._send(500, {"error": {"code": "internal_error"}})

        def do_POST(self) -> None:  # noqa: N802
            try:
                parts = self._parts()
                if parts != ["v1", "entries"]:
                    return self._send(404, {"error": {"code": "not_found"}})
                body = self._read_json()
                if not isinstance(body, dict) or set(body) != {"payload"}:
                    raise InvalidRequest("body must be {\"payload\": <object|array>}")
                entry = log.append(body["payload"])
                return self._send(201, {"entry": entry.as_json(), **log.root()})
            except AuditError as error:
                return self._send(error.status, {"error": {"code": error.code, "message": str(error)}})
            except Exception:
                return self._send(500, {"error": {"code": "internal_error"}})

    return Handler


def serve(host: str = "127.0.0.1", port: int = 18899) -> ThreadingHTTPServer:
    log = AuditLog()
    httpd = ThreadingHTTPServer((host, port), make_handler(log))
    httpd.log = log  # type: ignore[attr-defined]
    return httpd


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="verifiable audit log")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18899)
    args = parser.parse_args()
    server = serve(args.host, args.port)
    print(f"audit log listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()
