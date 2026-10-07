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


_HEX_DIGITS = frozenset("0123456789abcdef")


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in _HEX_DIGITS for ch in value)


def consistency_proof(leaves: list[str], old_size: int, new_size: int) -> list[dict[str, str]]:
    """Consistency path showing the first ``old_size`` leaves are a prefix of the first ``new_size``.

    Same duplicate-last-node tree as :func:`merkle_root`. Nodes are ordered bottom-up; ``position``
    says whether each node sits left ("left") or right ("right") of the running new-tree accumulator.
    ``old_size == 0`` and ``old_size == new_size`` yield an empty proof.
    """
    if (not isinstance(old_size, int) or isinstance(old_size, bool)
            or not isinstance(new_size, int) or isinstance(new_size, bool)):
        raise InvalidRequest("sizes must be integers")
    if old_size < 0 or new_size < 0 or old_size > new_size or new_size > len(leaves):
        raise InvalidRequest("require 0 <= old_size <= new_size <= current size")
    if old_size == new_size or old_size == 0:
        return []
    proof: list[dict[str, str]] = []
    level = list(leaves[:new_size])
    width = new_size
    # Index of the first node belonging to the new suffix at the current level: for an even old
    # size it is leaves[old_size]; for an odd one the boundary leaves share a pair, so start one
    # earlier and seed the path with the duplicated old last leaf leaves[old_size - 1].
    cut_index = old_size - 1 if old_size % 2 else old_size
    proof.append({"position": "left",
                  "hash": level[old_size - 1] if old_size % 2 else level[old_size]})
    while width > 1:
        if cut_index % 2 == 0:
            sibling = cut_index + 1
            if sibling < width:  # beyond the level: that node is a duplicate, supplied implicitly
                proof.append({"position": "right", "hash": level[sibling]})
        else:
            proof.append({"position": "left", "hash": level[cut_index - 1]})
        if len(level) % 2:
            level.append(level[-1])
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        width = (width + 1) // 2
        cut_index //= 2
    return proof


def _consistency_shape(old_size: int, new_size: int) -> list[str]:
    """The fixed bottom-up sequence of node positions implied by the two prefix sizes alone."""
    positions = ["left"]
    width, cut_index = new_size, (old_size - 1 if old_size % 2 else old_size)
    while width > 1:
        if cut_index % 2 == 0:
            if cut_index + 1 < width:
                positions.append("right")
        else:
            positions.append("left")
        width = (width + 1) // 2
        cut_index //= 2
    return positions


def verify_consistency(old_size: Any, new_size: Any, old_root: Any, new_root: Any, proof: Any) -> bool:
    """Offline consistency check. Returns False for every malformed input, never raises."""
    if not isinstance(old_size, int) or isinstance(old_size, bool):
        return False
    if not isinstance(new_size, int) or isinstance(new_size, bool):
        return False
    if old_size < 0 or new_size < 0 or old_size > new_size:
        return False
    if not isinstance(proof, list) or not _is_hex64(old_root) or not _is_hex64(new_root):
        return False
    if old_size == new_size:
        return proof == [] and old_root == new_root
    if old_size == 0:
        # An empty log is a prefix of every log; only the zero old root can be checked.
        return proof == [] and old_root == ZERO
    for step in proof:
        if (not isinstance(step, dict) or set(step) != {"position", "hash"}
                or step["position"] not in {"left", "right"} or not _is_hex64(step["hash"])):
            return False

    expected = _consistency_shape(old_size, new_size)
    if len(proof) != len(expected) or [step["position"] for step in proof] != expected:
        return False

    index = 0

    def take() -> str:
        nonlocal index
        value = proof[index]["hash"]
        index += 1
        return value

    current_new = take()
    current_old: str | None = current_new if old_size % 2 else None
    old_width, width, cut_index = old_size, new_size, (old_size - 1 if old_size % 2 else old_size)
    while width > 1:
        left_hash: str | None = None
        if cut_index % 2 == 0:
            if cut_index + 1 < width:
                current_new = node_hash(current_new, take())
            else:
                current_new = node_hash(current_new, current_new)  # implicit duplicated last node
        else:
            left_hash = take()
            current_new = node_hash(left_hash, current_new)

        # Rebuild the old prefix root one level at a time, driven by the old width b:
        # odd b duplicates its last node while pairing; even b pairs that node with a left sibling;
        # when b collapses to 1 the left node itself is the old root (attachment point).
        if old_width > 1:
            if old_width % 2 == 1:
                if current_old is None:
                    if left_hash is None:
                        return False
                    current_old = node_hash(left_hash, left_hash)
                else:
                    current_old = node_hash(current_old, current_old)
            elif current_old is not None:
                if left_hash is None:
                    return False
                current_old = node_hash(left_hash, current_old)
        elif current_old is None:
            if left_hash is None:
                return False
            current_old = left_hash

        old_width = (old_width + 1) // 2
        width = (width + 1) // 2
        cut_index //= 2

    if index != len(proof) or current_old is None:
        return False
    return current_old == old_root and current_new == new_root


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


def _parse_strict_query(query: str, required: set[str], missing_message: str) -> dict[str, str]:
    """Parse a query string requiring every name in ``required`` exactly once and nothing else.

    Values are never percent-decoded, so encoded whitespace, signs or other radices fail the
    downstream decimal check just like their raw forms.
    """
    if not query:
        raise InvalidRequest(missing_message)
    values: dict[str, str] = {}
    for pair in query.split("&"):
        if not pair or "=" not in pair:
            raise InvalidRequest("malformed query string")
        key, value = pair.split("=", 1)
        if key not in required:
            raise InvalidRequest(f"unknown query parameter: {key}")
        if key in values:
            raise InvalidRequest(f"query parameter {key} must appear exactly once")
        values[key] = value
    if required - values.keys():
        raise InvalidRequest(missing_message)
    return values


def parse_consistency_query(query: str) -> tuple[int, int]:
    """Parse the consistency query string: exactly one from/to, both strict non-negative decimals."""
    values = _parse_strict_query(query, {"from", "to"}, "from and to are required")
    return _decimal_int(values["from"], "from"), _decimal_int(values["to"], "to")


def parse_proofs_query(query: str) -> tuple[int, int, int]:
    """Parse the proofs query string: exactly one snapshot_size/start/limit and nothing else."""
    values = _parse_strict_query(query, {"snapshot_size", "start", "limit"},
                                 "snapshot_size, start and limit are required")
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

    def consistency(self, old_size: Any, new_size: Any) -> dict[str, Any]:
        """Old/new roots and a consistency path for two prefix sizes, fixed under one lock."""
        if not all(isinstance(value, int) and not isinstance(value, bool)
                   for value in (old_size, new_size)):
            raise InvalidRequest("from and to must be non-negative integers")
        if old_size < 0 or new_size < 0:
            raise InvalidRequest("from and to must be non-negative integers")
        with self._lock:
            if new_size > len(self._entries) or old_size > new_size:
                raise InvalidRequest("require 0 <= from <= to <= current size")
            leaves = [entry.hash for entry in self._entries[:new_size]]
            return {"from": old_size, "to": new_size,
                    "old_root": merkle_root(leaves[:old_size]), "new_root": merkle_root(leaves),
                    "proof": consistency_proof(leaves, old_size, new_size)}

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
                if self.path.split("?", 1)[0] == "/v1/proof/consistency":
                    old_size, new_size = parse_consistency_query(self.path.split("?", 1)[1] if "?" in self.path else "")
                    return self._send(200, log.consistency(old_size, new_size))
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
