"""Verifiable audit log: the baseline service.

Public contract is README.md. Entries are chained (each entry commits to the previous entry hash) and the
log publishes a Merkle root with inclusion proofs so a third party can verify a single entry offline, plus
consistency proofs so a third party can verify that one log size extends another.
"""
from __future__ import annotations

import hashlib
import json
import re
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


def verify_inclusion(entry_hash: Any, proof: Any, root: Any) -> bool:
    """Offline inclusion check against the published hash encoding.

    True iff `entry_hash` and `root` are both 64-char lowercase ASCII hex strings, `proof` is a
    list whose every node is exactly {"position": "left"|"right", "hash": <64-char lowercase hex>},
    and folding the nodes leaf-to-root with node_hash (position says which side the sibling sits
    on) reproduces `root`.  An empty proof verifies only when entry_hash == root.  Malformed
    material (missing/extra fields, wrong types, case, non-hex, non-list containers, recursive
    or hostile objects) yields False; the function never raises.
    """
    try:
        if not _is_hash64(entry_hash) or not _is_hash64(root) or not isinstance(proof, list):
            return False
        current = entry_hash
        for step in proof:
            if (not isinstance(step, dict) or set(step) != {"position", "hash"}
                    or step["position"] not in {"left", "right"} or not _is_hash64(step["hash"])):
                return False
            current = node_hash(current, step["hash"]) if step["position"] == "right" \
                else node_hash(step["hash"], current)
        return current == root
    except Exception:
        return False


def _is_json_value(value: Any) -> bool:
    """True only for structures json.loads can produce (used to validate an evidence payload)."""
    if value is None or isinstance(value, (str, bool, int, float)):
        return True
    if isinstance(value, list):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _is_json_value(item) for key, item in value.items())
    return False  # tuples, bytes, sets and other non-JSON types are rejected


def verify_entry_evidence(evidence: Any) -> bool:
    """Offline check of a single-entry evidence bundle: True iff it is internally consistent with the
    published hashing rules (chain hash, leaf hash, size-shaped inclusion proof, root).  Pure: touches
    no network or process state and never raises."""
    try:
        if not isinstance(evidence, dict) or set(evidence) != {"entry", "size", "root", "proof"}:
            return False
        entry, size, root, proof = evidence["entry"], evidence["size"], evidence["root"], evidence["proof"]
        if (not isinstance(size, int) or isinstance(size, bool) or size < 0
                or not _is_hash64(root) or not isinstance(proof, list)):
            return False
        if not isinstance(entry, dict) or set(entry) != {"index", "hash", "prev_hash", "payload"}:
            return False
        index, entry_hash, prev_hash, payload = (entry["index"], entry["hash"],
                                                 entry["prev_hash"], entry["payload"])
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < size:
            return False
        if not _is_hash64(entry_hash) or not _is_hash64(prev_hash):
            return False
        if not isinstance(payload, (dict, list)) or not _is_json_value(payload):
            return False
        if index == 0 and prev_hash != ZERO:
            return False
        if entry_hash != sha256_hex(prev_hash.encode(), leaf_hash(payload).encode()):
            return False
        # Size-aware inclusion: walk the index's path through the duplicate-last size-`size` tree,
        # which binds the claimed size to the proof (a wrong-length or mis-positioned proof fails).
        current, pos, count = entry_hash, index, size
        for step in proof:
            if count <= 1:
                return False
            if (not isinstance(step, dict) or set(step) != {"position", "hash"}
                    or not _is_hash64(step["hash"])):
                return False
            if step["position"] != ("right" if pos % 2 == 0 else "left"):
                return False
            if count % 2 == 1 and pos == count - 1 and step["hash"] != current:
                return False  # odd level duplicates the last node: the sibling is the node itself
            current = node_hash(current, step["hash"]) if step["position"] == "right" \
                else node_hash(step["hash"], current)
            count = (count + 1) // 2
            pos //= 2
        return count == 1 and current == root
    except Exception:
        return False


# --- Consistency proofs -----------------------------------------------------
#
# The duplicate-last tree satisfies, for every n >= 2 and with k the largest
# power of two below n (j = log2(k)):
#
#     merkle_root(L[:n]) == node_hash(merkle_root(L[:k]),
#                                     raise(merkle_root(L[k:n]), j - depth(n - k)))
#
# where depth(s) = ceil(log2(s)) and raise(h, t) folds h with itself t times
# (the forced duplication a short right subtree undergoes while the perfect
# left subtree finishes its levels).  Both the prover and the verifier below
# are built on that identity, so a proof is a single bottom-to-top list of
# {position, hash} nodes from which both the old and the new root recompute.

def _tree_split(n: int) -> tuple[int, int]:
    """Split of a size-n tree (n >= 2) into (left_size, left_depth); left_size is a power of two."""
    j = (n - 1).bit_length() - 1
    return 1 << j, j


def _tree_depth(n: int) -> int:
    """Levels a size-n tree (n >= 1) needs to reach its root."""
    return (n - 1).bit_length()


def _raise(hash_hex: str, levels: int) -> str:
    for _ in range(levels):
        hash_hex = node_hash(hash_hex, hash_hex)
    return hash_hex


def _forced_root(leaves: list[str], depth: int) -> str:
    """Root of `leaves` raised (by self-pairing) until its depth equals `depth`."""
    return _raise(merkle_root(leaves), depth - _tree_depth(len(leaves)))


def _consistency_nodes(leaves: list[str], m: int, n: int) -> list[dict[str, str]]:
    """Nodes proving merkle_root(leaves[:m]) is a prefix of merkle_root(leaves[:n]); n == len(leaves)."""
    if m == n or m == 0:
        # Subtree entirely inside the old prefix (or old prefix empty): emit the subroot itself.
        return [{"position": "right", "hash": merkle_root(leaves)}]
    k, j = _tree_split(n)
    if m <= k:
        return _consistency_nodes(leaves[:k], m, k) + [{"position": "right", "hash": _forced_root(leaves[k:], j)}]
    return _consistency_nodes(leaves[k:], m - k, n - k) + [{"position": "left", "hash": merkle_root(leaves[:k])}]


def consistency_proof(leaves: list[str], old_size: int, new_size: int) -> list[dict[str, str]]:
    """Proof that the first `old_size` leaves are a prefix of the first `new_size` ones (bottom-to-top)."""
    if not 0 <= old_size <= new_size <= len(leaves):
        raise InvalidRequest("require 0 <= old_size <= new_size <= len(leaves)")
    if old_size == new_size:
        return []
    return _consistency_nodes(leaves[:new_size], old_size, new_size)


def _is_hash64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _verify_consistency_nodes(m: int, n: int, proof: list[dict[str, str]], i: int) -> tuple[str, str, int]:
    """Recompute (old_subroot, new_subroot, next_proof_index) for a size-n tree with prefix m."""
    if m == n or m == 0:
        node = proof[i]
        if node["position"] != "right":
            raise ValueError("subroot node must be positioned right")
        return (node["hash"], node["hash"], i + 1) if m == n else (ZERO, node["hash"], i + 1)
    k, j = _tree_split(n)
    if m <= k:
        old, new, i = _verify_consistency_nodes(m, k, proof, i)
        node = proof[i]
        if node["position"] != "right":
            raise ValueError("right sibling must be positioned right")
        return old, node_hash(new, node["hash"]), i + 1
    old, new, i = _verify_consistency_nodes(m - k, n - k, proof, i)
    old = _raise(old, j - _tree_depth(m - k))
    new = _raise(new, j - _tree_depth(n - k))
    node = proof[i]
    if node["position"] != "left":
        raise ValueError("left sibling must be positioned left")
    return node_hash(node["hash"], old), node_hash(node["hash"], new), i + 1


def verify_consistency(old_size: Any, new_size: Any, old_root: Any, new_root: Any, proof: Any) -> bool:
    """Offline check of a consistency proof: True iff `proof` shows the size-`old_size` log with
    `old_root` is a prefix of the size-`new_size` log with `new_root`.  Never raises."""
    if (not isinstance(old_size, int) or isinstance(old_size, bool) or old_size < 0
            or not isinstance(new_size, int) or isinstance(new_size, bool) or new_size < 0
            or old_size > new_size):
        return False
    if not _is_hash64(old_root) or not _is_hash64(new_root):
        return False
    if old_size == 0 and old_root != ZERO:
        return False
    if new_size == 0 and new_root != ZERO:
        return False
    if not isinstance(proof, list):
        return False
    for node in proof:
        if (not isinstance(node, dict) or set(node) != {"position", "hash"}
                or node["position"] not in {"left", "right"} or not _is_hash64(node["hash"])):
            return False
    if old_size == new_size:
        return proof == [] and old_root == new_root
    try:
        old, new, used = _verify_consistency_nodes(old_size, new_size, proof, 0)
    except (IndexError, TypeError, KeyError, ValueError):
        return False
    return used == len(proof) and old == old_root and new == new_root


# --- Seals and external anchoring -------------------------------------------
#
# A seal freezes the log's current (size, root) together with a caller-supplied
# external reference and external time.  Nothing about the seal comes from a
# network clock, a file or a key: seal_id is a self-certifying digest of the
# five fields, so a third party can verify a seal record offline.

# Strict UTC RFC3339: exactly YYYY-MM-DDTHH:MM:SSZ — a real calendar date and
# time, no offsets, fractional seconds, whitespace or other spellings.
_EXTERNAL_TIME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$")


def is_external_time(value: Any) -> bool:
    """True iff `value` is a string of exactly the UTC form YYYY-MM-DDTHH:MM:SSZ with a valid date/time."""
    if not isinstance(value, str):
        return False
    match = _EXTERNAL_TIME_RE.match(value)
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    if not (1 <= month <= 12 and 0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
        return False
    if day < 1:
        return False
    days_in_month = [31, 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
                     31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return day <= days_in_month[month - 1]


def seal_id_of(size: int, root: str, external_ref: str, external_time: str) -> str:
    """seal_id = sha256(0x02 || canonical_json({external_ref, external_time, root, size})), lowercase hex."""
    document = {"external_ref": external_ref, "external_time": external_time, "root": root, "size": size}
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256_hex(b"\x02", canonical)


def verify_seal(seal: Any) -> bool:
    """Offline seal check: True iff `seal` is exactly the five declared fields, well-formed and self-consistent.

    Pure: touches no network, process state or the log, and never raises.  `size` must be a non-negative
    non-bool integer, `root`/`seal_id` 64-char lowercase hex strings, `external_ref` a non-empty string,
    `external_time` strict UTC RFC3339 (YYYY-MM-DDTHH:MM:SSZ), and `seal_id` must equal the recomputed
    digest over the other four fields.  Missing/extra fields or any malformed value yields False.
    """
    try:
        if not isinstance(seal, dict) or set(seal) != {
                "seal_id", "size", "root", "external_ref", "external_time"}:
            return False
        size, root = seal["size"], seal["root"]
        external_ref, external_time, seal_id = (seal["external_ref"], seal["external_time"], seal["seal_id"])
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            return False
        if not _is_hash64(root) or not _is_hash64(seal_id):
            return False
        if not isinstance(external_ref, str) or not external_ref:
            return False
        if not is_external_time(external_time):
            return False
        return seal_id == seal_id_of(size, root, external_ref, external_time)
    except Exception:
        return False


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


def parse_consistency_query(query: str) -> tuple[int, int]:
    """Parse the consistency query string: exactly one `from` and one `to`, nothing else."""
    if not query:
        raise InvalidRequest("from and to are required")
    values: dict[str, str] = {}
    for pair in query.split("&"):
        if not pair or "=" not in pair:
            raise InvalidRequest("malformed query string")
        key, value = pair.split("=", 1)
        if key not in {"from", "to"}:
            raise InvalidRequest(f"unknown query parameter: {key}")
        if key in values:
            raise InvalidRequest(f"query parameter {key} must appear exactly once")
        values[key] = value
    if {"from", "to"} - values.keys():
        raise InvalidRequest("from and to are required")
    return _decimal_int(values["from"], "from"), _decimal_int(values["to"], "to")


class AuditLog:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: list[Entry] = []
        self._seals: dict[str, dict[str, Any]] = {}

    def append(self, payload: Any) -> Entry:
        entry, _root, _size = self._append(payload)
        return entry

    def append_with_snapshot(self, payload: Any) -> dict[str, Any]:
        """Append and read the resulting (root, size) in the same lock acquisition as the append.

        The returned entry, root and size all describe the fixed prefix ending at this entry:
        size == entry.index + 1 and root is the Merkle root of exactly that prefix, so concurrent
        appends can never leak into a response already composed here.
        """
        entry, root, size = self._append(payload)
        return {"entry": entry.as_json(), "root": root, "size": size}

    def _append(self, payload: Any) -> tuple[Entry, str, int]:
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
            leaves = [e.hash for e in self._entries]
            return entry, merkle_root(leaves), len(leaves)

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

    def evidence(self, index: Any) -> dict[str, Any]:
        """Portable single-entry bundle for offline verification: entry + fixed snapshot size/root + proof.

        The prefix, root and proof are read under one lock acquisition, so later appends only enlarge
        the log and never change a bundle already returned.
        """
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise InvalidRequest("index must be a non-negative integer")
        with self._lock:
            if index >= len(self._entries):
                raise EntryNotFound(f"no entry at index {index}")
            leaves = [e.hash for e in self._entries]
            entry = self._entries[index]
            size = len(leaves)
            return {"entry": entry.as_json(), "size": size, "root": merkle_root(leaves),
                    "proof": inclusion_proof(leaves, index)}

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

    def consistency(self, old_size: Any, new_size: Any) -> dict[str, Any]:
        """Consistency proof between two prefix sizes of this log.

        Old/new roots and the proof are computed under a single lock acquisition, so the pair
        always belongs to one snapshot even while concurrent appends enlarge the log.
        """
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in (old_size, new_size)):
            raise InvalidRequest("from and to must be integers")
        if old_size < 0 or new_size < 0:
            raise InvalidRequest("from and to must be non-negative integers")
        if old_size > new_size:
            raise InvalidRequest("from must not exceed to")
        with self._lock:
            if new_size > len(self._entries):
                raise InvalidRequest(f"log has fewer than {new_size} entries")
            leaves = [entry.hash for entry in self._entries[:new_size]]
            return {"from": old_size, "to": new_size,
                    "old_root": merkle_root(leaves[:old_size]), "new_root": merkle_root(leaves),
                    "proof": consistency_proof(leaves, old_size, new_size)}

    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    def create_seal(self, external_ref: Any, external_time: Any) -> dict[str, Any]:
        """Freeze the current (size, root) with the caller's external reference/time under one lock.

        Validates strictly: `external_ref` must be a non-empty string and `external_time` strict UTC
        RFC3339 (YYYY-MM-DDTHH:MM:SSZ).  The snapshot and the stored record are fixed atomically, so
        later appends only enlarge the log and never alter a returned seal.
        """
        if not isinstance(external_ref, str) or not external_ref:
            raise InvalidRequest("external_ref must be a non-empty string")
        if not is_external_time(external_time):
            raise InvalidRequest("external_time must be UTC RFC3339 in the form YYYY-MM-DDTHH:MM:SSZ")
        with self._lock:
            leaves = [entry.hash for entry in self._entries]
            size, root = len(leaves), merkle_root(leaves)
            seal_id = seal_id_of(size, root, external_ref, external_time)
            record = {"seal_id": seal_id, "size": size, "root": root,
                      "external_ref": external_ref, "external_time": external_time}
            self._seals.setdefault(seal_id, record)
            return dict(record)

    def seal(self, seal_id: Any) -> dict[str, Any]:
        if not _is_hash64(seal_id):
            raise InvalidRequest("seal_id must be 64 lowercase hexadecimal characters")
        with self._lock:
            record = self._seals.get(seal_id)
            if record is None:
                raise EntryNotFound(f"no seal {seal_id}")
            return dict(record)


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
                if len(parts) == 3 and parts[:2] == ["v1", "evidence"]:
                    raw_index = parts[2]
                    evidence_index = int(raw_index) if all("0" <= ch <= "9" for ch in raw_index) else raw_index
                    return self._send(200, log.evidence(evidence_index))
                if len(parts) == 4 and parts[:3] == ["v1", "proof", "inclusion"]:
                    return self._send(200, log.proof(int(parts[3]) if parts[3].isdigit() else parts[3]))
                if self.path.split("?", 1)[0] == "/v1/proof/consistency":
                    old_size, new_size = parse_consistency_query(self.path.split("?", 1)[1] if "?" in self.path else "")
                    return self._send(200, log.consistency(old_size, new_size))
                if self.path.split("?", 1)[0] == "/v1/proofs/inclusion":
                    snapshot_size, start, limit = parse_proofs_query(self.path.split("?", 1)[1] if "?" in self.path else "")
                    return self._send(200, log.proofs_page(snapshot_size, start, limit))
                if len(parts) == 3 and parts[:2] == ["v1", "seals"]:
                    return self._send(200, log.seal(parts[2]))
                return self._send(404, {"error": {"code": "not_found"}})
            except AuditError as error:
                return self._send(error.status, {"error": {"code": error.code, "message": str(error)}})
            except Exception:
                return self._send(500, {"error": {"code": "internal_error"}})

        def do_POST(self) -> None:  # noqa: N802
            try:
                parts = self._parts()
                if parts == ["v1", "seals"]:
                    body = self._read_json()
                    if not isinstance(body, dict) or set(body) != {"external_ref", "external_time"}:
                        raise InvalidRequest("body must be {\"external_ref\": <non-empty string>, "
                                             "\"external_time\": \"YYYY-MM-DDTHH:MM:SSZ\"}")
                    return self._send(201, log.create_seal(body["external_ref"], body["external_time"]))
                if parts != ["v1", "entries"]:
                    return self._send(404, {"error": {"code": "not_found"}})
                body = self._read_json()
                if not isinstance(body, dict) or set(body) != {"payload"}:
                    raise InvalidRequest("body must be {\"payload\": <object|array>}")
                entry = log.append_with_snapshot(body["payload"])
                return self._send(201, entry)
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
