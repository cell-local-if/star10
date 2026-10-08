"""Baseline tests for the verifiable audit log."""
from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from auditlog import (AuditLog, EntryNotFound, InvalidRequest, inclusion_proof, leaf_hash, merkle_root,
                      node_hash, sha256_hex, verify_consistency, verify_entry_evidence, verify_inclusion)


class MerkleUnitTests(unittest.TestCase):
    def test_empty_log_has_zero_root(self) -> None:
        self.assertEqual(merkle_root([]), "0" * 64)

    def test_root_changes_with_every_appended_entry(self) -> None:
        log = AuditLog()
        roots = [log.root()["root"]]
        for i in range(5):
            log.append({"n": i})
            roots.append(log.root()["root"])
        self.assertEqual(len(set(roots)), len(roots))

    def test_inclusion_proof_verifies_for_every_index_and_odd_sizes(self) -> None:
        log = AuditLog()
        for i in range(7):
            log.append({"n": i, "note": "x" * i})
        size = log.size()
        self.assertEqual(size, 7)
        for index in range(size):
            proof = log.proof(index)
            self.assertTrue(verify_inclusion(proof["entry_hash"], proof["proof"], proof["root"]),
                            f"index {index} must verify")
            self.assertEqual(proof["size"], size)

    def test_tampered_proof_or_entry_is_rejected(self) -> None:
        log = AuditLog()
        for i in range(4):
            log.append({"n": i})
        proof = log.proof(2)
        self.assertFalse(verify_inclusion("f" * 64, proof["proof"], proof["root"]))
        broken = [dict(step) for step in proof["proof"]]
        if broken:
            broken[0]["hash"] = "e" * 64
            self.assertFalse(verify_inclusion(proof["entry_hash"], broken, proof["root"]))
        self.assertFalse(verify_inclusion(proof["entry_hash"], proof["proof"], "a" * 64))

    def test_entry_hash_commits_to_previous_entry(self) -> None:
        log = AuditLog()
        first = log.append({"n": 1})
        second = log.append({"n": 2})
        self.assertEqual(second.prev_hash, first.hash)
        self.assertEqual(first.prev_hash, "0" * 64)

    def test_invalid_payloads_and_indices(self) -> None:
        log = AuditLog()
        for bad in [None, "", 3, b"bytes", []]:
            if bad == []:
                continue          # [] is a legal JSON array payload
            with self.assertRaises(InvalidRequest):
                log.append(bad)
        log.append({"n": 1})
        with self.assertRaises(EntryNotFound):
            log.entry(5)
        with self.assertRaises(InvalidRequest):
            log.entry(-1)
        with self.assertRaises(EntryNotFound):
            inclusion_proof(["a" * 64], 3)


class HttpSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from auditlog import serve

        cls.server = serve(port=0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def call(self, method: str, path: str, body: dict | None = None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    def test_health_append_root_entry_and_proof(self) -> None:
        self.assertEqual(self.call("GET", "/health")[0], 200)
        status, body = self.call("POST", "/v1/entries", {"payload": {"action": "login"}})
        self.assertEqual((status, body["size"]), (201, 1))
        self.assertEqual(self.call("POST", "/v1/entries", {"payload": {"action": "logout"}})[1]["size"], 2)
        root_body = self.call("GET", "/v1/root")[1]
        self.assertEqual(root_body["size"], 2)
        entry = self.call("GET", "/v1/entries/0")[1]
        proof = self.call("GET", "/v1/proof/inclusion/0")[1]
        self.assertTrue(verify_inclusion(entry["hash"], proof["proof"], root_body["root"]))

    def test_errors(self) -> None:
        self.assertEqual(self.call("GET", "/v1/entries/99")[0], 404)
        self.assertEqual(self.call("POST", "/v1/entries", {"payload": None})[0], 400)
        self.assertEqual(self.call("GET", "/nope")[0], 404)


class PagedProofsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from auditlog import serve

        cls.server = serve(port=0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.log = cls.server.log

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def setUp(self) -> None:
        with self.log._lock:
            self.log._entries.clear()

    def call(self, path: str):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    def append(self, n: int) -> None:
        for i in range(n):
            self.log.append({"n": i, "note": "x" * i})

    def test_pages_cover_prefix_and_every_proof_verifies(self) -> None:
        self.append(100)
        seen = []
        start = 0
        root = None
        while True:
            status, body = self.call(f"/v1/proofs/inclusion?snapshot_size=100&start={start}&limit=20")
            self.assertEqual(status, 200, body)
            self.assertEqual(body["snapshot_size"], 100)
            if root is None:
                root = body["root"]
            self.assertEqual(body["root"], root)
            self.assertEqual(body["start"], start)
            self.assertLessEqual(body["count"], 20)
            indexes = [item["index"] for item in body["proofs"]]
            self.assertEqual(indexes, list(range(start, start + body["count"])))
            for item in body["proofs"]:
                self.assertEqual(item["size"], 100)
                self.assertEqual(item["root"], root)
                self.assertTrue(verify_inclusion(item["entry_hash"], item["proof"], item["root"]))
                seen.append(item["index"])
            if body["next_start"] is None:
                self.assertEqual(start + body["count"], 100)
                break
            self.assertEqual(body["next_start"], start + body["count"])
            start = body["next_start"]
        self.assertEqual(seen, list(range(100)))

    def test_root_matches_prefix_smaller_than_log_and_stable_across_appends(self) -> None:
        self.append(10)
        _, early = self.call("/v1/proofs/inclusion?snapshot_size=7&start=0&limit=5")
        self.append(5)  # log is now 15; the size-7 snapshot must be unchanged
        self.assertEqual(self.log.size(), 15)
        _, later = self.call("/v1/proofs/inclusion?snapshot_size=7&start=5&limit=10")
        self.assertEqual(early["root"], later["root"])
        self.assertEqual(later["start"], 5)
        self.assertEqual(later["count"], 2)
        self.assertIsNone(later["next_start"])
        for item in later["proofs"]:
            self.assertTrue(verify_inclusion(item["entry_hash"], item["proof"], later["root"]))

    def test_snapshot_root_equals_merkle_root_of_prefix(self) -> None:
        self.append(6)
        with self.log._lock:
            prefix = [e.hash for e in self.log._entries[:4]]
        _, body = self.call("/v1/proofs/inclusion?snapshot_size=4&start=0&limit=100")
        self.assertEqual(body["root"], merkle_root(prefix))
        self.assertEqual(body["count"], 4)
        self.assertIsNone(body["next_start"])

    def test_start_at_snapshot_size_returns_empty_page(self) -> None:
        self.append(3)
        status, body = self.call("/v1/proofs/inclusion?snapshot_size=3&start=3&limit=20")
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 0)
        self.assertEqual(body["proofs"], [])
        self.assertIsNone(body["next_start"])

    def test_empty_log_snapshot_zero_is_an_empty_page(self) -> None:
        status, body = self.call("/v1/proofs/inclusion?snapshot_size=0&start=0&limit=20")
        self.assertEqual(status, 200)
        self.assertEqual(body["root"], "0" * 64)
        self.assertEqual(body["count"], 0)
        self.assertEqual(body["proofs"], [])
        self.assertIsNone(body["next_start"])

    def test_concurrent_appends_do_not_change_existing_snapshot(self) -> None:
        self.append(20)
        _, before = self.call("/v1/proofs/inclusion?snapshot_size=20&start=0&limit=100")

        def append_more() -> None:
            for _ in range(200):
                self.log.append({"k": "v" * 3})

        threads = [threading.Thread(target=append_more) for _ in range(4)]
        for thread in threads:
            thread.start()
        _, during = self.call("/v1/proofs/inclusion?snapshot_size=20&start=0&limit=100")
        for thread in threads:
            thread.join()
        _, after = self.call("/v1/proofs/inclusion?snapshot_size=20&start=0&limit=100")
        self.assertEqual(during["root"], before["root"])
        self.assertEqual(after["root"], before["root"])
        self.assertEqual([p["entry_hash"] for p in after["proofs"]],
                         [p["entry_hash"] for p in before["proofs"]])

    def test_invalid_inputs(self) -> None:
        self.append(5)
        bad_paths = [
            "/v1/proofs/inclusion",
            "/v1/proofs/inclusion?start=0&limit=20",
            "/v1/proofs/inclusion?snapshot_size=5&start=0",
            "/v1/proofs/inclusion?snapshot_size=5&start=0&limit=20&extra=1",
            "/v1/proofs/inclusion?snapshot_size=5&snapshot_size=5&start=0&limit=20",
            "/v1/proofs/inclusion?snapshot_size=5&start=0&start=1&limit=20",
            "/v1/proofs/inclusion?snapshot_size=5&start=0&limit=20&limit=30",
            "/v1/proofs/inclusion?snapshot_size=6&start=0&limit=20",      # log too short
            "/v1/proofs/inclusion?snapshot_size=5&start=6&limit=20",      # start beyond snapshot
            "/v1/proofs/inclusion?snapshot_size=5&start=0&limit=0",       # below range
            "/v1/proofs/inclusion?snapshot_size=5&start=0&limit=101",     # above range
            "/v1/proofs/inclusion?snapshot_size=-1&start=0&limit=20",     # sign
            "/v1/proofs/inclusion?snapshot_size=5&start=-0&limit=20",
            "/v1/proofs/inclusion?snapshot_size=5&start=0&limit=+20",
            "/v1/proofs/inclusion?snapshot_size=5.0&start=0&limit=20",    # fraction
            "/v1/proofs/inclusion?snapshot_size=5&start=0&limit=2e1",     # exponent
            "/v1/proofs/inclusion?snapshot_size=%205&start=0&limit=20",   # whitespace
            "/v1/proofs/inclusion?snapshot_size=5&start=0%20&limit=20",
            "/v1/proofs/inclusion?snapshot_size=0x5&start=0&limit=20",    # non-decimal
            "/v1/proofs/inclusion?snapshot_size=5&start=abc&limit=20",
            "/v1/proofs/inclusion?snapshot_size=5&start=0&limit=",        # empty value
        ]
        for path in bad_paths:
            status, body = self.call(path)
            self.assertEqual(status, 400, path)
            self.assertEqual(body["error"]["code"], "invalid_request", path)

    def test_unknown_route_still_404(self) -> None:
        self.assertEqual(self.call("/v1/proofs/inclusion/")[0], 404)


class EntryEvidenceTests(unittest.TestCase):
    """GET /v1/evidence/{index} plus the offline verify_entry_evidence checker."""

    @classmethod
    def setUpClass(cls) -> None:
        from auditlog import serve

        cls.server = serve(port=0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.log = cls.server.log

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def setUp(self) -> None:
        with self.log._lock:
            self.log._entries.clear()

    def call(self, path: str):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    def append(self, n: int) -> None:
        for i in range(n):
            self.log.append({"n": i, "note": "x" * i})

    def test_every_index_at_every_size_exports_and_verifies_offline(self) -> None:
        for total in (1, 2, 3, 4, 5, 8, 9):
            self.setUp()
            self.append(total)
            for index in range(total):
                status, ev = self.call(f"/v1/evidence/{index}")
                self.assertEqual(status, 200, (total, index, ev))
                self.assertEqual(set(ev), {"entry", "size", "root", "proof"})
                self.assertEqual(ev["size"], total)
                self.assertEqual(set(ev["entry"]), {"index", "hash", "prev_hash", "payload"})
                self.assertEqual(ev["entry"]["index"], index)
                self.assertTrue(verify_entry_evidence(ev), (total, index))
                # inclusion part is the same material the baseline proof endpoint exposes
                self.assertTrue(verify_inclusion(ev["entry"]["hash"], ev["proof"], ev["root"]))
                for node in ev["proof"]:
                    self.assertEqual(set(node), {"position", "hash"})
                    self.assertIn(node["position"], ("left", "right"))
                    self.assertRegex(node["hash"], r"^[0-9a-f]{64}$")

    def test_empty_object_and_array_payloads_verify(self) -> None:
        for payload in ({}, []):
            with self.log._lock:
                self.log._entries.clear()
            self.log.append(payload)
            _, ev = self.call("/v1/evidence/0")
            self.assertTrue(verify_entry_evidence(ev), payload)
            self.assertEqual(ev["entry"]["prev_hash"], "0" * 64)

    def test_first_prev_hash_is_zero_and_chain_is_consistent(self) -> None:
        self.append(3)
        for index in range(3):
            _, ev = self.call(f"/v1/evidence/{index}")
            self.assertEqual(ev["entry"]["prev_hash"],
                             "0" * 64 if index == 0 else self.call(f"/v1/evidence/{index - 1}")[1]["entry"]["hash"])

    def test_returned_evidence_remains_valid_after_later_appends(self) -> None:
        self.append(4)
        _, before = self.call("/v1/evidence/2")
        self.assertEqual(before["size"], 4)
        self.append(20)  # log grows to 24; a fresh fetch sees the bigger snapshot...
        _, after = self.call("/v1/evidence/2")
        self.assertEqual(after["size"], 24)
        self.assertNotEqual(after["root"], before["root"])
        # ...but the bundle already handed out stays self-contained and verifies forever.
        self.assertTrue(verify_entry_evidence(before))
        self.assertTrue(verify_entry_evidence(after))
        self.assertEqual(before["entry"], after["entry"])

    def test_index_beyond_size_is_404(self) -> None:
        self.append(2)
        for path in ("/v1/evidence/2", "/v1/evidence/99"):
            status, body = self.call(path)
            self.assertEqual(status, 404, path)
            self.assertEqual(body["error"]["code"], "not_found", path)
        with self.log._lock:
            self.log._entries.clear()
        status, body = self.call("/v1/evidence/0")  # empty log
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")

    def test_malformed_index_is_400(self) -> None:
        self.append(2)
        for path in ("/v1/evidence/-1", "/v1/evidence/+0", "/v1/evidence/1.0", "/v1/evidence/0x1",
                     "/v1/evidence/abc", "/v1/evidence/1%20", "/v1/evidence/%201",
                     "/v1/evidence/1e0", "/v1/evidence/%DB%B0"):  # non-ASCII digit must not be accepted
            status, body = self.call(path)
            self.assertEqual(status, 400, path)
            self.assertEqual(body["error"]["code"], "invalid_request", path)

    def test_unknown_routes_still_404(self) -> None:
        self.assertEqual(self.call("/v1/evidence")[0], 404)
        self.assertEqual(self.call("/v1/evidence/")[0], 404)
        self.assertEqual(self.call("/v1/evidence/1/2")[0], 404)
        self.assertEqual(self.call("/v1/evidencex/0")[0], 404)
        self.assertEqual(self.call("/nope")[0], 404)

    # --- offline verifier: negative cases -----------------------------------

    def good_evidence(self, total: int = 5, index: int = 2) -> dict:
        self.append(total)
        return self.call(f"/v1/evidence/{index}")[1]

    def test_verifier_accepts_real_evidence_for_all_sizes(self) -> None:
        for total in range(1, 12):
            with self.log._lock:
                self.log._entries.clear()
            self.append(total)
            for index in range(total):
                self.assertTrue(verify_entry_evidence(self.call(f"/v1/evidence/{index}")[1]),
                                (total, index))

    def test_verifier_rejects_non_dict_and_wrong_top_level_shape(self) -> None:
        ev = self.good_evidence()
        for bad in (None, 1, "x", [], json.dumps(ev)):
            self.assertIs(verify_entry_evidence(bad), False, bad)
        for key in ("entry", "size", "root", "proof"):
            broken = dict(ev)
            del broken[key]
            self.assertIs(verify_entry_evidence(broken), False, key)
        self.assertIs(verify_entry_evidence({**ev, "extra": 1}), False)

    def test_verifier_rejects_bad_size_and_index(self) -> None:
        ev = self.good_evidence()
        for size in (-1, 0, ev["size"] - 1, "5", 5.0, True, None):
            self.assertIs(verify_entry_evidence({**ev, "size": size}), False, size)
        bad_entry = dict(ev["entry"])
        for index in (-1, ev["size"], ev["size"] + 1, "2", 2.0, True, None):
            bad_entry["index"] = index
            self.assertIs(verify_entry_evidence({**ev, "entry": bad_entry}), False, index)

    def test_verifier_rejects_bad_hashes(self) -> None:
        ev = self.good_evidence()
        for field in ("hash", "prev_hash"):
            for value in ("a" * 63, "A" * 64, "g" * 64, None, 123, b"a" * 64):
                entry = dict(ev["entry"])
                entry[field] = value
                self.assertIs(verify_entry_evidence({**ev, "entry": entry}), False, (field, value))
        for value in ("a" * 63, "A" * 64, "g" * 64, None, 123):
            self.assertIs(verify_entry_evidence({**ev, "root": value}), False, value)

    def test_verifier_rejects_bad_payloads(self) -> None:
        ev = self.good_evidence(index=0)
        for payload in (None, "str", 1, 1.5, True, b"x", (), set(), {"ok": object()}, [object()]):
            entry = dict(ev["entry"])
            entry["payload"] = payload
            self.assertIs(verify_entry_evidence({**ev, "entry": entry}), False, payload)
        # dict with a non-string key can't come from JSON but must still be rejected safely
        entry = dict(ev["entry"])
        entry["payload"] = {1: 2}
        self.assertIs(verify_entry_evidence({**ev, "entry": entry}), False)

    def test_first_entry_requires_zero_prev_hash(self) -> None:
        ev = self.good_evidence(total=1, index=0)
        entry = dict(ev["entry"])
        entry["prev_hash"] = "1" + "0" * 63
        entry["hash"] = sha256_hex(entry["prev_hash"].encode(), leaf_hash(entry["payload"]).encode())
        self.assertIs(verify_entry_evidence({**ev, "entry": entry}), False)

    def test_tampered_payload_or_hash_breaks_chain(self) -> None:
        ev = self.good_evidence()
        entry = dict(ev["entry"])
        entry["payload"] = {"n": 999}
        self.assertIs(verify_entry_evidence({**ev, "entry": entry}), False)
        entry = dict(ev["entry"])
        entry["hash"] = "f" * 64
        self.assertIs(verify_entry_evidence({**ev, "entry": entry}), False)
        entry = dict(ev["entry"])
        entry["prev_hash"] = "0" * 64  # wrong predecessor for a non-first entry
        entry["hash"] = sha256_hex(entry["prev_hash"].encode(), leaf_hash(entry["payload"]).encode())
        self.assertIs(verify_entry_evidence({**ev, "entry": entry}), False)

    def test_tampered_proof_or_root_is_rejected(self) -> None:
        for total in (1, 2, 3, 6, 7):
            with self.log._lock:
                self.log._entries.clear()
            self.append(total)
            ev = self.call(f"/v1/evidence/{total - 1}")[1]
            self.assertIs(verify_entry_evidence({**ev, "root": "a" * 64}), False, total)
            if ev["proof"]:
                broken = [dict(step) for step in ev["proof"]]
                broken[0]["hash"] = "e" * 64
                self.assertIs(verify_entry_evidence({**ev, "proof": broken}), False, total)
                flipped = [dict(step) for step in ev["proof"]]
                flipped[0]["position"] = "left" if flipped[0]["position"] == "right" else "right"
                self.assertIs(verify_entry_evidence({**ev, "proof": flipped}), False, total)
                self.assertIs(verify_entry_evidence({**ev, "proof": ev["proof"][:-1]}), False, total)
                self.assertIs(
                    verify_entry_evidence({**ev, "proof": ev["proof"]
                                           + [{"position": "right", "hash": "c" * 64}]}), False, total)
        # non-list / malformed nodes
        ev = self.good_evidence()
        for proof in (None, "x", [None], [{"position": "up", "hash": "a" * 64}],
                      [{"position": "left", "hash": "zz"}],
                      [{"position": "left", "hash": "a" * 64, "extra": 1}], [{"hash": "a" * 64}]):
            self.assertIs(verify_entry_evidence({**ev, "proof": proof}), False, proof)

    def test_proof_shape_is_bound_to_size(self) -> None:
        # A duplicate-last tree gives an entry the same path shape for all sizes in one power-of-two
        # band (e.g. index 2: 4 levels for sizes 9..16); sizes from other bands have a different
        # number of levels and must be rejected even though every hash in the bundle is genuine.
        self.append(10)
        ev = self.call("/v1/evidence/2")[1]
        self.assertEqual(len(ev["proof"]), 4)
        for wrong_size in (2, 3, 4, 5, 8, 17, 32, 100):
            self.assertIs(verify_entry_evidence({**ev, "size": wrong_size}), False, wrong_size)
        # size <= index is always invalid
        self.assertIs(verify_entry_evidence({**ev, "size": 0}), False)

    def test_odd_last_sibling_must_be_self_duplicate(self) -> None:
        # For the last entry of an odd-size tree the first sibling is the duplicated node, i.e. it
        # must equal the entry hash itself. A forged bundle with a distinct sibling and a re-derived
        # self-consistent root fools a naive inclusion check but must fail the size-aware checker.
        self.append(5)
        ev = self.call("/v1/evidence/4")[1]
        self.assertEqual(ev["proof"][0]["position"], "right")
        self.assertEqual(ev["proof"][0]["hash"], ev["entry"]["hash"])
        forged_proof = [dict(step) for step in ev["proof"]]
        forged_proof[0]["hash"] = "9" * 64
        current = ev["entry"]["hash"]
        for step in forged_proof:
            current = (node_hash(current, step["hash"]) if step["position"] == "right"
                       else node_hash(step["hash"], current))
        forged = {**ev, "proof": forged_proof, "root": current}
        self.assertTrue(verify_inclusion(forged["entry"]["hash"], forged_proof, current))
        self.assertFalse(verify_entry_evidence(forged))

    def test_never_raises_on_garbage(self) -> None:
        for garbage in (0, False, "", b"{}", object(), {"entry": object()},
                        {"entry": {}, "size": {}, "root": {}, "proof": {}},
                        {"entry": {"index": {}}, "size": -1, "root": 1, "proof": [object()]}):
            self.assertIs(verify_entry_evidence(garbage), False, garbage)


class ConsistencyProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from auditlog import serve

        cls.server = serve(port=0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.log = cls.server.log

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def setUp(self) -> None:
        with self.log._lock:
            self.log._entries.clear()

    def call(self, path: str):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    def append(self, n: int) -> None:
        for i in range(n):
            self.log.append({"n": i, "note": "x" * i})

    def test_every_pair_of_sizes_verifies_offline(self) -> None:
        self.append(40)
        with self.log._lock:
            leaves = [e.hash for e in self.log._entries]
        roots = [merkle_root(leaves[:n]) for n in range(41)]
        for new_size in range(41):
            for old_size in range(new_size + 1):
                status, body = self.call(f"/v1/proof/consistency?from={old_size}&to={new_size}")
                self.assertEqual(status, 200, (old_size, new_size, body))
                self.assertEqual((body["from"], body["to"]), (old_size, new_size))
                self.assertEqual(body["old_root"], roots[old_size])
                self.assertEqual(body["new_root"], roots[new_size])
                self.assertTrue(
                    verify_consistency(old_size, new_size, body["old_root"], body["new_root"], body["proof"]),
                    (old_size, new_size))
                for node in body["proof"]:
                    self.assertIn(node["position"], ("left", "right"))
                    self.assertEqual(len(node["hash"]), 64)
                    int(node["hash"], 16)

    def test_equal_sizes_return_empty_proof_and_same_root(self) -> None:
        self.append(5)
        status, body = self.call("/v1/proof/consistency?from=5&to=5")
        self.assertEqual(status, 200)
        self.assertEqual(body["proof"], [])
        self.assertEqual(body["old_root"], body["new_root"])
        self.assertTrue(verify_consistency(5, 5, body["old_root"], body["new_root"], []))

    def test_zero_sizes_and_empty_log(self) -> None:
        status, body = self.call("/v1/proof/consistency?from=0&to=0")
        self.assertEqual(status, 200)
        self.assertEqual(body["proof"], [])
        self.assertEqual(body["old_root"], "0" * 64)
        self.assertEqual(body["new_root"], "0" * 64)
        self.assertTrue(verify_consistency(0, 0, body["old_root"], body["new_root"], body["proof"]))
        self.append(3)
        status, body = self.call("/v1/proof/consistency?from=0&to=3")
        self.assertEqual(status, 200)
        self.assertEqual(body["old_root"], "0" * 64)
        self.assertTrue(verify_consistency(0, 3, body["old_root"], body["new_root"], body["proof"]))

    def test_proof_is_stable_across_later_appends(self) -> None:
        self.append(6)
        _, before = self.call("/v1/proof/consistency?from=3&to=6")
        self.append(10)
        _, after = self.call("/v1/proof/consistency?from=3&to=6")
        self.assertEqual(before, after)

    def test_tampered_proof_is_rejected(self) -> None:
        self.append(9)
        _, body = self.call("/v1/proof/consistency?from=5&to=9")
        args = (5, 9, body["old_root"], body["new_root"])
        self.assertFalse(verify_consistency(*args, proof=[]))
        self.assertFalse(verify_consistency(5, 9, "a" * 64, body["new_root"], body["proof"]))
        self.assertFalse(verify_consistency(5, 9, body["old_root"], "b" * 64, body["proof"]))
        broken = [dict(node) for node in body["proof"]]
        broken[0]["hash"] = "e" * 64
        self.assertFalse(verify_consistency(*args, proof=broken))
        flipped = [dict(node) for node in body["proof"]]
        flipped[0]["position"] = "left" if flipped[0]["position"] == "right" else "right"
        self.assertFalse(verify_consistency(*args, proof=flipped))
        if len(body["proof"]) > 1:
            self.assertFalse(verify_consistency(*args, proof=list(reversed(body["proof"]))))
        self.assertFalse(verify_consistency(*args, proof=body["proof"][:-1]))
        self.assertFalse(verify_consistency(*args, proof=body["proof"] + [{"position": "right", "hash": "c" * 64}]))

    def test_malformed_verify_inputs_return_false_not_raise(self) -> None:
        zero = "0" * 64
        bad = [
            (-1, 2, zero, zero, []), (2, 1, zero, zero, []), (True, 2, zero, zero, []),
            (0.5, 2, zero, zero, []), ("1", 2, zero, zero, []), (0, 0, "1" * 64, "1" * 64, []),
            (0, 1, zero, "g" * 64, []), (0, 1, zero, "a" * 63, []), (0, 1, zero, "a" * 65, []),
            (0, 1, zero, zero, None), (0, 1, zero, zero, "x"),
            (0, 2, zero, zero, [{"position": "up", "hash": zero}]),
            (0, 2, zero, zero, [{"position": "left", "hash": "zz"}]),
            (0, 2, zero, zero, [{"position": "left", "hash": zero, "extra": 1}]),
            (0, 2, zero, zero, [{"position": "left"}]),
            (0, 2, zero, zero, [None]),
            (3, 3, zero, zero, [{"position": "right", "hash": zero}]),
        ]
        for args in bad:
            self.assertIs(verify_consistency(*args), False, args)

    def test_invalid_queries(self) -> None:
        self.append(5)
        bad_paths = [
            "/v1/proof/consistency",
            "/v1/proof/consistency?from=1",
            "/v1/proof/consistency?to=1",
            "/v1/proof/consistency?from=1&to=2&extra=1",
            "/v1/proof/consistency?from=1&from=1&to=2",
            "/v1/proof/consistency?from=1&to=2&to=3",
            "/v1/proof/consistency?from=&to=2",
            "/v1/proof/consistency?from=1&to=",
            "/v1/proof/consistency?from=-1&to=2",
            "/v1/proof/consistency?from=+1&to=2",
            "/v1/proof/consistency?from=1.0&to=2",
            "/v1/proof/consistency?from=1e1&to=20",
            "/v1/proof/consistency?from=%201&to=2",
            "/v1/proof/consistency?from=1%20&to=2",
            "/v1/proof/consistency?from=0x1&to=2",
            "/v1/proof/consistency?from=abc&to=2",
            "/v1/proof/consistency?from=3&to=2",     # from > to
            "/v1/proof/consistency?from=0&to=6",     # beyond log size
            "/v1/proof/consistency?from=0&to=99",
        ]
        for path in bad_paths:
            status, body = self.call(path)
            self.assertEqual(status, 400, path)
            self.assertEqual(body["error"]["code"], "invalid_request", path)

    def test_unknown_route_still_404(self) -> None:
        self.assertEqual(self.call("/v1/proof/consistency/")[0], 404)
        self.assertEqual(self.call("/v1/proof/unknown?from=0&to=1")[0], 404)


if __name__ == "__main__":
    unittest.main()
