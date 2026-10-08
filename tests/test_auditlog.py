"""Baseline tests for the verifiable audit log."""
from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from auditlog import (AuditLog, EntryNotFound, InvalidRequest, inclusion_proof, merkle_root,
                      verify_consistency, verify_entry_evidence, verify_inclusion)


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


class EvidenceTests(unittest.TestCase):
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

    def test_evidence_verifies_offline_for_every_index(self) -> None:
        self.append(9)
        for index in range(9):
            status, body = self.call(f"/v1/evidence/{index}")
            self.assertEqual(status, 200, body)
            self.assertEqual(set(body), {"entry", "size", "root", "proof"})
            self.assertEqual(set(body["entry"]), {"index", "hash", "prev_hash", "payload"})
            self.assertEqual(body["entry"]["index"], index)
            self.assertEqual(body["entry"]["payload"], {"n": index, "note": "x" * index})
            self.assertEqual(body["size"], 9)
            self.assertEqual(body["root"], self.log.root()["root"])
            for node in body["proof"]:
                self.assertIn(node["position"], ("left", "right"))
                self.assertEqual(len(node["hash"]), 64)
            self.assertTrue(verify_entry_evidence(body), index)

    def test_empty_object_and_array_payloads_are_legal(self) -> None:
        self.log.append({})
        self.log.append([])
        self.log.append([{}, []])
        for index in range(3):
            _, body = self.call(f"/v1/evidence/{index}")
            self.assertTrue(verify_entry_evidence(body), index)

    def test_evidence_is_stable_across_later_appends(self) -> None:
        self.append(5)
        _, before = self.call("/v1/evidence/3")
        self.append(10)
        _, after = self.call("/v1/evidence/3")
        self.assertEqual(before["entry"], after["entry"])
        self.assertTrue(verify_entry_evidence(before))
        self.assertTrue(verify_entry_evidence(after))
        # size/root reflect their own snapshot; both remain valid evidence
        self.assertLess(before["size"], after["size"])

    def test_index_out_of_range_is_404(self) -> None:
        self.append(2)
        for path in ("/v1/evidence/2", "/v1/evidence/99"):
            status, body = self.call(path)
            self.assertEqual(status, 404, path)
            self.assertEqual(body["error"]["code"], "not_found")

    def test_empty_log_has_no_evidence(self) -> None:
        status, body = self.call("/v1/evidence/0")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")

    def test_malformed_index_is_400(self) -> None:
        self.append(3)
        for raw in ("-1", "+1", "1.0", "1e1", "0x1", "abc", "%201", "1%20", ""):
            path = f"/v1/evidence/{raw}"
            status, body = self.call(path)
            if raw == "":
                self.assertEqual(status, 404, path)  # no index segment at all
            else:
                self.assertEqual(status, 400, path)
                self.assertEqual(body["error"]["code"], "invalid_request", path)

    def test_unknown_route_still_404(self) -> None:
        self.assertEqual(self.call("/v1/evidence")[0], 404)
        self.assertEqual(self.call("/v1/evidence/0/extra")[0], 404)

    def test_tampered_evidence_is_rejected(self) -> None:
        self.append(6)
        _, good = self.call("/v1/evidence/2")

        def mutated(**changes):
            import copy
            evil = copy.deepcopy(good)
            for key, value in changes.items():
                if key == "entry":
                    evil["entry"].update(value)
                else:
                    evil[key] = value
            return evil

        zero = "0" * 64
        bad = [
            mutated(size=0), mutated(size=2),                     # index must be < size
            mutated(size=-1), mutated(size="6"), mutated(size=True),
            mutated(root="g" * 64), mutated(root=zero),
            mutated(proof=[]), mutated(proof=good["proof"][:-1]),
            mutated(proof=list(reversed(good["proof"]))),
            mutated(entry={"hash": "f" * 64}),
            mutated(entry={"prev_hash": zero}),                   # breaks the chain
            mutated(entry={"payload": {"n": 999}}),               # leaf hash mismatch
            mutated(entry={"index": 6}),                          # index >= size
            mutated(entry={"index": -1}), mutated(entry={"index": "2"}),
        ]
        flipped = [dict(node) for node in good["proof"]]
        flipped[0]["position"] = "left" if flipped[0]["position"] == "right" else "right"
        bad.append(mutated(proof=flipped))
        for evil in bad:
            self.assertIs(verify_entry_evidence(evil), False, evil)

    def test_first_entry_prev_hash_must_be_zero(self) -> None:
        self.append(3)
        _, body = self.call("/v1/evidence/0")
        self.assertEqual(body["entry"]["prev_hash"], "0" * 64)
        self.assertTrue(verify_entry_evidence(body))
        body["entry"]["prev_hash"] = "0" * 63 + "1"
        self.assertIs(verify_entry_evidence(body), False)

    def test_malformed_evidence_returns_false_not_raise(self) -> None:
        self.append(2)
        _, good = self.call("/v1/evidence/1")
        zero = "0" * 64
        bad = [
            None, "x", [], 0, {},
            {"entry": good["entry"], "size": 2, "root": zero},                    # missing proof
            {"entry": good["entry"], "size": 2, "root": zero, "proof": [], "x": 1},  # unknown field
            {"entry": {"index": 1, "hash": zero, "prev_hash": zero}, "size": 2, "root": zero, "proof": []},
            {"entry": {"index": 1, "hash": zero, "prev_hash": zero, "payload": None}, "size": 2, "root": zero, "proof": []},
            {"entry": {"index": 1, "hash": zero, "prev_hash": zero, "payload": "s"}, "size": 2, "root": zero, "proof": []},
            {"entry": {"index": 1, "hash": zero, "prev_hash": zero, "payload": 3}, "size": 2, "root": zero, "proof": []},
            {"entry": {"index": 1, "hash": zero, "prev_hash": zero, "payload": {"a": object()}},
             "size": 2, "root": zero, "proof": []},
            {"entry": {"index": 1, "hash": zero, "prev_hash": "F" * 64, "payload": {}}, "size": 2, "root": zero, "proof": []},
            {"entry": {"index": 1, "hash": zero, "prev_hash": zero, "payload": {}}, "size": 2, "root": zero,
             "proof": [{"position": "up", "hash": zero}]},
            {"entry": {"index": 1, "hash": zero, "prev_hash": zero, "payload": {}}, "size": 2, "root": zero,
             "proof": [{"position": "left", "hash": zero, "extra": 1}]},
            {"entry": {"index": 1, "hash": zero, "prev_hash": zero, "payload": {}}, "size": 2, "root": zero,
             "proof": [None]},
        ]
        for evil in bad:
            self.assertIs(verify_entry_evidence(evil), False, evil)


if __name__ == "__main__":
    unittest.main()
