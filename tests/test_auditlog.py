"""Baseline tests for the verifiable audit log."""
from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from auditlog import (AuditLog, EntryNotFound, InvalidRequest, consistency_proof, inclusion_proof,
                      merkle_root, verify_consistency, verify_inclusion)


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


class ConsistencyUnitTests(unittest.TestCase):
    @staticmethod
    def leaves(n: int) -> list[str]:
        from auditlog import sha256_hex
        return [sha256_hex(b"leaf", str(i).encode()) for i in range(n)]

    def test_exhaustive_prefixes_verify(self) -> None:
        leaves = self.leaves(130)
        for n in range(0, len(leaves) + 1):
            new_root = merkle_root(leaves[:n])
            for m in range(0, n + 1):
                old_root = merkle_root(leaves[:m])
                proof = consistency_proof(leaves, m, n)
                self.assertTrue(verify_consistency(m, n, old_root, new_root, proof), f"{m}->{n}")
                for step in proof:
                    self.assertEqual(set(step), {"position", "hash"})
                    self.assertIn(step["position"], {"left", "right"})
                    int(step["hash"], 16)
                    self.assertEqual(len(step["hash"]), 64)

    def test_equal_sizes_and_zero_are_empty_proofs(self) -> None:
        leaves = self.leaves(6)
        root = merkle_root(leaves)
        zero = "0" * 64
        self.assertEqual(consistency_proof(leaves, 4, 4), [])
        self.assertTrue(verify_consistency(4, 4, root, root, []))
        self.assertTrue(verify_consistency(0, 0, zero, zero, []))
        self.assertTrue(verify_consistency(0, 6, zero, root, []))
        self.assertEqual(consistency_proof(leaves, 0, 6), [])

    def test_tampered_order_and_length_rejected(self) -> None:
        leaves = self.leaves(11)
        for m, n in [(1, 2), (2, 3), (3, 7), (5, 9), (7, 8), (8, 11), (1, 11), (10, 11)]:
            old_root, new_root = merkle_root(leaves[:m]), merkle_root(leaves[:n])
            proof = consistency_proof(leaves, m, n)
            self.assertTrue(verify_consistency(m, n, old_root, new_root, proof), f"{m}->{n}")
            self.assertFalse(verify_consistency(m, n, old_root, "f" * 64, proof), f"{m}->{n} bad new root")
            self.assertFalse(verify_consistency(m, n, "f" * 64, new_root, proof), f"{m}->{n} bad old root")
            for k in range(len(proof)):
                broken = [dict(step) for step in proof]
                broken[k]["hash"] = f"{k:064d}"
                self.assertFalse(verify_consistency(m, n, old_root, new_root, broken), f"{m}->{n} tamper {k}")
                swapped = [dict(step) for step in proof]
                swapped[k]["position"] = "left" if swapped[k]["position"] == "right" else "right"
                self.assertFalse(verify_consistency(m, n, old_root, new_root, swapped), f"{m}->{n} swap {k}")
            if proof:
                self.assertFalse(verify_consistency(m, n, old_root, new_root, list(reversed(proof))))
                self.assertFalse(verify_consistency(m, n, old_root, new_root, proof[:-1]))
                self.assertFalse(
                    verify_consistency(m, n, old_root, new_root, proof + [{"position": "left", "hash": "1" * 64}]))

    def test_shape_is_bound_to_sizes(self) -> None:
        leaves = self.leaves(20)
        # Replaying the 1->3 proof under a size-4 label only rebuilds the size-3 root, so it must
        # not match the authentic signed STH at size 4; a 2->3 label has a different node shape.
        p13 = consistency_proof(leaves, 1, 3)
        self.assertFalse(verify_consistency(1, 4, merkle_root(leaves[:1]), merkle_root(leaves[:4]), p13))
        self.assertFalse(verify_consistency(2, 3, merkle_root(leaves[:2]), merkle_root(leaves[:3]), p13))

    def test_malformed_inputs_return_false_never_raise(self) -> None:
        leaves = self.leaves(6)
        root2, root6 = merkle_root(leaves[:2]), merkle_root(leaves)
        good = consistency_proof(leaves, 2, 6)
        cases = [
            ("neg", lambda: verify_consistency(-1, 6, root2, root6, good)),
            ("m>n", lambda: verify_consistency(6, 2, root6, root2, good)),
            ("bool", lambda: verify_consistency(True, 6, root2, root6, good)),
            ("float", lambda: verify_consistency(2.0, 6, root2, root6, good)),
            ("root types", lambda: verify_consistency(2, 6, None, root6, good)),
            ("upper hex", lambda: verify_consistency(2, 6, root2, "A" * 64, good)),
            ("proof str", lambda: verify_consistency(2, 6, root2, root6, "x")),
            ("bad hex", lambda: verify_consistency(2, 6, root2, root6, [{"position": "left", "hash": "z" * 64}])),
            ("bad pos", lambda: verify_consistency(2, 6, root2, root6, [{"position": "up", "hash": "1" * 64}])),
            ("extra key", lambda: verify_consistency(2, 6, root2, root6,
                                                     [{"position": "left", "hash": "1" * 64, "x": 1}])),
            ("node not dict", lambda: verify_consistency(2, 6, root2, root6, ["x"])),
            ("m=n nonempty", lambda: verify_consistency(6, 6, root6, root6, good)),
            ("m=n diff root", lambda: verify_consistency(6, 6, root6, "1" * 64, [])),
            ("m=0 nonempty", lambda: verify_consistency(0, 6, "0" * 64, root6, good)),
            ("m=0 bad old", lambda: verify_consistency(0, 6, "1" * 64, root6, [])),
        ]
        for name, check in cases:
            self.assertFalse(check(), name)

    def test_generator_validates_ranges(self) -> None:
        leaves = self.leaves(4)
        with self.assertRaises(InvalidRequest):
            consistency_proof(leaves, 2, 5)     # beyond available leaves
        with self.assertRaises(InvalidRequest):
            consistency_proof(leaves, 3, 2)
        with self.assertRaises(InvalidRequest):
            consistency_proof(leaves, -1, 2)
        with self.assertRaises(InvalidRequest):
            consistency_proof(leaves, True, 2)  # type: ignore[arg-type]


class ConsistencyHttpTests(unittest.TestCase):
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

    def test_consistency_end_to_end_for_every_prefix(self) -> None:
        self.append(33)
        with self.log._lock:
            leaves = [e.hash for e in self.log._entries]
        for m in range(0, 34):
            for n in range(m, 34):
                status, body = self.call(f"/v1/proof/consistency?from={m}&to={n}")
                self.assertEqual(status, 200, body)
                self.assertEqual((body["from"], body["to"]), (m, n))
                self.assertEqual(body["old_root"], merkle_root(leaves[:m]))
                self.assertEqual(body["new_root"], merkle_root(leaves[:n]))
                self.assertTrue(
                    verify_consistency(m, n, body["old_root"], body["new_root"], body["proof"]),
                    f"{m}->{n}")

    def test_empty_log_and_equal_sizes(self) -> None:
        status, body = self.call("/v1/proof/consistency?from=0&to=0")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"from": 0, "to": 0, "old_root": "0" * 64,
                                "new_root": "0" * 64, "proof": []})
        self.append(4)
        status, body = self.call("/v1/proof/consistency?from=3&to=3")
        self.assertEqual(status, 200)
        self.assertEqual(body["old_root"], body["new_root"])
        self.assertEqual(body["proof"], [])
        status, body = self.call("/v1/proof/consistency?from=0&to=4")
        self.assertEqual(status, 200)
        self.assertEqual(body["old_root"], "0" * 64)
        self.assertEqual(body["proof"], [])

    def test_snapshot_stable_across_appends(self) -> None:
        self.append(7)
        _, before = self.call("/v1/proof/consistency?from=3&to=7")
        self.append(9)
        _, after = self.call("/v1/proof/consistency?from=3&to=7")
        self.assertEqual(before, after)
        _, grown = self.call("/v1/proof/consistency?from=7&to=16")
        self.assertTrue(verify_consistency(7, 16, before["new_root"], grown["new_root"], grown["proof"]))

    def test_strict_query_parsing_and_ranges(self) -> None:
        self.append(5)
        bad_paths = [
            "/v1/proof/consistency",
            "/v1/proof/consistency?from=1",
            "/v1/proof/consistency?to=3",
            "/v1/proof/consistency?from=1&to=3&extra=1",
            "/v1/proof/consistency?from=1&from=2&to=3",
            "/v1/proof/consistency?from=1&to=3&to=4",
            "/v1/proof/consistency?from=-1&to=3",
            "/v1/proof/consistency?from=1&to=+3",
            "/v1/proof/consistency?from=1.0&to=3",
            "/v1/proof/consistency?from=1e0&to=3",
            "/v1/proof/consistency?from=%201&to=3",
            "/v1/proof/consistency?from=0x1&to=3",
            "/v1/proof/consistency?from=&to=3",
            "/v1/proof/consistency?from=1&to=",
            "/v1/proof/consistency?from=abc&to=3",
            "/v1/proof/consistency?from=6&to=6",       # to beyond current size
            "/v1/proof/consistency?from=4&to=6",
            "/v1/proof/consistency?from=5&to=3",       # from > to
        ]
        for path in bad_paths:
            status, body = self.call(path)
            self.assertEqual(status, 400, path)
            self.assertEqual(body["error"]["code"], "invalid_request", path)

    def test_unknown_routes_unchanged(self) -> None:
        for path in ["/v1/proof/consistency/", "/v1/proof/consistency/1", "/v1/proof",
                     "/v1/proofs/consistency?from=0&to=1", "/nope"]:
            self.assertEqual(self.call(path)[0], 404, path)


if __name__ == "__main__":
    unittest.main()
