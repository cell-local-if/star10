"""Baseline tests for the verifiable audit log."""
from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from auditlog import AuditLog, EntryNotFound, InvalidRequest, inclusion_proof, merkle_root, verify_inclusion


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

    def test_paged_proofs_cover_fixed_prefix_and_verify(self) -> None:
        log = AuditLog()
        for i in range(10):
            log.append({"n": i})
        log.append({"n": 10})          # snapshot deliberately shorter than the log

        pages = []
        start = 0
        while True:
            page = log.proofs(10, start, 4)
            self.assertEqual(page["snapshot_size"], 10)
            pages.append(page)
            proofs = page["proofs"]
            self.assertEqual([p["index"] for p in proofs], list(range(start, page["start"] + page["count"])))
            for item in proofs:
                self.assertEqual(item["size"], 10)
                self.assertEqual(item["root"], pages[0]["root"])
                self.assertTrue(verify_inclusion(item["entry_hash"], item["proof"], item["root"]),
                                f"index {item['index']} must verify against the snapshot root")
            if page["next_start"] is None:
                break
            start = page["next_start"]

        self.assertEqual([p["count"] for p in pages], [4, 4, 2])
        self.assertEqual(pages[-1]["next_start"], None)
        self.assertEqual(sum(p["count"] for p in pages), 10)

    def test_paged_proofs_at_prefix_boundary_allows_empty_page(self) -> None:
        log = AuditLog()
        log.append({"n": 0})
        page = log.proofs(1, 1, 20)
        self.assertEqual((page["count"], page["proofs"], page["next_start"]), (0, [], None))
        self.assertEqual(log.proofs(0, 0, 20)["root"], "0" * 64)

    def test_paged_proofs_reject_bad_ranges(self) -> None:
        log = AuditLog()
        log.append({"n": 0})
        with self.assertRaises(InvalidRequest):
            log.proofs(5, 0, 20)       # log shorter than the snapshot
        with self.assertRaises(InvalidRequest):
            log.proofs(1, 2, 20)       # start past the snapshot
        with self.assertRaises(InvalidRequest):
            log.proofs(1, 0, 0)        # limit out of range
        with self.assertRaises(InvalidRequest):
            log.proofs(1, 0, 101)

    def test_paged_proofs_are_stable_under_concurrent_appends(self) -> None:
        log = AuditLog()
        for i in range(20):
            log.append({"n": i})
        before = log.proofs(20, 0, 100)

        def append_many() -> None:
            for i in range(20, 60):
                log.append({"n": i})

        thread = threading.Thread(target=append_many)
        thread.start()
        seen = [log.proofs(20, start, 7) for start in range(0, 20, 7)]
        thread.join()
        after = log.proofs(20, 0, 100)
        self.assertEqual(before, after)
        self.assertTrue(all(p["root"] == before["root"] for p in seen))
        self.assertEqual(log.size(), 60)

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

    def test_paged_inclusion_proofs_endpoint(self) -> None:
        for i in range(5):
            self.assertEqual(self.call("POST", "/v1/entries", {"payload": {"n": i}})[0], 201)

        status, first = self.call("GET", "/v1/proofs/inclusion?snapshot_size=5&start=0&limit=2")
        self.assertEqual(status, 200)
        self.assertEqual((first["snapshot_size"], first["start"], first["count"]), (5, 0, 2))
        self.assertEqual(first["next_start"], 2)
        self.assertEqual([p["index"] for p in first["proofs"]], [0, 1])
        for item in first["proofs"]:
            self.assertEqual(item["size"], 5)
            self.assertEqual(item["root"], first["root"])
            self.assertTrue(verify_inclusion(item["entry_hash"], item["proof"], first["root"]))

        status, middle = self.call("GET", "/v1/proofs/inclusion?snapshot_size=5&start=2&limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(middle["root"], first["root"])
        self.assertEqual((middle["count"], middle["next_start"]), (2, 4))

        status, last = self.call("GET", "/v1/proofs/inclusion?snapshot_size=5&start=4&limit=20")
        self.assertEqual(status, 200)
        self.assertEqual((last["count"], last["next_start"]), (1, None))
        self.assertEqual([p["index"] for p in last["proofs"]], [4])

        status, tail = self.call("GET", "/v1/proofs/inclusion?snapshot_size=5&start=5&limit=20")
        self.assertEqual(status, 200)
        self.assertEqual((tail["count"], tail["proofs"], tail["next_start"]), (0, [], None))

        self.assertEqual(self.call("GET", "/v1/proofs/inclusion?snapshot_size=0&start=0&limit=20")[1]["root"],
                         "0" * 64)

    def test_paged_inclusion_proofs_rejects_bad_queries(self) -> None:
        self.assertEqual(self.call("POST", "/v1/entries", {"payload": {"n": 1}})[0], 201)
        bad_queries = [
            "",                                          # missing all
            "?snapshot_size=1&start=0",                  # missing limit
            "?snapshot_size=1&limit=20",                 # missing start
            "?snapshot_size=1&start=0&limit=20&x=1",     # unknown parameter
            "?snapshot_size=1&snapshot_size=1&start=0&limit=20",  # duplicated
            "?snapshot_size=1000&start=0&limit=20",      # log too short
            "?snapshot_size=1&start=2&limit=20",         # start past snapshot
            "?snapshot_size=1&start=0&limit=0",          # limit out of range
            "?snapshot_size=1&start=0&limit=101",
            "?snapshot_size=-1&start=0&limit=20",        # sign
            "?snapshot_size=1&start=%2B0&limit=20",      # plus sign
            "?snapshot_size=1&start=0&limit=2.0",        # decimal point
            "?snapshot_size=1e1&start=0&limit=20",       # exponent
            "?snapshot_size=%201&start=0&limit=20",      # encoded whitespace
            "?snapshot_size=0x1&start=0&limit=20",       # non-decimal characters
            "?snapshot_size=&start=0&limit=20",          # empty value
            "?snapshot_size=1&start=0",                  # trailing ampersand form below instead
        ]
        bad_queries[-1] = "?snapshot_size=1&start=0&limit=20&"  # empty trailing piece
        for query in bad_queries:
            status, body = self.call("GET", f"/v1/proofs/inclusion{query}")
            self.assertEqual(status, 400, query)
            self.assertEqual(body["error"]["code"], "invalid_request", query)

        # leading-zero values are still plain non-negative decimal integers
        self.assertEqual(self.call("GET", "/v1/proofs/inclusion?snapshot_size=01&start=00&limit=020")[0], 200)


if __name__ == "__main__":
    unittest.main()
