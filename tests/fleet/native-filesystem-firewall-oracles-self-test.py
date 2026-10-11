"""Checks domain oracles reject drift without deriving ownership from graphs."""

import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

specification = importlib.util.spec_from_file_location("native_domain_oracles", sys.argv[1])
if specification is None or specification.loader is None:
    raise RuntimeError("cannot load native domain oracles")
ORACLE = importlib.util.module_from_spec(specification)
specification.loader.exec_module(ORACLE)


class DomainOracleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / "selected"
        self.directory.mkdir(mode=0o750)
        metadata = self.directory.stat()
        self.claim = {"id": "real-backend-owner", "path": str(self.directory), "device": metadata.st_dev, "inode": metadata.st_ino, "mode": 0o750, "uid": None, "gid": None, "digest": None}

    def test_matching_directory_claim_checks_live_identity(self):
        result = ORACLE.resource(self.directory, [self.claim])
        self.assertTrue(result["claimMatches"])
        self.assertEqual(result["owners"], ["real-backend-owner"])
        self.assertEqual(result["entries"], [])

    def test_replacement_inode_keeps_claim_owner_but_exposes_drift(self):
        self.directory.rename(self.root / "displaced")
        self.directory.mkdir(mode=0o750)
        result = ORACLE.resource(self.directory, [self.claim])
        self.assertFalse(result["claimMatches"])
        self.assertEqual(result["owners"], ["real-backend-owner"])

    def test_metadata_drift_exposes_mismatching_claim(self):
        self.directory.chmod(0o711)
        self.assertFalse(ORACLE.resource(self.directory, [self.claim])["claimMatches"])

    def test_unclaimed_and_duplicate_claims_are_distinct(self):
        self.assertEqual(ORACLE.resource(self.directory, [])["owners"], [])
        self.assertFalse(ORACLE.resource(self.directory, [self.claim, self.claim])["claimMatches"])

    def test_foreign_snapshot_retains_inode_and_contents(self):
        observed = ORACLE.resource(self.directory, [], foreign=True)
        (self.directory / "foreign").write_bytes(b"foreign")
        changed = ORACLE.resource(self.directory, [], foreign=True)
        self.assertEqual(observed["inode"], changed["inode"])
        self.assertNotEqual(observed, changed)

    def test_configuration_checks_exact_byte_hash(self):
        path = self.root / "file"
        path.write_bytes(b"owned\n")
        claim = {"id": "configuration-owner", "path": str(path), "digest": hashlib.sha256(b"owned\n").hexdigest()}
        self.assertTrue(ORACLE.resource(path, [claim], configuration=True)["claimMatches"])
        path.write_bytes(b"foreign\n")
        self.assertFalse(ORACLE.resource(path, [claim], configuration=True)["claimMatches"])

    def test_symlinks_are_never_read_as_resources(self):
        path = self.root / "link"
        path.symlink_to(self.directory)
        with self.assertRaises(OSError):
            ORACLE.resource(path, [])

    def test_absence_does_not_erase_durable_claims(self):
        missing = self.root / "missing"
        self.assertEqual(ORACLE.resource(missing, [{"id": "retained", "path": str(missing)}]), {"exists": False, "owners": ["retained"]})

    def test_kernel_rules_are_hashed_separately_from_declared_policy(self):
        kernel = {"nftables": [
            {"chain": {"name": "input", "policy": "drop"}},
            {"rule": {"expr": [{"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set": [443, 22]}}}, {"accept": None}]}},
        ]}
        digest = "sha256:" + hashlib.sha256(b"aos.network.ruleset-observation/v1\0" + ORACLE.canonical(kernel)).hexdigest()
        claims = [{"id": "actual-ruleset-owner", "observed_digest": digest}]
        result = ORACLE.ruleset_projection(kernel, claims)
        self.assertTrue(result["claimMatches"])
        self.assertEqual(result["tcp"], [22, 443])
        kernel["nftables"][0]["chain"]["policy"] = "accept"
        self.assertFalse(ORACLE.ruleset_projection(kernel, claims)["claimMatches"])

    def test_unclaimed_kernel_table_is_not_owned(self):
        result = ORACLE.ruleset_projection({"nftables": []}, [])
        self.assertEqual(result["owners"], [])
        self.assertFalse(result["claimMatches"])

    def test_multiple_ruleset_receipts_fail_closed(self):
        with self.assertRaises(ValueError):
            ORACLE.ruleset_projection({"nftables": []}, [{"id": "first"}, {"id": "second"}])

    def test_configuration_identity_exposes_same_bytes_replacement(self):
        path = self.root / "file"
        path.write_bytes(b"owned\n")
        claim = {"id": "configuration-owner", "path": str(path), "digest": hashlib.sha256(b"owned\n").hexdigest()}
        original = ORACLE.resource(path, [claim], configuration=True, identity=True)
        path.rename(self.root / "original-file")
        path.write_bytes(b"owned\n")
        replacement = ORACLE.resource(path, [claim], configuration=True, identity=True)
        self.assertTrue(original["claimMatches"])
        self.assertTrue(replacement["claimMatches"])
        self.assertEqual(original["digest"], replacement["digest"])
        self.assertNotEqual(original["inode"], replacement["inode"])

    def test_exact_kernel_identity_detects_non_port_rule_mutation(self):
        kernel = {"nftables": [{"rule": {"expr": [{"accept": None}], "handle": 4}}]}
        original = ORACLE.ruleset_projection(kernel, [], identity=True)
        kernel["nftables"][0]["rule"]["handle"] = 5
        changed = ORACLE.ruleset_projection(kernel, [], identity=True)
        self.assertEqual(original["tcp"], changed["tcp"])
        self.assertEqual(original["policies"], changed["policies"])
        self.assertNotEqual(original["kernelDigest"], changed["kernelDigest"])

    def test_dependency_claim_reads_original_backend_identity(self):
        claim = ORACLE.dependency_claim(b'{"effect":"actual-native-owner","revision":"resolved-original"}')
        self.assertEqual(claim, {"effect": "actual-native-owner", "revision": "resolved-original"})

    def test_dependency_claim_rejects_extra_missing_or_unbounded_fields(self):
        for contents in (b'{}', b'[]', b'{"effect":"owner","revision":"rev","desired":"fake"}', b'{"effect":"","revision":"rev"}', b' ' * 16385):
            with self.assertRaises(ValueError):
                ORACLE.dependency_claim(contents)

    def test_dependency_marker_never_reads_paths_outside_owned_root(self):
        for path in (self.root / "file", Path("/var/lib/aos/native-dependency-barrier/../other")):
            with self.assertRaises(ValueError):
                ORACLE.dependency_marker(path)

    def test_protected_inventory_rejects_writable_directory(self):
        self.root.chmod(0o777)
        with self.assertRaises(ValueError):
            ORACLE.receipts(self.root)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
