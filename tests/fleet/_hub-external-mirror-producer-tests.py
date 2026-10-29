"""Controlled actual-ref projection and independent candidate-checkpoint tests."""

import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("mirror_producer", Path(__file__).with_name("_hub-external-mirror-producer.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def reference(path, raw):
    return {"file": path, "sha256": hashlib.sha256(raw).hexdigest(), "byteSize": len(raw)}


class MirrorProducerTests(unittest.TestCase):
    def setUp(self):
        spec.loader.exec_module(module)

    def test_real_list_export_original_is_required_before_config_or_clock_copies(self):
        listing = {"version": 1, "list_cohort": {"original": "exported-list"},
            "publication": {"original": "publication"}, "issuer_installation": {"original": "issuer"}}
        raw = json.dumps(listing).encode()
        module.capture_external_mirror_native = lambda *args: {}
        module.observe_external_oci_pair = lambda *args: {}
        config = json.dumps({"bindings": {"HUB_EXTERNAL_MIRROR_CONSUMER": json.dumps({
            "version": 1, "domains": [{"list_cohort": listing["list_cohort"]}]})}}).encode()
        reads = []
        def read(machine, python, path, maximum):
            reads.append(path)
            return config if path == "/configuration" else raw + b" "
        module.read_direct_guest_file = read
        writes = []
        module.install_direct_guest_file = lambda *args: writes.append(args)
        with self.assertRaisesRegex(ValueError, "independent List export changed"):
            module.prepare_external_mirror_selection(None, None, {"python": "selected-python"}, {
                "coordinates": {"runId": "a" * 32, "nativeRoot": "/selected-root"},
                "configurationFile": "/configuration"}, {}, {}, {}, {
                    "listFile": {"path": "/actual-list-original", "sha256": hashlib.sha256(raw).hexdigest(),
                        "bytes": len(raw)}, "listExport": listing})
        self.assertEqual(reads, ["/configuration", "/actual-list-original"])
        self.assertEqual(writes, [])

    def test_candidate_sha_mismatch_never_reads_seed_signs_or_installs(self):
        candidate = b'{"controlled":"unsigned candidate"}'
        module.prepare_external_mirror_selection = lambda *args: {
            "selectionFile": {"file": "/original-selection"}}
        module.prepare_mirror_functional = lambda *args: {"actualPrepare": True}
        module.read_direct_guest_file = lambda *args: candidate
        module.retain_direct_flow = lambda *args: "retained-private-reference"
        module.await_direct_review = lambda *args: {"selection": {
            "reviewedCandidateSha256": "f" * 64, "reviewerPrivateKey": {"unused": True}}}
        forbidden = []
        module.direct_selected_bytes = lambda *args: forbidden.append("seed")
        module.sign_mirror_functional = lambda *args: forbidden.append("sign")
        module.install_mirror_functional = lambda *args: forbidden.append("install")
        with self.assertRaisesRegex(ValueError, "another unsigned candidate"):
            module.review_install_external_mirror(None, None, {"python": "selected-python"}, {
                "coordinates": {"runId": "a" * 32, "nativeRoot": "/selected-root"}}, {}, {}, {}, {})
        self.assertEqual(forbidden, [])

    def test_matching_candidate_checkpoint_calls_sign_before_original_epoch_install(self):
        candidate, seed = b'{"controlled":"unsigned candidate"}', b"controlled private seed"
        sha = hashlib.sha256(candidate).hexdigest()
        selected = {"selectionFile": {"file": "/original-selection"},
            "reviewerPublicKey": {"file": "/original-reviewer"}}
        module.prepare_external_mirror_selection = lambda *args: selected
        module.prepare_mirror_functional = lambda *args: {"actualPrepare": True}
        module.read_direct_guest_file = lambda *args: candidate
        module.retain_direct_flow = lambda *args: "retained-private-reference"
        fields = []
        def review(label, hashes, required):
            fields.append(required)
            self.assertEqual(hashes["candidateSha256"], sha)
            return {"selection": {"reviewedCandidateSha256": sha,
                "reviewerPrivateKey": {"controlledSeedSelection": True}}}
        module.await_direct_review = review
        module.direct_selected_bytes = lambda *args: seed
        module.install_direct_guest_file = lambda machine, python, path, raw: reference(path, raw)
        events = []
        def sign(*args):
            events.append("sign")
            self.assertEqual(args[4], sha)
            self.assertEqual(args[6], "/original-reviewer")
            return {"controlledSigned": True}
        def install(*args):
            events.append("original-live-install")
            self.assertEqual(args[-1], {"pid": 42})
            return {"controlledStored": True}
        module.sign_mirror_functional = sign
        module.install_mirror_functional = install
        result = module.review_install_external_mirror(None, None, {"python": "selected-python"}, {
            "coordinates": {"runId": "a" * 32, "nativeRoot": "/selected-root", "workerRoot": "/worker-root"},
            "nativeFiles": {"HUB_MIRROR_GUARD_KEY": "/selected-root/independent-mirror-key"}},
            {"worker": {"pid": 42}}, {}, {}, {})
        self.assertEqual(events, ["sign", "original-live-install"])
        self.assertEqual(fields, [{"reviewedCandidateSha256", "reviewerPrivateKey"}])
        self.assertEqual(result["triplet"]["guardKeyFile"], "/selected-root/independent-mirror-key")


if __name__ == "__main__":
    unittest.main()
