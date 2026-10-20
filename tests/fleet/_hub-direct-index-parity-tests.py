"""Refuse stale, incomplete or divergent index and storage attribution evidence."""

import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


parity = load("direct_index_parity", "_hub-direct-index-parity.py")
codec = load("direct_codec_assessment", "_hub-direct-codec-assessment.py")
parity.retain_direct_flow = codec.retain_direct_flow = lambda *_: None


class EvidenceRefusals(unittest.TestCase):
    def test_authoritative_index_requires_exact_nonempty_complete_source(self):
        # These are controlled assertion inputs, never observed SQL/VM evidence.
        commit = "a" * 64
        selected = {
            "index": [["fresh", None, commit]], "releases": [["1.0.0"]],
            "channel_floors": [["stable", "1.0.0"]],
            "channel_partitions": [[number] for number in range(256)],
            "artifact_snapshots": [["1.0.0", commit, "tag", "manifest", "complete", 1, 1]],
        }
        for name in ("packages", "versions", "platforms", "keys", "release_records",
                     "catalog_artifacts", "release_artifacts", "channels"):
            selected[name] = [["nonempty-controlled-value"]]
        readers = {name: copy.deepcopy(selected) for name in ("hybrid", "native_only", "worker_only")}
        parity.registry_index_observations = lambda query, _slug: query
        accepted = parity.assert_direct_registry_index_parity(readers, "fleet/fixture", source_commit=commit)
        self.assertEqual(accepted["modes"], ["hybrid", "native_only", "worker_only"])
        for change in ("stale_commit", "missing_package", "incomplete_head", "different_platform", "wrong_frontier"):
            changed = copy.deepcopy(readers)
            if change == "stale_commit":
                changed["hybrid"]["index"][0][2] = "b" * 64
            elif change == "missing_package":
                changed["hybrid"]["packages"] = []
            elif change == "incomplete_head":
                changed["hybrid"]["artifact_snapshots"][0][6] = 0
            elif change == "different_platform":
                changed["worker_only"]["platforms"] = [["different"]]
            else:
                changed["hybrid"]["channel_floors"] = [["stable", "0.9.0"]]
            with self.assertRaises(ValueError, msg=change):
                parity.assert_direct_registry_index_parity(changed, "fleet/fixture", source_commit=commit)

    def test_storage_calls_are_attributed_by_actual_prefix_not_division(self):
        selected = [{"registrySlug": "fleet/a", "release": "1.0.0", "sourceCommit": "a" * 64,
            "placement": {"prefix": "private/a"}},
            {"registrySlug": "fleet/b", "release": "1.0.0", "sourceCommit": "b" * 64,
            "placement": {"prefix": "private/b"}}]
        projections = []
        for number, prefix in enumerate(("private/a", "private/a", "private/b")):
            projections.append({"requestId": str(number), "requestBytes": 17,
                "replyBytes": 31, "observation": {"placementPrefixSha256": hashlib.sha256(prefix.encode()).hexdigest(),
                    "operation": "inspect_git_objects", "executorSourceBytes": "73",
                    "payload": {"returnedGitContentBytes": "11", "returnedWholeOciObjectBytes": "0"}}})
        actual = codec.direct_release_storage_budget(projections, selected)
        self.assertEqual([row["calls"] for row in actual["releases"]], [2, 1])
        self.assertEqual([row["executorSourceBytes"] for row in actual["releases"]], [146, 73])
        changed = copy.deepcopy(projections)
        changed[0]["observation"]["placementPrefixSha256"] = "c" * 64
        with self.assertRaises(ValueError):
            codec.direct_release_storage_budget(changed, selected)
        with self.assertRaises(ValueError):
            codec.direct_release_storage_budget(projections, [selected[0], selected[0]])

    def test_missing_or_incomplete_outbound_body_cannot_enable_zero(self):
        arguments = ({}, {}, {}, {}, "a" * 64, None, {})
        with self.assertRaises(ValueError):
            codec.assess_direct_native_bodies(*arguments)
        boundary = {"unresolvedNativeRequestIds": ["actual-unknown"], "receivedWithoutOriginal": [],
            "captures": [], "authenticatedCompletions": [], "actualNativeRequests": 1}
        with self.assertRaises(ValueError):
            codec.assess_direct_native_bodies(*arguments, storage_work_boundary=boundary)


if __name__ == "__main__":
    unittest.main()
