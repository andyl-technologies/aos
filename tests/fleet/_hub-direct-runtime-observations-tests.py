"""Exercise evidence refusals without dispatching provider or fleet operations."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest


source = Path(__file__).with_name("_hub-direct-runtime-observations.py")
specification = importlib.util.spec_from_file_location("direct_runtime_observations", source)
observations = importlib.util.module_from_spec(specification)
specification.loader.exec_module(observations)


def event(kind):
    """Construct an explicitly synthetic parser input, never runtime evidence."""
    value = {
        "version": 1, "kind": kind, "scope": "production_queue", "atMillis": 100,
        "isolateDigest": "1" * 64, "sourceDigest": "2" * 64,
        "object": {"session": {"sessionDigest": "3" * 64, "originalDigest": "4" * 64},
                   "clientOperationDigest": "5" * 64, "placementDigest": "6" * 64,
                   "operationDigest": "7" * 64, "completeOperationDigest": "8" * 64,
                   "dependencyPhase": "visibility", "byteSize": "65536"},
        "queueClass": "metadata", "readKind": None, "dataKind": "queue_metadata",
        "control": None, "deliveryDigest": "9" * 64, "attemptDigest": "a" * 64,
        "direction": None, "bytes": "0", "outcome": "pending", "replayed": None,
        "aggregateActive": 1, "bulkActive": 0, "metadataActive": 1,
        "providerActive": 0, "providerBulkActive": 0, "providerMetadataActive": 0,
    }
    if kind.startswith("provider_read_"):
        value.update(scope="storage_read", dataKind="source_object", deliveryDigest=None,
                     readKind="full_integrity", direction="provider_to_worker", attemptDigest="b" * 64)
    return value


def parse(*values):
    text = "\n".join(observations.DIRECT_RUNTIME_PREFIX + json.dumps(value) for value in values)
    return observations.direct_runtime_observations(text, "2" * 64)


class EvidenceRefusals(unittest.TestCase):
    def test_same_registry_parallel_requires_full_distinct_actual_originals(self):
        values, originals = [], []
        publication = "e" * 32
        size = str(2 * 1024 ** 3)
        for index, digest in enumerate(("c", "d")):
            queue = event("queue_start")
            queue["object"]["session"]["sessionDigest"] = digest * 64
            queue["object"].update(dependencyPhase="content", byteSize=size)
            queue["queueClass"] = "bulk"
            start, finish = event("provider_read_start"), event("provider_read_finish")
            for item in (start, finish):
                item["object"] = copy.deepcopy(queue["object"])
                item.update(queueClass="bulk", attemptDigest=digest * 64)
            start["atMillis"] = 100 + index * 20
            finish.update(atMillis=200 + index * 20, bytes=size, outcome="positive", replayed=False)
            values.extend((queue, start, finish))
            originals.append({"publicationId": publication, "dependencyPhase": "content",
                "byteSize": size, "sessionDigest": digest * 64,
                "originalDigest": "4" * 64, "clientOperationDigest": "5" * 64,
                "placementDigest": "6" * 64, "objectPathSha256": digest * 64})
        actual = observations.direct_same_registry_parallel_reads(
            parse(*values), {"originals": originals}, publication, int(size),
        )
        self.assertEqual(len(actual["samePublicationOverlaps"]), 1)
        self.assertEqual(len(actual["completeIntegrityIntervals"]), 2)
        for variation in ("other_publication", "other_isolate", "partial", "missing_finish"):
            changed, selected = copy.deepcopy(values), copy.deepcopy(originals)
            if variation == "other_publication":
                selected[1]["publicationId"] = "f" * 32
            elif variation == "other_isolate":
                changed[4]["isolateDigest"] = changed[5]["isolateDigest"] = "f" * 64
            elif variation == "partial":
                changed[5]["bytes"] = "17"
            else:
                changed.pop()
            refused = observations.direct_same_registry_parallel_reads(
                parse(*changed), {"originals": selected}, publication, int(size),
            )
            self.assertEqual(refused["samePublicationOverlaps"], [], variation)

    def test_overlap_requires_complete_same_isolate_attempts(self):
        bulk_start, bulk_finish = event("queue_start"), event("queue_finish")
        for value in (bulk_start, bulk_finish):
            value.update(queueClass="bulk", bulkActive=1, metadataActive=0)
            value["object"]["dependencyPhase"] = "content"
        bulk_start["atMillis"] = 100
        bulk_finish.update(atMillis=200, outcome="positive")
        metadata_start, metadata_finish = event("queue_start"), event("queue_finish")
        metadata_start.update(atMillis=120, attemptDigest="c" * 64)
        metadata_finish.update(atMillis=150, attemptDigest="c" * 64, outcome="positive")
        actual = observations.summarize_direct_runtime(parse(
            bulk_start, metadata_start, metadata_finish, bulk_finish,
        ))["queue_overlap"]
        self.assertEqual(len(actual["positive_metadata_completions_during_bulk"]), 1)
        for value in (metadata_start, metadata_finish):
            value["isolateDigest"] = "d" * 64
        other_isolate = observations.summarize_direct_runtime(parse(
            bulk_start, metadata_start, metadata_finish, bulk_finish,
        ))["queue_overlap"]
        self.assertEqual(other_isolate["positive_metadata_completions_during_bulk"], [])
        missing = observations.summarize_direct_runtime(parse(
            bulk_start, metadata_start, metadata_finish,
        ))["queue_overlap"]
        self.assertEqual(missing["positive_metadata_completions_during_bulk"], [])
        self.assertEqual(missing["incomplete_or_inconsistent_attempts"], 1)

    def test_isolated_reads_cannot_supply_production_bytes(self):
        start, finish = event("provider_read_start"), event("provider_read_finish")
        finish.update(bytes="65536", outcome="positive")
        result = observations.summarize_direct_runtime(parse(start, finish))
        self.assertEqual(result["unjoined_storage_read_events"], 2)
        self.assertEqual(result["production_read_bytes"], [])
        self.assertEqual(result["production_placement_originals"], 0)

    def test_failed_prefix_does_not_become_declared_object_bytes(self):
        queue, start, finish = event("queue_start"), event("provider_read_start"), event("provider_read_finish")
        finish.update(bytes="17", outcome="unknown")
        result = observations.summarize_direct_runtime(parse(queue, start, finish))
        self.assertEqual(result["production_read_bytes"], [{
            "dependency_phase": "visibility", "read_kind": "full_integrity",
            "outcome": "unknown", "consumed_bytes": 17,
        }])
        self.assertEqual(result["queue_attempts"]["missing_finish_attempts"], 1)
        self.assertEqual(result["production_phase_originals"], {"visibility": 1})
        self.assertIsNone(result["native_bulk_bytes"])
        self.assertIsNone(result["global_invocation_bound"])

    def test_changed_physical_original_cannot_join(self):
        queue, read = event("queue_start"), event("provider_read_finish")
        read.update(bytes="65536", outcome="positive")
        read["object"]["operationDigest"] = "c" * 64
        result = observations.summarize_direct_runtime(parse(queue, read))
        self.assertEqual(result["production_read_bytes"], [])
        self.assertEqual(result["unjoined_storage_read_events"], 1)

    def test_schema_source_and_duplicate_fields_refuse(self):
        for change in ({"sourceDigest": "c" * 64}, {"providerUrl": "https://synthetic.test"},
                       {"bytes": "00"}, {"atMillis": True}, {"queueClass": "bulk"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                value = event("queue_start")
                value.update(change)
                parse(value)
        body = json.dumps(event("queue_start"))
        with self.assertRaises(ValueError):
            observations.direct_runtime_observations(
                observations.DIRECT_RUNTIME_PREFIX + body[:-1] + ',"version":1}', "2" * 64,
            )

    def test_unknown_reply_retains_unknown_length(self):
        reply = event("control_reply")
        reply.update(scope="native_control", object=None, queueClass=None,
                     dataKind="logical_metadata", direction="native_to_worker",
                     bytes=None, outcome="unknown", deliveryDigest=None,
                     control={"requestDigest": "3" * 64, "publicBodyDigest": "4" * 64,
                              "signedBodyDigest": "5" * 64, "replyBodyDigest": None,
                              "step": "freeze", "sessions": []})
        actual = parse(reply)
        self.assertIsNone(actual[0]["bytes"])
        self.assertEqual(observations.summarize_direct_runtime(actual)["unknown_control_replies"], 1)
        oversized = copy.deepcopy(reply)
        oversized["control"]["sessions"] = [{"sessionDigest": "3" * 64,
                                                "originalDigest": "4" * 64}] * 65
        with self.assertRaises(ValueError):
            parse(oversized)


if __name__ == "__main__":
    unittest.main()
