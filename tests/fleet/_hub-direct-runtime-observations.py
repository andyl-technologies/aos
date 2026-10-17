"""Interpret genuine DirectUpload console observations from the installed Worker.

The parser rejects schema drift and retains unknown or missing terminal effects.
It joins source reads to production queue originals before counting bytes; the
isolated qualifier's read observations cannot substitute for registry traffic.
Native bulk-byte conclusions still require the independent HTTP/provider audit.
"""

import collections
import json
import re


DIRECT_RUNTIME_PREFIX = "direct_upload_observation "
DIRECT_RUNTIME_FIELDS = frozenset((
    "version", "kind", "scope", "atMillis", "isolateDigest", "sourceDigest",
    "object", "queueClass", "readKind", "dataKind", "control", "deliveryDigest",
    "attemptDigest", "direction", "bytes", "outcome", "replayed",
    "aggregateActive", "bulkActive", "metadataActive", "providerActive",
    "providerBulkActive", "providerMetadataActive",
))
DIRECT_RUNTIME_KINDS = frozenset((
    "control_request", "control_reply", "queue_enqueue", "queue_start",
    "queue_finish", "queue_ack", "queue_retry", "provider_read_start",
    "provider_read_finish",
))
DIRECT_RUNTIME_STEPS = frozenset((
    "admission", "status", "grant_parts", "report_parts", "freeze", "complete",
    "baseline", "promote", "commit", "abort", "abort_report",
))


def _direct_runtime_digest(value, nullable=False):
    if nullable and value is None:
        return
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("runtime observation has an invalid commitment")


def _direct_runtime_integer(value, wire=False, nullable=False, maximum=2 ** 64 - 1):
    if nullable and value is None:
        return None
    if wire:
        if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
            raise ValueError("runtime observation has an invalid wire count")
        value = int(value)
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("runtime observation has an invalid numeric count")
    return value


def _direct_runtime_session(session):
    if not isinstance(session, dict) or set(session) != {"sessionDigest", "originalDigest"}:
        raise ValueError("runtime session differs from its closed schema")
    for value in session.values():
        _direct_runtime_digest(value)


def _direct_runtime_closed_json(body):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("runtime observation contains duplicate fields")
            result[key] = value
        return result

    return json.loads(body, object_pairs_hook=pairs)


def direct_runtime_observations(text, expected_source_digest):
    """Parse bounded production events under one independently observed source."""
    _direct_runtime_digest(expected_source_digest)
    events = []
    for line in text.splitlines():
        position = line.find(DIRECT_RUNTIME_PREFIX)
        if position < 0:
            continue
        body = line[position + len(DIRECT_RUNTIME_PREFIX):]
        if len(body.encode()) > 16 * 1024:
            raise ValueError("runtime observation exceeds the production event bound")
        event = _direct_runtime_closed_json(body)
        if (
            not isinstance(event, dict) or event.keys() != DIRECT_RUNTIME_FIELDS
            or type(event["version"]) is not int or event["version"] != 1
            or event["kind"] not in DIRECT_RUNTIME_KINDS
            or event["sourceDigest"] != expected_source_digest
            or event["outcome"] not in {"pending", "positive", "refused", "unknown"}
            or event["replayed"] is not None and type(event["replayed"]) is not bool
        ):
            raise ValueError("runtime observation schema, source or outcome changed")
        for name in ("isolateDigest", "sourceDigest", "attemptDigest"):
            _direct_runtime_digest(event[name])
        _direct_runtime_digest(event["deliveryDigest"], nullable=True)
        _direct_runtime_integer(event["atMillis"])
        _direct_runtime_integer(event["bytes"], wire=True, nullable=True)
        for name in ("aggregateActive", "bulkActive", "metadataActive", "providerActive",
                     "providerBulkActive", "providerMetadataActive"):
            _direct_runtime_integer(event[name], maximum=2 ** 32 - 1)

        kind = event["kind"]
        if kind.startswith("control_"):
            expected_direction = "worker_to_native" if kind == "control_request" else "native_to_worker"
            if (
                event["scope"] != "native_control" or event["dataKind"] != "logical_metadata"
                or event["direction"] != expected_direction or event["object"] is not None
                or event["queueClass"] is not None or event["readKind"] is not None
            ):
                raise ValueError("runtime control event has inconsistent provenance")
            control = event["control"]
            if (
                not isinstance(control, dict) or set(control) != {
                    "requestDigest", "publicBodyDigest", "signedBodyDigest",
                    "replyBodyDigest", "step", "sessions",
                }
                or control["step"] not in DIRECT_RUNTIME_STEPS
                or not isinstance(control["sessions"], list) or len(control["sessions"]) > 64
            ):
                raise ValueError("runtime control differs from the bounded batch schema")
            for name in ("requestDigest", "publicBodyDigest", "signedBodyDigest"):
                _direct_runtime_digest(control[name])
            _direct_runtime_digest(control["replyBodyDigest"], nullable=True)
            for session in control["sessions"]:
                _direct_runtime_session(session)
        else:
            obj = event["object"]
            if (
                not isinstance(obj, dict) or set(obj) != {
                    "session", "clientOperationDigest", "placementDigest", "operationDigest",
                    "completeOperationDigest", "dependencyPhase", "byteSize",
                }
                or obj["dependencyPhase"] not in {"content", "leaf_metadata", "visibility"}
                or event["control"] is not None
            ):
                raise ValueError("runtime object differs from the retained original schema")
            _direct_runtime_session(obj["session"])
            for name in ("clientOperationDigest", "placementDigest"):
                _direct_runtime_digest(obj[name])
            for name in ("operationDigest", "completeOperationDigest"):
                _direct_runtime_digest(obj[name], nullable=True)
            _direct_runtime_integer(obj["byteSize"], wire=True)
            expected_class = "bulk" if obj["dependencyPhase"] == "content" else "metadata"
            if event["queueClass"] != expected_class:
                raise ValueError("runtime queue class differs from the true dependency phase")
            if kind.startswith("queue_"):
                if (event["scope"] != "production_queue" or event["dataKind"] != "queue_metadata"
                        or event["direction"] is not None or event["readKind"] is not None):
                    raise ValueError("runtime queue event has inconsistent provenance")
            elif (event["scope"] != "storage_read" or event["dataKind"] != "source_object"
                    or event["direction"] != "provider_to_worker"
                    or event["readKind"] not in {"full_integrity", "semantic_metadata"}):
                raise ValueError("runtime source read has inconsistent provenance")
        events.append(event)
    if not events:
        raise ValueError("the actual Worker log contains no production observation events")
    return events


def _direct_runtime_original(obj):
    session = obj["session"]
    return (session["sessionDigest"], session["originalDigest"], obj["clientOperationDigest"],
            obj["placementDigest"], obj["operationDigest"], obj["dependencyPhase"], obj["byteSize"])


def direct_queue_overlap(events):
    """Join complete local attempts and observe metadata completion during bulk."""
    attempts = collections.defaultdict(list)
    for event in events:
        if event["kind"] in {"queue_start", "queue_finish"}:
            attempts[(event["isolateDigest"], event["attemptDigest"])].append(event)
    intervals = []
    invalid = 0
    for key, boundaries in attempts.items():
        starts = [item for item in boundaries if item["kind"] == "queue_start"]
        finishes = [item for item in boundaries if item["kind"] == "queue_finish"]
        if len(starts) != 1 or len(finishes) != 1:
            invalid += 1
            continue
        start, finish = starts[0], finishes[0]
        if (
            _direct_runtime_original(start["object"]) != _direct_runtime_original(finish["object"])
            or start["deliveryDigest"] != finish["deliveryDigest"]
            or finish["atMillis"] < start["atMillis"]
        ):
            invalid += 1
            continue
        intervals.append({"isolate_digest": key[0], "attempt_digest": key[1],
            "queue_class": start["queueClass"], "dependency_phase": start["object"]["dependencyPhase"],
            "started_at_millis": start["atMillis"], "finished_at_millis": finish["atMillis"],
            "outcome": finish["outcome"]})
    overlapping = []
    for metadata in intervals:
        if metadata["queue_class"] != "metadata" or metadata["outcome"] != "positive":
            continue
        bulk_attempts = [bulk["attempt_digest"] for bulk in intervals
            if bulk["queue_class"] == "bulk"
            and bulk["isolate_digest"] == metadata["isolate_digest"]
            and bulk["started_at_millis"] < metadata["finished_at_millis"] < bulk["finished_at_millis"]]
        if bulk_attempts:
            overlapping.append({"metadata_attempt_digest": metadata["attempt_digest"],
                "isolate_digest": metadata["isolate_digest"], "bulk_attempt_digests": bulk_attempts,
                "dependency_phase": metadata["dependency_phase"]})
    return {"complete_local_attempt_intervals": intervals,
        "incomplete_or_inconsistent_attempts": invalid,
        "positive_metadata_completions_during_bulk": overlapping,
        "clock_scope": "same participating isolate; no cross-isolate clock comparison",
        "settlement_scope": "local queue handler intervals; server settlement requires separate receipts"}


def summarize_direct_runtime(events):
    """Count correlated actual reads and preserve incomplete queue/control attempts."""
    originals = {
        _direct_runtime_original(event["object"])
        for event in events if event["scope"] == "production_queue"
    }
    counts = collections.Counter(event["kind"] for event in events)
    phase_objects = collections.Counter(original[-2] for original in originals)
    production_reads = [event for event in events if event["scope"] == "storage_read"
                        and _direct_runtime_original(event["object"]) in originals]
    byte_groups = collections.Counter()
    for event in production_reads:
        if event["kind"] == "provider_read_finish" and event["bytes"] is not None:
            obj = event["object"]
            key = (obj["dependencyPhase"], event["readKind"], event["outcome"])
            byte_groups[key] += int(event["bytes"])

    def attempts(start_kind, finish_kind, selected):
        groups = collections.defaultdict(collections.Counter)
        for event in selected:
            if event["kind"] in {start_kind, finish_kind}:
                groups[(event["isolateDigest"], event["attemptDigest"])][event["kind"]] += 1
        return {
            "started": sum(group[start_kind] for group in groups.values()),
            "finished": sum(group[finish_kind] for group in groups.values()),
            "missing_finish_attempts": sum(group[start_kind] > 0 and group[finish_kind] == 0
                                            for group in groups.values()),
            "unmatched_finish_attempts": sum(group[finish_kind] > 0 and group[start_kind] == 0
                                              for group in groups.values()),
            "duplicate_boundary_attempts": sum(group[start_kind] > 1 or group[finish_kind] > 1
                                                for group in groups.values()),
        }

    production = [event for event in events if event["scope"] == "production_queue"]
    peaks = {}
    for event in [*production, *production_reads]:
        peak = peaks.setdefault(event["isolateDigest"], {name: 0 for name in (
            "aggregateActive", "bulkActive", "metadataActive", "providerActive",
            "providerBulkActive", "providerMetadataActive",
        )})
        for name in peak:
            peak[name] = max(peak[name], event[name])

    control_groups = {}
    for event in events:
        if event["scope"] != "native_control":
            continue
        key = (event["control"]["step"], event["direction"], event["outcome"])
        group = control_groups.setdefault(key, {
            "step": key[0], "direction": key[1], "outcome": key[2], "events": 0,
            "known_bytes": 0, "unknown_byte_counts": 0, "maximum_known_bytes": 0,
        })
        group["events"] += 1
        if event["bytes"] is None:
            group["unknown_byte_counts"] += 1
        else:
            amount = int(event["bytes"])
            group["known_bytes"] += amount
            group["maximum_known_bytes"] = max(group["maximum_known_bytes"], amount)
    return {
        "event_counts": dict(counts), "production_placement_originals": len(originals),
        "production_phase_originals": dict(phase_objects),
        "production_read_bytes": [{"dependency_phase": key[0], "read_kind": key[1],
                                   "outcome": key[2], "consumed_bytes": count}
                                  for key, count in sorted(byte_groups.items())],
        "unjoined_storage_read_events": sum(event["scope"] == "storage_read"
                                             for event in events) - len(production_reads),
        "queue_attempts": attempts("queue_start", "queue_finish", production),
        "queue_overlap": direct_queue_overlap(production),
        "production_read_attempts": attempts("provider_read_start", "provider_read_finish", production_reads),
        "control_attempts": attempts("control_request", "control_reply", events),
        "control_byte_groups": [control_groups[key] for key in sorted(control_groups)],
        "unknown_control_replies": sum(event["kind"] == "control_reply"
                                       and event["outcome"] == "unknown" for event in events),
        "local_queue_ack_invocations": counts["queue_ack"],
        "participating_isolate_peaks": peaks,
        "global_invocation_bound": None,
        "native_bulk_bytes": None,
        "native_bulk_evidence": "requires correlated Native HTTP and direct provider transfer receipts",
        "observation_completeness": "requires full retained log boundaries and terminal original audit",
    }


def direct_same_registry_parallel_reads(events, mapping, publication_id, minimum_bytes):
    """Join simultaneous full reads of distinct originals in one publication.

    The SQL capture supplies actual publication ownership. Isolated qualifier
    reads, different publications, replayed finishes and incomplete attempts
    cannot establish this same-registry concurrency gate.
    """
    selected = {}
    for original in mapping["originals"]:
        if (original["publicationId"] != publication_id
                or original["dependencyPhase"] != "content"
                or int(original["byteSize"]) < minimum_bytes):
            continue
        coordinate = (original["sessionDigest"], original["originalDigest"],
            original["clientOperationDigest"], original["placementDigest"])
        if coordinate in selected and selected[coordinate] != original:
            raise ValueError("same-registry original ownership is ambiguous")
        selected[coordinate] = original
    production = {_direct_runtime_original(event["object"])
        for event in events if event["scope"] == "production_queue"}
    attempts = collections.defaultdict(list)
    for event in events:
        if (event["scope"] == "storage_read" and event["readKind"] == "full_integrity"
                and _direct_runtime_original(event["object"]) in production):
            attempts[(event["isolateDigest"], event["attemptDigest"])].append(event)
    intervals, incomplete = [], 0
    for (isolate, attempt), boundaries in attempts.items():
        starts = [item for item in boundaries if item["kind"] == "provider_read_start"]
        finishes = [item for item in boundaries if item["kind"] == "provider_read_finish"]
        if len(starts) != 1 or len(finishes) != 1:
            incomplete += 1
            continue
        start, finish = starts[0], finishes[0]
        obj = start["object"]
        coordinate = (obj["session"]["sessionDigest"], obj["session"]["originalDigest"],
            obj["clientOperationDigest"], obj["placementDigest"])
        original = selected.get(coordinate)
        if original is None:
            continue
        if (_direct_runtime_original(obj) != _direct_runtime_original(finish["object"])
                or finish["outcome"] != "positive" or finish["replayed"] is not False
                or finish["bytes"] != original["byteSize"]
                or int(obj["byteSize"]) != int(original["byteSize"])
                or finish["atMillis"] <= start["atMillis"]):
            incomplete += 1
            continue
        intervals.append({"isolateDigest": isolate, "attemptDigest": attempt,
            "sessionDigest": coordinate[0], "originalDigest": coordinate[1],
            "objectPathSha256": original["objectPathSha256"],
            "publicationId": publication_id, "consumedBytes": int(finish["bytes"]),
            "startedAtMillis": start["atMillis"], "finishedAtMillis": finish["atMillis"]})
    overlaps = []
    for index, first in enumerate(intervals):
        for second in intervals[index + 1:]:
            if (first["isolateDigest"] == second["isolateDigest"]
                    and first["sessionDigest"] != second["sessionDigest"]
                    and first["objectPathSha256"] != second["objectPathSha256"]
                    and max(first["startedAtMillis"], second["startedAtMillis"])
                        < min(first["finishedAtMillis"], second["finishedAtMillis"])):
                overlaps.append({"isolateDigest": first["isolateDigest"],
                    "attemptDigests": [first["attemptDigest"], second["attemptDigest"]],
                    "sessionDigests": [first["sessionDigest"], second["sessionDigest"]],
                    "publicationId": publication_id})
    return {"version": 1, "publicationId": publication_id,
        "minimumObjectBytes": minimum_bytes, "completeIntegrityIntervals": intervals,
        "samePublicationOverlaps": overlaps, "incompleteOrRefusedAttempts": incomplete,
        "scope": "actual distinct Content sessions within one retained publication; same-isolate consumed streams, no cross-isolate clock inference"}
