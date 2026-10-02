"""Drive and join queue faults around one real retained production original.

The selected fleet must retain raw originals, replies, complete logs and query
results independently. Actual SQL/token calls live in the sibling Native helper;
the provider adapter owns its explicit single-object replacement. This joiner
grants no provider permission and leaves platform accounting unresolved.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import re


PREFIX = "direct_queue_fault_observation "
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
EVENT_FIELDS = {"version", "sourceDigest", "runDigest", "kind", "invocationDigest",
                "atMillis", "jobDigest", "batchMessages", "selectedMessages", "outcome", "sdkReturned"}
KINDS = {"fetch_start", "fetch_finish", "invocation_start", "invocation_jobs", "invocation_finish",
         "enqueue_dispatch", "enqueue_sdk_return", "enqueue_ack_dropped",
         "completion_ack_attempt", "completion_ack_dropped", "completion_ack_sdk_return"}
FAULTS = {"enqueue_ack_lost", "completion_ack_lost", "conditional_source_replacement",
          "authorization_revoked", "delegation_expired"}


def _load_sibling(name):
    source = Path(__file__).with_name(name)
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runtime = _load_sibling("_hub-direct-runtime-observations.py")
resources = _load_sibling("_hub-direct-invocation-resources.py")


def canonical_digest(value):
    """Commit a bounded parsed original using the wrapper's sorted JSON encoding."""
    def validate(item):
        if item is None or type(item) in {bool, str}:
            return
        if type(item) is int and abs(item) <= 9007199254740991:
            return
        if isinstance(item, list):
            for child in item:
                validate(child)
            return
        if isinstance(item, dict) and all(isinstance(key, str) for key in item):
            for child in item.values():
                validate(child)
            return
        raise ValueError("queue original is not compatible bounded JSON")
    validate(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if len(encoded) > 64 * 1024:
        raise ValueError("selected queue original exceeds its production bound")
    return hashlib.sha256(encoded).hexdigest()


def queue_selection(admission, complete, placement_id, source_digest, run_digest, fault):
    """Select a retained admission/Complete without guessing its later close receipt."""
    if (fault not in {"none", "enqueue_ack_lost", "completion_ack_lost"}
            or not isinstance(source_digest, str) or not DIGEST.fullmatch(source_digest)
            or not isinstance(run_digest, str) or not DIGEST.fullmatch(run_digest)
            or not isinstance(placement_id, str) or not re.fullmatch(r"[1-9][0-9]{0,18}", placement_id)
            or complete["session"] != {"sessionId": admission["sessionId"],
                                       "logicalFingerprint": admission["logicalFingerprint"]}
            or not any(str(row["placementId"]) == placement_id for row in admission["placements"])):
        raise ValueError("queue selection differs from the retained original")
    phase = admission["intent"]["dependencyPhase"]
    if phase not in {"content", "leaf_metadata", "visibility"}:
        raise ValueError("queue selection has no real dependency phase")
    return {"version": 1, "sourceDigest": source_digest, "runDigest": run_digest,
            "admissionDigest": canonical_digest(admission), "completeDigest": canonical_digest(complete),
            "placementId": placement_id,
            "binding": "HUB_DIRECT_VERIFY_BULK" if phase == "content" else "HUB_DIRECT_VERIFY_METADATA",
            "fault": fault}


def fault_observations(text, source_digest, run_digest):
    """Parse bounded wrapper events with exact source/run and unknown retention."""
    rows = []
    if not all(isinstance(value, str) and DIGEST.fullmatch(value) for value in (source_digest, run_digest)):
        raise ValueError("queue fault source/run selection differs")
    if len(text.encode()) > 16 * 1024 * 1024:
        raise ValueError("queue fault log exceeds its retained bound")
    for line in text.splitlines():
        offset = line.find(PREFIX)
        if offset < 0:
            continue
        body = line[offset+len(PREFIX):]
        if len(body.encode()) > 4096:
            raise ValueError("queue fault event exceeds its bound")
        row = runtime._direct_runtime_closed_json(body)
        if (set(row) != EVENT_FIELDS or type(row["version"]) is not int or row["version"] != 1
                or row["kind"] not in KINDS or row["sourceDigest"] != source_digest
                or row["runDigest"] != run_digest
                or row["outcome"] not in {"pending", "positive", "unknown", "returned", "threw"}
                or type(row["atMillis"]) is not int or row["atMillis"] < 0
                or not isinstance(row["invocationDigest"], str) or not DIGEST.fullmatch(row["invocationDigest"])
                or row["jobDigest"] is not None and (not isinstance(row["jobDigest"], str)
                                                   or not DIGEST.fullmatch(row["jobDigest"]))
                or row["sdkReturned"] is not None and type(row["sdkReturned"]) is not bool):
            raise ValueError("queue fault event identity or closed schema differs")
        for field in ("batchMessages", "selectedMessages"):
            if row[field] is not None and (type(row[field]) is not int or not 0 <= row[field] <= 32):
                raise ValueError("queue fault batch observation differs")
        rows.append(row)
        if len(rows) > 16384:
            raise ValueError("queue fault event count exceeds its bound")
    return rows


def production_original(admission, complete, placement_id):
    """Derive the privacy-safe event commitments from the exact retained original."""
    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()
    return {"sessionDigest": digest(admission["sessionId"]),
            "originalDigest": digest(admission["logicalFingerprint"]),
            "completeOperationDigest": digest(complete["operationId"]),
            "placementDigest": digest(placement_id)}


def selected_queue_events(events, original):
    """Refuse substituted queue identities while selecting one production original."""
    selected = []
    for event in events:
        if not event["kind"].startswith("queue_"):
            continue
        obj = event["object"]
        if obj["session"]["sessionDigest"] != original["sessionDigest"]:
            continue
        if (obj["session"]["originalDigest"] != original["originalDigest"]
                or obj["placementDigest"] != original["placementDigest"]
                or obj["completeOperationDigest"] != original["completeOperationDigest"]):
            raise ValueError("queue observation changed the selected original")
        selected.append(event)
    return selected


def single_invocation_resources(observation, wrappers, production_events, original):
    """Join whole handler bounds only for a singleton selected queue delivery."""
    candidates = [row for row in wrappers if row["kind"] == "invocation_jobs"
                  and row["selectedMessages"] == 1 and row["batchMessages"] == 1]
    if len(candidates) != 1:
        raise ValueError("resource window is not one selected singleton invocation")
    invocation = candidates[0]
    related = [row for row in wrappers if row["invocationDigest"] == invocation["invocationDigest"]]
    starts = [row for row in related if row["kind"] == "invocation_start"]
    finishes = [row for row in related if row["kind"] == "invocation_finish"]
    if len(starts) != 1 or len(finishes) != 1:
        raise ValueError("whole queue invocation lacks its actual terminal boundary")
    started, finished = starts[0]["atMillis"], finishes[0]["atMillis"]
    if not started <= invocation["atMillis"] <= finished:
        raise ValueError("whole queue invocation boundaries are unordered")
    for row in wrappers:
        if (row["invocationDigest"] != invocation["invocationDigest"]
                and started <= row["atMillis"] <= finished):
            raise ValueError("resource window overlaps another observed invocation")
    queues = selected_queue_events(production_events, original)
    queue_starts = [row for row in queues if row["kind"] == "queue_start"]
    queue_finishes = [row for row in queues if row["kind"] == "queue_finish"]
    if (len(queue_starts) != 1 or len(queue_finishes) != 1
            or queue_starts[0]["attemptDigest"] != queue_finishes[0]["attemptDigest"]
            or not started <= queue_starts[0]["atMillis"] <= queue_finishes[0]["atMillis"] <= finished
            or queue_starts[0]["aggregateActive"] != 1):
        raise ValueError("resource window lacks one whole production attempt")
    for row in production_events:
        if (started <= row["atMillis"] <= finished and row["kind"] == "queue_start"
                and row["attemptDigest"] != queue_starts[0]["attemptDigest"]):
            raise ValueError("resource window contains another production queue attempt")
    return {"invocationDigest": invocation["invocationDigest"], "jobDigest": invocation["jobDigest"],
            "attemptDigest": queue_starts[0]["attemptDigest"],
            "processEnvelope": resources.invocation_process_envelope(observation, started, finished),
            "scope": "whole singleton observed handler; process envelope includes runtime overhead, not isolate accounting"}


def assert_pending_did_not_publish(before, after, provider_receipts, selected_path_digests):
    """Check actual read-only progress and the complete selected provider window."""
    fields = {"sessionDigest", "admissionDigest", "state", "completionReceipts", "publicationState"}
    if (set(before) != fields or set(after) != fields
            or before["sessionDigest"] != after["sessionDigest"]
            or before["admissionDigest"] != after["admissionDigest"]
            or before["state"] not in {"admitted", "staged_verified"}
            or after["state"] not in {"admitted", "staged_verified"}
            or type(before["completionReceipts"]) is not int
            or type(after["completionReceipts"]) is not int
            or before["completionReceipts"] != 0 or after["completionReceipts"] != 0
            or before["publicationState"] != after["publicationState"]
            or after["publicationState"] != "preparing"):
        raise AssertionError("pending original or publication barrier advanced")
    if not selected_path_digests or not all(isinstance(value, str) and DIGEST.fullmatch(value)
                                         for value in selected_path_digests):
        raise ValueError("pending provider window has no independently mapped physical originals")
    for receipt in provider_receipts:
        if receipt["caller"] not in {"worker", "client", "native", "provider"}:
            raise ValueError("pending provider window has an unknown caller")
        if receipt["method"] not in {"GET", "HEAD", "POST", "PUT", "DELETE"}:
            raise ValueError("pending provider window has an unknown method")
        if receipt["pathSha256"] not in selected_path_digests:
            raise ValueError("pending provider window contains an unpartitioned physical path")
        if receipt["method"] in {"POST", "PUT", "DELETE"}:
            raise AssertionError("pending recovery dispatched a provider mutation")
    return {"sessionDigest": before["sessionDigest"], "admissionDigest": before["admissionDigest"],
            "observedProviderCalls": len(provider_receipts), "observedProviderMutations": 0,
            "nativeBulkBytes": None, "qualification": None,
            "scope": "observed selected receipts only; completeness/auth/body custody needs independent review"}


def assert_ack_loss_observed(rows, job_digest, fault):
    """Require the selected actual SDK boundary, retaining its unknown outcome."""
    if (fault not in {"enqueue_ack_lost", "completion_ack_lost"}
            or not isinstance(job_digest, str) or not DIGEST.fullmatch(job_digest)):
        raise ValueError("ACK loss selection differs")
    selected = [row for row in rows if row["jobDigest"] == job_digest]
    if fault == "enqueue_ack_lost":
        dispatched = [row for row in selected if row["kind"] == "enqueue_dispatch"]
        returned = [row for row in selected if row["kind"] == "enqueue_sdk_return"
                    and row["outcome"] == "positive" and row["sdkReturned"] is True]
        dropped = [row for row in selected if row["kind"] == "enqueue_ack_dropped"
                   and row["outcome"] == "unknown" and row["sdkReturned"] is True]
        if (len(dispatched) != 1 or len(returned) != 1 or len(dropped) != 1
                or not dispatched[0]["atMillis"] <= returned[0]["atMillis"] <= dropped[0]["atMillis"]
                or len({row["invocationDigest"] for row in dispatched + returned + dropped}) != 1):
            raise AssertionError("selected enqueue ACK loss lacks the actual successful SDK return")
    else:
        attempted = [row for row in selected if row["kind"] == "completion_ack_attempt"]
        dropped = [row for row in selected if row["kind"] == "completion_ack_dropped"
                   and row["outcome"] == "unknown" and row["sdkReturned"] is False]
        if (not attempted or len(dropped) != 1
                or not any(row["invocationDigest"] == dropped[0]["invocationDigest"]
                           and row["atMillis"] <= dropped[0]["atMillis"] for row in attempted)):
            raise AssertionError("selected completion ACK loss lacks the actual consumer callback")
        if any(row["kind"] == "completion_ack_sdk_return"
               and row["invocationDigest"] == dropped[0]["invocationDigest"] for row in selected):
            raise AssertionError("dropped completion ACK also reported an SDK return")
    return {"jobDigest": job_digest, "fault": fault, "outcome": "unknown",
            "queueServerAcceptance": None, "qualification": None}


def assert_retained_read_replay(events, original, expected_job_digest, wrappers):
    """Join real production replay to the unchanged closed job without new reads."""
    if not isinstance(expected_job_digest, str) or not DIGEST.fullmatch(expected_job_digest):
        raise ValueError("closed replay job commitment differs")
    selected = selected_queue_events(events, original)
    finishes = [row for row in selected if row["kind"] == "queue_finish"]
    positive = [row for row in finishes if row["outcome"] == "positive"
                and row["replayed"] is False]
    replayed = [row for row in finishes if row["outcome"] == "positive"
                and row["replayed"] is True]
    if (len(positive) != 1 or not replayed
            or any(row["atMillis"] < positive[0]["atMillis"] for row in replayed)
            or len({row["attemptDigest"] for row in positive + replayed}) != len(positive + replayed)):
        raise AssertionError("queue replay lacks real original/replayed terminal observations")
    jobs = [row for row in wrappers if row["kind"] == "invocation_jobs" and row["selectedMessages"]]
    if len(jobs) < 2 or any(row["jobDigest"] != expected_job_digest for row in jobs):
        raise AssertionError("queue redelivery changed the original closed job")
    # Provider/physical journals are owned by other DOs. Their actual captures
    # must independently establish no redispatch; an ambient counter is not used.
    return {"jobDigest": expected_job_digest, "positiveAttempts": len(positive),
            "replayedAttempts": len(replayed), "providerRedispatch": None, "qualification": None}
