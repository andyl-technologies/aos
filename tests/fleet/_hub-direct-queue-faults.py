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
native_faults = _load_sibling("_hub-direct-queue-fault-native.py")


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


def authenticated_admission_join(manifest, events, admission):
    """Join actual successful typed Worker verification before queue dispatch.

    Unlike the full-window accounting join, this requires no queue membership:
    no queue send is allowed yet. The selected session comes from the separately
    Core-validated immutable admission. Log/source/process custody is measured
    by the caller; this function only compares those retained observations.
    """
    capture = manifest["captures"][0]
    request, reply = (capture["bodies"][name] for name in ("request", "response"))
    public_sha = capture["immutableProjection"]["originalPublicRequest"]["sha256"]
    expected = {"sessionDigest": hashlib.sha256(admission["sessionId"].encode()).hexdigest(),
                "originalDigest": hashlib.sha256(admission["logicalFingerprint"].encode()).hexdigest()}
    offers, replies = [], []
    for event in events:
        if event["kind"] not in {"control_request", "control_reply"}:
            continue
        control = event["control"]
        if control["step"] != "admission" or control["signedBodyDigest"] != request["sha256"]:
            continue
        if (event["sourceDigest"] != manifest["sourceDigest"]
                or control["publicBodyDigest"] != public_sha):
            raise ValueError("authenticated admission source or public original differs")
        if event["kind"] == "control_request" and event["bytes"] == request["byteSize"]:
            offers.append(event)
        elif (event["kind"] == "control_reply" and event["outcome"] == "positive"
                and event["bytes"] == reply["byteSize"]
                and control["replyBodyDigest"] == reply["sha256"]):
            if control["sessions"] != [expected]:
                raise ValueError("authenticated admission reply names a different original")
            replies.append(event)
    pairs = {(offer["control"]["requestDigest"], finish["control"]["requestDigest"])
             for offer in offers for finish in replies
             if offer["control"]["requestDigest"] == finish["control"]["requestDigest"]}
    if len(pairs) != 1:
        raise ValueError("one exact authenticated Admission exchange is unavailable")
    return {"publicBeginSha256": public_sha, "requestSha256": request["sha256"],
            "replySha256": reply["sha256"], "requestDigest": next(iter(pairs))[0],
            "session": expected, "queueMembership": None,
            "scope": "actual successful typed Worker reply; independent source/process/window custody required"}


def prepared_queue_context(admission_body, status, complete_body, whoami,
                           placement_id, source_digest, run_digest, fault):
    """Join actual pre-Complete SQL and prepared production wire originals.

    The caller retains all arguments privately before installing the wrapper.
    No closed job, queue acceptance or completion intent is manufactured here.
    """
    if fault not in FAULTS:
        raise ValueError("production queue fault case differs")
    batch = native_faults._sql_row(complete_body)
    if (set(batch) != {"operationId", "items"} or not DIGEST.fullmatch(batch["operationId"])
            or not isinstance(batch["items"], list) or len(batch["items"]) != 1):
        raise ValueError("production fault needs one exact prepared Complete item")
    complete = batch["items"][0]
    if (complete["session"] != status["session"] or status["state"] != "creating"
            or complete["expectedResourceVersion"] != status["resourceVersion"]
            or not isinstance(complete["manifests"], list) or not complete["manifests"]
            or len(complete["manifests"]) != 1 or len(status["placements"]) != 1):
        # This first called slice selects one actual required placement. Extra
        # placements need independently retained originals, never truncation.
        raise ValueError("prepared Complete CAS, session or placement scope differs")
    manifest = complete["manifests"][0]
    if (manifest["placement"]["placementId"] != placement_id
            or manifest["placement"] != status["placements"][0]):
        raise ValueError("prepared Complete does not name the selected placement")
    admission, before = native_faults.admission_snapshot(
        admission_body, status["session"], status["intent"], whoami, placement_id)
    selected = queue_selection(admission, complete, placement_id, source_digest, run_digest,
                               fault if fault in {"enqueue_ack_lost", "completion_ack_lost"} else "none")
    return {"admission": admission, "complete": complete, "batch": batch,
            "completeBodySha256": hashlib.sha256(complete_body).hexdigest(),
            "completeBodyBytes": str(len(complete_body)), "before": before,
            "selection": selected, "original": production_original(admission, complete, placement_id),
            "fault": fault, "closedJob": None, "qualification": None}


def run_precomplete_queue_fault(prepared, *, read_admission, read_whoami,
                               capture_admission_projection, install_wrapper,
                               start_collector, configure_fault, retain_private):
    """Run the actual supervisor callback before its one saved dispatch.

    Operations are supplied by the existing machine/SQL/process owners. The
    Native supervisor owns the child and continuation marker; this callback
    does not send Complete or retry a mutation. Its returned references feed
    Native's closed continuation_record, not a ready/accepted boolean.
    """
    fields = {"fault", "status", "publicBeginBody", "completeBody", "placementId", "sourceDigest", "runDigest",
              "cutoffUnixMs"}
    if set(prepared) != fields:
        raise ValueError("production pre-Complete callback fields differ")
    admission_body = read_admission(prepared["status"]["session"]["sessionId"])
    whoami = read_whoami()
    context = prepared_queue_context(
        admission_body, prepared["status"], prepared["completeBody"], whoami,
        prepared["placementId"], prepared["sourceDigest"], prepared["runDigest"], prepared["fault"])
    if type(prepared["cutoffUnixMs"]) is not int or prepared["cutoffUnixMs"] <= 0:
        raise ValueError("production original has no fixed supervisor cutoff")
    context["cutoffUnixMs"] = prepared["cutoffUnixMs"]
    context["selection"]["capture"] = {
        "version": 1, "binding": "REGISTRY_BUCKET",
        "prefix": ".aos-queue-fault-capture/" + prepared["runDigest"] + "/",
        "cutoffUnixMs": prepared["cutoffUnixMs"]}
    # This callback must execute the current feature-enabled codec on actual
    # captured envelopes and the measured reader's original admission image.
    # Python comparisons of the public DTO or SQL fields do not replace it.
    evidence = capture_admission_projection(context)
    evidence_fields = {"manifest", "manifestSha256", "codecStdout", "sqlAdmissionsBody",
                       "authenticatedEvents", "references"}
    if not isinstance(evidence, dict) or set(evidence) != evidence_fields:
        raise ValueError("actual admission projection evidence is unavailable")
    manifest = evidence["manifest"]
    selected = manifest["captures"][0]["immutableProjection"]
    public = prepared["publicBeginBody"]
    sql_image = evidence["sqlAdmissionsBody"]
    if (not isinstance(public, bytes) or not isinstance(sql_image, bytes)
            or selected["originalPublicRequest"]["sha256"] != hashlib.sha256(public).hexdigest()
            or selected["originalPublicRequest"]["byteSize"] != str(len(public))
            or selected["sqlAdmissions"]["sha256"] != hashlib.sha256(sql_image).hexdigest()
            or selected["sqlAdmissions"]["byteSize"] != str(len(sql_image))
            or manifest["sourceDigest"] != prepared["sourceDigest"]):
        raise ValueError("actual codec projection selected a different original")
    sql_row = native_faults._sql_row(sql_image)
    if (sql_row["admission"] != context["admission"] or sql_row["state"] != "admitted"
            or sql_row["sessionId"] != context["admission"]["sessionId"]
            or sql_row["publicationId"] != context["admission"]["intent"]["target"]["publicationId"]):
        raise ValueError("Core image and admission-only reader selected different originals")
    projection = native_faults.admission_codec_result(
        evidence["codecStdout"], manifest, evidence["manifestSha256"])
    authenticated = authenticated_admission_join(
        manifest, evidence["authenticatedEvents"], context["admission"])
    references = evidence["references"]
    if not isinstance(references, dict) or set(references) != {
            "codecExecution", "codecOutput", "manifest", "sqlReader", "nativeCapture", "workerCapture"}:
        raise ValueError("admission codec, reader and capture custody references are missing")
    for reference in references.values():
        if (not isinstance(reference, dict) or set(reference) != {"file", "sha256", "byteSize"}
                or not isinstance(reference["file"], str) or not reference["file"].startswith("/")
                or not isinstance(reference["sha256"], str) or not DIGEST.fullmatch(reference["sha256"])
                or not isinstance(reference["byteSize"], str)
                or not re.fullmatch(r"[1-9][0-9]{0,8}", reference["byteSize"])):
            raise ValueError("admission validation receipt is not a private byte reference")
    if (references["codecOutput"]["sha256"] != hashlib.sha256(evidence["codecStdout"]).hexdigest()
            or references["manifest"]["sha256"] != evidence["manifestSha256"]):
        raise ValueError("actual codec result or manifest receipt changed")
    validation_ref = retain_private("queue-admission-core.json", {
        "projection": projection, "authenticatedControlJoin": authenticated,
        "references": references, "qualification": None})
    # Persist this complete original before wrapper installation or fault actions.
    original_ref = retain_private("queue-original.json", context)
    wrapper = install_wrapper(context["selection"])
    if (wrapper["compiledSourceDigest"] != context["selection"]["sourceDigest"]
            or wrapper.get("selection") != context["selection"]
            or not isinstance(wrapper.get("scriptPath"), str)
            or not wrapper["scriptPath"].endswith("/queue-fault-entry.mjs")
            or set(wrapper["modules"]) != {"installed-shim.mjs", "index.wasm",
                                          "queue-fault-worker.mjs", "queue-fault-entry.mjs"}):
        raise ValueError("actual wrapper installation differs from the prepared original")
    wrapper_ref = retain_private("queue-wrapper.json", wrapper)
    # Collection begins before continuation can cause the first real delivery.
    collector = start_collector(wrapper, prepared["cutoffUnixMs"])
    fault_ref = configure_fault(context)
    admission_ref = retain_private("queue-admission.json", {
        "sqlBodySha256": hashlib.sha256(admission_body).hexdigest(),
        "sqlBodyBytes": str(len(admission_body)), "original": original_ref,
        "coreValidation": validation_ref,
        "admissionDigest": context["selection"]["admissionDigest"],
        "completeBodySha256": context["completeBodySha256"], "fault": fault_ref})
    return {"admissionObservation": admission_ref, "wrapperObservation": wrapper_ref,
            "collector": collector, "context": context}


def run_called_queue_fault_window(cases, run_staged, callback_factory, assess):
    """Call five independently selected production windows without replay.

    Each case already names a real caller-owned preparing PublicationObject and
    its authenticated token/runtime selection. Window B's own source/child
    supervisor implements prepare/continue; a stopped child is not restaged.
    """
    if (not isinstance(cases, list) or len(cases) != len(FAULTS)
            or {case["fault"] for case in cases} != FAULTS
            or len({case["runDigest"] for case in cases}) != len(cases)
            or any(set(case) != {"fault", "runDigest", "selectionFile", "outputDirectory"}
                   or not DIGEST.fullmatch(case["runDigest"]) for case in cases)):
        raise ValueError("called production window needs five distinct exact fault originals")
    results = {}
    for case in cases:
        callbacks = []
        callback = callback_factory(case)

        def before_complete(prepared, root):
            if callbacks:
                raise ValueError("pre-Complete callback cannot repeat or restage an original")
            callbacks.append((prepared, root))
            return callback(prepared, root)

        # No exception handler retries this driver or writes a new original.
        run = run_staged(case["selectionFile"], case["outputDirectory"],
                         before_complete=before_complete)
        if len(callbacks) != 1:
            raise ValueError("production driver did not reach its saved-original boundary")
        results[case["fault"]] = assess(case, run)
    return {"cases": results, "nativeBulkBytes": None, "qualification": None,
            "resource2GiBAssessment": None,
            "scope": "called normal broker fault windows; independent provider/current-source joins required"}


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
