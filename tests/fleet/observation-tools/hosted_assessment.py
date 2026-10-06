"""Assess private hosted application observations without inventing wire facts.

The selected runtime codecs, Native log readers and SQL projection comparison
remain the production sources of semantics. Receiver images are independent
byte images, not duplicated Native captures. Unobserved traffic remains unknown.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys


PACKAGE_READER = runpy.run_path(str(Path(__file__).resolve(strict=True).parent / "package_context.py"))
PACKAGE = PACKAGE_READER["context"](__file__)
SOURCE = Path(PACKAGE["runtimeSource"])
WRAPPER = Path(PACKAGE["nativeAuth"]["file"])

MAX_JSON = 1024 * 1024
MAX_BODY = 8 * 1024 * 1024
MAX_CORPUS = 512 * 1024 * 1024
MAX_RECORDS = 262144
CAPTURE_IMPLEMENTATION_SHA = PACKAGE["captureImplementationSha256"]
CAPTURE_BASE_FIELDS = {"version", "captureId", "corpusId", "windowId", "role", "purpose",
                       "sourceCommit", "sourceTree", "runtimeSourceDigest", "nativeExecutableSha256",
                       "workerSourceDigest", "captureImplementationSha256", "transportCallId", "requestId",
                       "method", "pathSha256", "queryClass", "status", "provenance", "instrumentationTraffic"}
CAPTURE_DIRECTION_FIELDS = {"direction", "state", "observedBytes", "retainedBytes", "eof", "imageKind",
                            "frameState", "startedAtMillis", "finishedAtMillis", "responseConsumptionClaim",
                            "capturePersistence", "privateImages", "qualificationClaim"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def closed(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError("Closed assessment schema differs")


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Digest differs")
    return value


def decimal(value, maximum=2**64 - 1):
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        raise ValueError("Count differs")
    count = int(value)
    if count > maximum:
        raise ValueError("Count exceeds bound")
    return count


def private_reader():
    """Reuse the installed reviewed reader without weakening private inputs."""
    raw = PACKAGE_READER["installed_bytes"](WRAPPER, MAX_JSON)
    if sha(raw) != PACKAGE["nativeAuth"]["sha256"]:
        raise ValueError("Installed reader commitment differs")
    namespace = {"__name__": "reviewed_auth_reader", "__file__": str(WRAPPER)}
    exec(compile(raw, str(WRAPPER), "exec"), namespace)
    return namespace


def read(reference, maximum=MAX_JSON):
    return READERS["read_ref"](reference, maximum)


def parsed(reference, maximum=MAX_JSON):
    return READERS["closed_json"](read(reference, maximum))


def unique(rows, key):
    if not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise ValueError("Record inventory exceeds bound")
    result = {}
    for row in rows:
        identity = key(row)
        if identity in result:
            raise ValueError("Duplicate record ownership")
        result[identity] = row
    return result


def observe(selection, manifest_reference):
    """Invoke the selected actual codec and bind its returned manifest digest."""
    manifest_raw = read(manifest_reference)
    manifest = READERS["closed_json"](manifest_raw)
    process = READERS["observe"](selection["observerExecutable"], manifest_reference["file"])
    if process.returncode:
        return manifest, None, {"reason": "selected_codec_refused", "exitCode": process.returncode,
                                "stderrSha256": sha(process.stderr)}
    report = READERS["closed_json"](process.stdout)
    closed(report, {"version", "codecRevision", "selectedSourceDigest", "manifestSha256",
                    "selectedBodyBytes", "maximumSelectedBodyBytes", "maximumBodyBytes", "captures"})
    if (report["manifestSha256"] != sha(manifest_raw)
            or report["codecRevision"] != selection["runtime"]["runtimeCodecRevision"]
            or report["selectedSourceDigest"] != selection["runtime"]["workerSourceDigest"]
            or report["maximumBodyBytes"] != MAX_BODY
            or report["maximumSelectedBodyBytes"] != MAX_CORPUS):
        raise ValueError("Actual codec report belongs to another selection")
    return manifest, report, None


DIRECT_CONTROL_ROUTES = {
    "/_internal/storage/v1/capabilities": (64 * 1024, "direct_storage_capabilities"),
    "/_internal/storage/direct-upload-authority": (256 * 1024, "direct_authority_lookup"),
    "/_internal/storage/direct-upload-final-guard": (256 * 1024, "direct_final_guard"),
}
DIRECT_CONTROL_FIELDS = {
    "version", "state", "route", "transportCallId", "constructorSourceSha256", "nonceSha256",
    "offeredRequestSha256", "offeredRequestBytes", "endpointScheme", "replyStatus",
    "exposedReplySha256", "exposedReplyBytes", "replyEof", "outcome", "observedAtUnixMicros",
    "replyMacAuthentication", "finalSqlAuthority",
}
DIRECT_CONTROL_OUTCOMES = {
    "offered", "cancelled", "transport_error", "status_rejected", "signature_header_error",
    "stream_error", "reply_overflow", "reply_eof_unverified",
}


def direct_constructor_sha256():
    """Commit the same finite compiled constructor inputs as the Native sender."""
    value = hashlib.sha256(b"aos.native.direct-control-constructor.v1\0")
    for name in (
            "crates/aos-hub/src/direct_upload/authority/transport.rs",
            "crates/aos-hub/src/direct_upload/authority/transport/observation.rs",
            "crates/aos-hub-core/src/direct_upload/capabilities_wire.rs",
            "crates/aos-hub-core/src/direct_upload/authority_lookup.rs",
            "crates/aos-hub-core/src/direct_upload/final_guard.rs",
            "crates/aos-hub-core/src/direct_upload/wire.rs"):
        raw = PACKAGE_READER["installed_bytes"](SOURCE / name, MAX_JSON)
        encoded = name.encode()
        value.update(len(encoded).to_bytes(8, "big"))
        value.update(encoded)
        value.update(len(raw).to_bytes(8, "big"))
        value.update(raw)
    return value.hexdigest()


def validate_direct_control_event(value, constructor):
    """Validate observed transport facts without asserting MAC or SQL success."""
    closed(value, DIRECT_CONTROL_FIELDS)
    if (type(value["version"]) is not int or value["version"] != 1
            or value["state"] not in {"offered", "terminal"}
            or value["route"] not in DIRECT_CONTROL_ROUTES
            or value["outcome"] not in DIRECT_CONTROL_OUTCOMES
            or value["endpointScheme"] not in {"http", "https"}
            or value["constructorSourceSha256"] != constructor
            or value["replyMacAuthentication"] is not None or value["finalSqlAuthority"] is not None
            or type(value["replyEof"]) is not bool
            or not isinstance(value["transportCallId"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", value["transportCallId"])):
        raise ValueError("Direct control sender context differs")
    for name in ("constructorSourceSha256", "nonceSha256", "offeredRequestSha256", "exposedReplySha256"):
        digest(value[name])
    bound, _ = DIRECT_CONTROL_ROUTES[value["route"]]
    decimal(value["offeredRequestBytes"], bound)
    consumed = decimal(value["exposedReplyBytes"])
    if value["observedAtUnixMicros"] is not None:
        decimal(value["observedAtUnixMicros"])
    status = value["replyStatus"]
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        raise ValueError("Direct control status differs")
    if (consumed == 0 and value["exposedReplySha256"] != sha(b"")
            or status is None and (consumed or value["replyEof"])
            or value["state"] == "offered" and (value["outcome"] != "offered"
                or status is not None or consumed or value["replyEof"])
            or value["state"] == "terminal" and value["outcome"] == "offered"
            or value["replyEof"] != (value["outcome"] == "reply_eof_unverified")
            or value["replyEof"] and (status != 200 or consumed > bound)
            or value["outcome"] in {"stream_error", "signature_header_error", "reply_overflow"} and status != 200
            or value["outcome"] == "signature_header_error" and consumed
            or value["outcome"] == "status_rejected" and (status is None or status == 200 or consumed)
            or value["outcome"] == "transport_error" and status is not None):
        raise ValueError("Direct control stream facts conflict")
    return value


def direct_control_records(source, process, provenance, message_reader):
    """Reuse the pinned process/log reader; refuse duplicate or oversized events."""
    result = {"directOffered": [], "directTerminal": []}
    constructor = None
    prefix = "[INFO] message=direct_control_sender_observed "
    for message, journal_at in message_reader(source, process, provenance):
        if not isinstance(message, str) or not message.startswith(prefix):
            continue
        encoded = message[len(prefix):]
        if len(encoded.encode()) > 8192:
            raise ValueError("Direct control event exceeds its retained bound")
        _, end = json.JSONDecoder().raw_decode(encoded)
        if len(encoded[:end].encode()) > 4096 or encoded[end:] and not encoded[end:].startswith(" span="):
            raise ValueError("Direct control event framing differs")
        if constructor is None:
            constructor = direct_constructor_sha256()
        value = validate_direct_control_event(READERS["closed_json"](encoded[:end]), constructor)
        kind = "directOffered" if value["state"] == "offered" else "directTerminal"
        result[kind].append({"value": value, "journalAtUnixMicros": journal_at,
                             "receiptSha256": sha(encoded[:end].encode())})
        if sum(len(rows) for rows in result.values()) > MAX_RECORDS:
            raise ValueError("Direct control event inventory exceeds its bound")
    for rows in result.values():
        unique(rows, lambda item: item["value"]["transportCallId"])
    return result


def direct_control_receiver_pair(call, captures, offered, terminal, codec):
    """Join control byte images; retain missing authentication and SQL custody."""
    result = {"transportCallId": call, "requestImage": None, "nativeReplyConsumedBytes": None,
              "fullReplyConsumed": False, "typedPayload": None, "replyMacAuthentication": None,
              "finalSqlContext": None, "workerHandlerCompletion": None, "missing": []}
    if set(captures) != {"received_request", "exposed_response"}:
        result["missing"].append("missing_directional_receiver_image")
        return result
    if len(offered) != 1 or len(terminal) != 1 or codec is None:
        result["missing"].append("missing_or_duplicate_control_sender_or_actual_codec")
        return result
    try:
        first, last = offered[0], terminal[0]
        constructor = direct_constructor_sha256()
        validate_direct_control_event(first, constructor)
        validate_direct_control_event(last, constructor)
        stable = DIRECT_CONTROL_FIELDS - {"state", "replyStatus", "exposedReplySha256",
                    "exposedReplyBytes", "replyEof", "outcome", "observedAtUnixMicros"}
        if (first["state"] != "offered" or last["state"] != "terminal"
                or first["transportCallId"] != call
                or any(first[name] != last[name] for name in stable)
                or first["observedAtUnixMicros"] is None or last["observedAtUnixMicros"] is None
                or decimal(first["observedAtUnixMicros"]) > decimal(last["observedAtUnixMicros"])):
            raise ValueError("Direct control sender lifetime differs")
        route = first["route"]
        bound, operation = DIRECT_CONTROL_ROUTES[route]
        bodies = []
        for direction in ("received_request", "exposed_response"):
            receipt = captures[direction]
            if (receipt["role"] != "storage_wrapper" or receipt["method"] != "POST"
                    or receipt["pathSha256"] != sha(route.encode())
                    or receipt["transportCallId"] != call or receipt["queryClass"] != "absent"
                    or receipt["state"] != "eof" or receipt["eof"] is not True
                    or receipt["capturePersistence"] != "written"
                    or receipt["responseConsumptionClaim"] is not False):
                raise ValueError("Direct control receiver is incomplete")
            images = [image for image in receipt["privateImages"] if image["name"] == "body"]
            if len(images) != 1:
                raise ValueError("Direct control body ownership differs")
            image = images[0]
            raw = read(image["reference"], bound)
            if (image["sha256"] != sha(raw) or image["bytes"] != str(len(raw))
                    or receipt["observedBytes"] != str(len(raw)) or receipt["retainedBytes"] != str(len(raw))):
                raise ValueError("Direct control receiver bytes differ")
            bodies.append(raw)
        request, reply = captures["received_request"], captures["exposed_response"]
        original, exposed = bodies
        if (request["provenance"] != "independent_wrapper_received_bytes"
                or request["imageKind"] != "complete_received_image"
                or reply["provenance"] != "wrapper_exposed_reply_bytes"
                or reply["imageKind"] != "complete_wrapper_reply_image"
                or first["offeredRequestSha256"] != sha(original)
                or decimal(first["offeredRequestBytes"], bound) != len(original)
                or last["replyStatus"] != reply["status"]):
            raise ValueError("Direct control original differs")
        consumed = decimal(last["exposedReplyBytes"], bound)
        if (consumed > len(exposed) or sha(exposed[:consumed]) != last["exposedReplySha256"]
                or last["replyEof"] and consumed != len(exposed)):
            raise ValueError("Direct control consumed prefix differs")
        control = codec["control"]
        closed(control, {"operation", "selectedSourceDigest", "originalRequestSha256",
                         "originalRequestSemanticSha256", "deploymentIdSha256", "challengeNonceSha256",
                         "originalContextSha256", "returnedProtectedMaterialBytes", "correlationValidatorSourceSha256"})
        if (codec["class"] != "storage_control_metadata" or codec["request"]["sha256"] != sha(original)
                or codec["response"]["sha256"] != sha(exposed)
                or control["operation"] != (operation if last["replyStatus"] == 200 else "storage_control_refused")
                or control["originalRequestSha256"] != sha(original)
                or control["challengeNonceSha256"] != first["nonceSha256"]
                or control["selectedSourceDigest"] != RUNTIME["workerSourceDigest"]
                or control["returnedProtectedMaterialBytes"] != "0"):
            raise ValueError("Direct control actual codec differs")
        result.update(requestImage="matched_selected_control_receiver_byte_image",
                      nativeReplyConsumedBytes=str(consumed), fullReplyConsumed=last["replyEof"], typedPayload=control)
        if not last["replyEof"]:
            result["missing"].append("control_reply_not_fully_consumed")
    except (ValueError, KeyError, TypeError, OSError):
        result["missing"].append("control_receiver_native_codec_join_mismatch")
    # This slice has no independently selected Worker completion/header input.
    # A decoded byte image and EOF never imply the later Native reply verifier.
    result["missing"].extend(("independent_worker_authenticated_completion_receipt_required",
        "independent_protected_header_authentication_required",
        "independent_current_receiver_deployment_and_window_proof_required",
        "independent_current_original_policy_sql_and_provider_mapping_required"))
    return result


def execute_records(sidecar):
    """Reuse the real Native process/log parser on the same held, pinned inode."""
    # ingress_events checks the process epoch/source and the plain-log custody.
    _, log_missing = READERS["ingress_events"](sidecar)
    log = sidecar["nativeLog"]
    if log_missing or log is None or sidecar["nativeProcess"] is None:
        return {"attempts": [], "finalContexts": [], "directOffered": [], "directTerminal": []}
    parser = runpy.run_path(str(SOURCE / "tests/fleet/_hub-storage-work-execute-observation.py"))
    function = parser["storage_work_execute_receipts"]
    if log["format"] == "journal":
        source_reader = runpy.run_path(str(SOURCE / "tests/fleet/_hub-storage-capture.py"))["observed_native_messages"]
        source_reader.__globals__["_closed_review_json"] = READERS["closed_json"]
        function.__globals__.update(observed_native_messages=source_reader,
                                   _closed_review_json=READERS["closed_json"])
        raw = read(log["reference"], 256 * MAX_JSON).decode()
        records = function(raw, sidecar["nativeProcess"])
        records.update(direct_control_records(raw, sidecar["nativeProcess"], None, source_reader))
        return bracket_records(records, log["epoch"])
    if log["format"] != "plain" or log["provenance"] is None:
        raise ValueError("Execute log provenance differs")
    reference = log["reference"]
    descriptor = os.open(reference["file"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as held:
        before = os.fstat(held.fileno())
        raw = held.read(256 * MAX_JSON + 1)
        if (str(len(raw)) != reference["byteSize"] or sha(raw) != reference["sha256"]
                or log["provenance"]["window"]["sha256"] != reference["sha256"]):
            raise ValueError("Execute log window differs")
        source_reader = READERS["source_readers"]((held.fileno(), reference["file"]))
        function.__globals__.update(
            observed_native_messages=source_reader.__globals__["observed_native_messages"],
            _closed_review_json=READERS["closed_json"])
        records = function(Path(reference["file"]), sidecar["nativeProcess"], log["provenance"])
        records.update(direct_control_records(Path(reference["file"]), sidecar["nativeProcess"],
                       log["provenance"], source_reader.__globals__["observed_native_messages"]))
        after = os.fstat(held.fileno())
        if any(getattr(before, name) != getattr(after, name) for name in
               ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
            raise ValueError("Execute log changed")
    return bracket_records(records, log["epoch"])


def bracket_records(records, epoch):
    """Require event clocks to remain within the selected Native lifetime."""
    for kind in ("attempts", "finalContexts", "directOffered", "directTerminal"):
        for item in records.get(kind, []):
            value = item["value"]
            time = value.get("observedAtUnixMicros", value.get("completedAtUnixMicros"))
            if time is None or not decimal(epoch["firstUnixMicros"]) <= decimal(time) <= decimal(epoch["lastUnixMicros"]):
                raise ValueError("Execute event lacks current process clock bracket")
            journal_at = item.get("journalAtUnixMicros")
            if kind in {"directOffered", "directTerminal"} and journal_at is not None:
                if not decimal(epoch["firstUnixMicros"]) <= decimal(journal_at) <= decimal(epoch["lastUnixMicros"]):
                    raise ValueError("Direct control journal event lies outside its process epoch")
    return records


def receiver_pair(call, captures, attempt, final_context, codec):
    """Partition an independent received image using Native offered/consumed facts."""
    result = {"transportCallId": call, "requestImage": None,
              "nativeReplyConsumedBytes": None, "fullReplyConsumed": False,
              "typedPayload": None, "finalSqlContext": None, "missing": []}
    if set(captures) != {"received_request", "exposed_response"}:
        result["missing"].append("missing_directional_receiver_image")
        return result
    request, reply = (captures[name] for name in ("received_request", "exposed_response"))
    if attempt is None or codec is None:
        result["missing"].append("missing_native_attempt_or_actual_codec")
        return result
    validator = runpy.run_path(str(SOURCE / "tests/fleet/_hub-storage-work-execute-observation.py"))
    validator["validate_storage_work_attempt"](attempt)
    try:
        bodies = []
        for receipt in (request, reply):
            if (receipt["role"] != "storage_wrapper" or receipt["method"] != "POST"
                    or receipt["pathSha256"] != sha(b"/_internal/storage/v1/execute")
                    or receipt["transportCallId"] != call or receipt["queryClass"] != "absent"
                    or receipt["state"] != "eof" or receipt["eof"] is not True
                    or receipt["capturePersistence"] != "written"
                    or receipt["responseConsumptionClaim"] is not False):
                raise ValueError("Receiver is incomplete")
            images = [image for image in receipt["privateImages"] if image["name"] == "body"]
            if len(images) != 1:
                raise ValueError("Receiver body ownership differs")
            image = images[0]
            raw = read(image["reference"], MAX_BODY)
            if (sha(raw) != image["sha256"] or str(len(raw)) != image["bytes"]
                    or str(len(raw)) != receipt["observedBytes"]
                    or str(len(raw)) != receipt["retainedBytes"]):
                raise ValueError("Receiver body differs")
            bodies.append(raw)
        offered, exposed = bodies
        if (request["provenance"] != "independent_wrapper_received_bytes"
                or request["imageKind"] != "complete_received_image"
                or reply["provenance"] != "wrapper_exposed_reply_bytes"
                or reply["imageKind"] != "complete_wrapper_reply_image"
                or attempt["offeredRequestSha256"] != sha(offered)
                or decimal(attempt["offeredRequestBytes"]) != len(offered)
                or attempt["replyStatus"] != reply["status"]):
            raise ValueError("Native offered request differs")
        consumed = decimal(attempt["exposedReplyBytes"], MAX_BODY)
        if (consumed > len(exposed) or sha(exposed[:consumed]) != attempt["exposedReplySha256"]
                or attempt["replyEof"] and consumed != len(exposed)):
            raise ValueError("Native consumed prefix differs")
        if (codec["request"]["sha256"] != sha(offered)
                or codec["response"]["sha256"] != sha(exposed)
                or codec.get("storageWork") is None
                or codec["storageWork"]["operation"] != attempt["operation"]
                or codec["storageWork"]["planIdSha256"] != sha(attempt["planId"].encode())
                or codec["storageWork"]["selectedSourceDigest"] != RUNTIME["workerSourceDigest"]):
            raise ValueError("Typed codec selection differs")
        result.update(requestImage="matched_selected_receiver_byte_image",
                      nativeReplyConsumedBytes=str(consumed),
                      fullReplyConsumed=attempt["replyEof"] and consumed == len(exposed),
                      typedPayload=codec["storageWork"])
        if final_context is not None:
            stable = validator["EXECUTE_ATTEMPT_FIELDS"] - {"elapsedMicros", "observedAtUnixMicros"}
            if any(final_context["attempt"][field] != attempt[field] for field in stable):
                raise ValueError("Final SQL belongs to another attempt")
            result["finalSqlContext"] = final_context["commitments"]
        else:
            result["missing"].append("missing_final_current_sql_context")
        if attempt["outcome"] != "typed_result_checked" or not result["fullReplyConsumed"]:
            result["missing"].append("reply_not_fully_checked")
        # A decoded plan and observed final SQL are distinct from independently
        # selected current actor/purpose/profile/original admission projections.
        result["missing"].append("independent_current_original_policy_and_provider_mapping_required")
        result["missing"].append("independent_protected_header_authentication_required")
        result["missing"].append("independent_current_receiver_deployment_and_window_proof_required")
    except (ValueError, KeyError, TypeError):
        result["missing"].append("receiver_native_codec_join_mismatch")
    return result


def capture_policy(reference):
    """Bind actual exported receipts to the selected private capture policy."""
    value = parsed(reference)
    closed(value, {"version", "corpusId", "windowId", "sourceCommit", "sourceTree", "runtimeSourceDigest",
                   "nativeExecutableSha256", "workerSourceDigest", "captureImplementationSha256",
                   "startsAt", "expiresAt", "capturePrefix", "storageOrigin", "originProxyOrigin",
                   "originRoutes", "maximumBodyBytes", "maximumCorpusBytes"})
    if (value["version"] != 1 or value["captureImplementationSha256"] != CAPTURE_IMPLEMENTATION_SHA
            or value["maximumBodyBytes"] != MAX_BODY or value["maximumCorpusBytes"] != MAX_CORPUS
            or value["sourceCommit"] != SOURCE_COMMIT or value["sourceTree"] != SOURCE_TREE
            or value["workerSourceDigest"] != RUNTIME["workerSourceDigest"]
            or value["runtimeSourceDigest"] != RUNTIME["workerSourceDigest"]
            or value["nativeExecutableSha256"] != RUNTIME["nativeExecutableSha256"]):
        raise ValueError("Selected capture implementation/runtime differs")
    for name in ("corpusId", "windowId"):
        if not isinstance(value[name], str) or not re.fullmatch(r"[0-9a-f]{32}", value[name]):
            raise ValueError("Capture window identity differs")
    if value["capturePrefix"] != "private-capture/" + value["corpusId"] + "/":
        raise ValueError("Capture corpus prefix differs")
    if (type(value["startsAt"]) is not int or type(value["expiresAt"]) is not int
            or not 0 <= value["startsAt"] < value["expiresAt"] <= value["startsAt"] + 3600):
        raise ValueError("Capture original cutoff differs")
    return value


def exported_receipt(item, policy):
    """Reopen raw producer records and their separately exported private images."""
    closed(item, {"receipt", "images"})
    receipt = parsed(item["receipt"])
    closed(receipt, CAPTURE_BASE_FIELDS | CAPTURE_DIRECTION_FIELDS)
    for name in ("corpusId", "windowId", "sourceCommit", "sourceTree", "runtimeSourceDigest",
                 "nativeExecutableSha256", "workerSourceDigest", "captureImplementationSha256"):
        if receipt[name] != policy[name]:
            raise ValueError("Individual receiver policy differs")
    if (receipt["version"] != 1 or receipt["qualificationClaim"] is not False
            or receipt["instrumentationTraffic"] is not True
            or receipt["responseConsumptionClaim"] is not False
            or receipt["role"] not in {"origin_proxy", "storage_wrapper"}
            or receipt["direction"] not in {"received_request", "exposed_response"}
            or receipt["state"] not in {"eof", "cancelled", "overflow", "unknown"}
            or receipt["frameState"] not in {"bounded", "overflow", "unknown"}
            or receipt["capturePersistence"] not in {"written", "unknown", "overflow"}
            or type(receipt["eof"]) is not bool
            or not isinstance(receipt["captureId"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", receipt["captureId"])):
        raise ValueError("Producer observation contract differs")
    for name in ("transportCallId", "requestId"):
        if receipt[name] is not None and (not isinstance(receipt[name], str)
                or not re.fullmatch(r"[0-9a-f]{32}", receipt[name])):
            raise ValueError("Actual capture correlation differs")
    decimal(receipt["observedBytes"])
    decimal(receipt["retainedBytes"], MAX_BODY)
    if decimal(receipt["finishedAtMillis"]) < decimal(receipt["startedAtMillis"]):
        raise ValueError("Capture observation clocks reversed")
    image_refs = unique(item["images"], lambda row: row["key"])
    images = unique(receipt["privateImages"], lambda row: row["key"])
    if set(image_refs) != set(images) or len(images) > 4:
        raise ValueError("Exported private image inventory differs")
    corpus = 0
    for image in images.values():
        closed(image, {"name", "key", "bytes", "sha256"})
        allowed = {"body", "x-aos-storage-work-signature"} if receipt["role"] == "storage_wrapper" else {
            "body", "x-aos-hybrid-ingress", "x-aos-direct-upload-logical-signature", "x-aos-hybrid-upload-phase"}
        prefix = policy["capturePrefix"] + receipt["captureId"] + "/" + receipt["direction"] + "-"
        if image["name"] not in allowed or image["key"] != prefix + image["name"] + ".bin":
            raise ValueError("Export image belongs to another call or protocol")
        mapped = image_refs[image["key"]]
        closed(mapped, {"key", "reference"})
        maximum = MAX_BODY if image["name"] == "body" else 16384 if image["name"] == "x-aos-hybrid-ingress" else 128
        raw = read(mapped["reference"], maximum)
        if sha(raw) != image["sha256"] or str(len(raw)) != image["bytes"]:
            raise ValueError("Exported image commitment differs")
        image["reference"] = mapped["reference"]
        corpus += len(raw)
    return receipt, corpus


def application_records(reference, marker, expected_fields):
    """Read actual closed producer records, preserving missing terminal events."""
    raw = read(reference, 256 * MAX_JSON)
    rows = []
    for line in raw.decode("utf-8").splitlines():
        if marker not in line:
            continue
        encoded = line.split(marker, 1)[1]
        value, end = json.JSONDecoder().raw_decode(encoded)
        if encoded[end:] and not encoded[end:].startswith(" span="):
            raise ValueError("Application observation suffix differs")
        value = READERS["closed_json"](encoded[:end])
        closed(value, expected_fields)
        if len(encoded[:end].encode()) > 4096 or value["version"] != 1:
            raise ValueError("Application record bound differs")
        digest(value["observerSourceSha256"])
        if type(value["attemptOrdinal"]) is not int or value["attemptOrdinal"] < 0:
            raise ValueError("Application attempt differs")
        rows.append(value)
        if len(rows) > MAX_RECORDS:
            raise ValueError("Application inventory exceeds bound")
    return rows


CLIENT_FIELDS = {"version", "purpose", "observerSourceSha256", "processId", "attemptOrdinal",
                 "startedAtMillis", "completedAtMillis", "sessionSha256", "originalSha256",
                 "clientOperationSha256", "placementSha256", "partSha256", "providerOriginSha256",
                 "providerPathSha256", "offered", "reply", "status", "etagSha256", "outcome"}
SDK_FIELDS = {"version", "purpose", "observerSourceSha256", "sourceDigest", "isolateSha256",
              "attemptOrdinal", "atMillis", "operation", "keySha256", "original", "outcome"}


def client_summary(rows):
    """Count unique acknowledged offered prefixes without claiming delivered bytes."""
    attempts = {}
    accepted = {}
    offered_attempt_bytes = 0
    unresolved = []
    for row in rows:
        if row["purpose"] != "upload_part" or row["outcome"] not in {"pending", "accepted", "refused", "unknown"}:
            raise ValueError("Client application purpose differs")
        identity = (row["processId"], row["attemptOrdinal"])
        if type(row["processId"]) is not int or not 0 < row["processId"] <= 2**32 - 1:
            raise ValueError("Client process identity differs")
        for name in ("sessionSha256", "originalSha256", "clientOperationSha256",
                     "providerOriginSha256", "providerPathSha256"):
            digest(row[name])
        for name in ("placementSha256", "partSha256", "etagSha256"):
            if row[name] is not None:
                digest(row[name])
        previous = attempts.get(identity)
        if previous is not None and (previous["outcome"] != "pending" or row["outcome"] == "pending"):
            raise ValueError("Duplicate client terminal")
        if previous is not None and any(previous[name] != row[name] for name in
                (CLIENT_FIELDS - {"completedAtMillis", "offered", "reply", "status", "etagSha256", "outcome"})):
            raise ValueError("Client terminal belongs to another original")
        attempts[identity] = row
    for identity, row in attempts.items():
        prefix = row["offered"]
        if prefix is not None:
            closed(prefix, {"bytes", "sha256", "eof", "failed", "overflow"})
            if type(prefix["bytes"]) is not int or not 0 <= prefix["bytes"] <= 2**64 - 1:
                raise ValueError("Client prefix count differs")
            digest(prefix["sha256"])
            if any(type(prefix[name]) is not bool for name in ("eof", "failed", "overflow")):
                raise ValueError("Client prefix state differs")
            offered_attempt_bytes += prefix["bytes"]
        reply = row["reply"]
        if reply is not None:
            closed(reply, {"bytes", "sha256", "eof", "failed", "overflow"})
            digest(reply["sha256"])
            if (type(reply["bytes"]) is not int or not 0 <= reply["bytes"] <= 8192
                    or any(type(reply[name]) is not bool for name in ("eof", "failed", "overflow"))):
                raise ValueError("Client consumed reply differs")
        if (row["outcome"] != "accepted" or prefix is None or not prefix["eof"]
                or prefix["failed"] or prefix["overflow"] or row["etagSha256"] is None
                or row["placementSha256"] is None or row["partSha256"] is None
                or reply is None or not reply["eof"] or reply["failed"] or reply["overflow"]
                or row["status"] != 200):
            unresolved.append(list(identity))
            continue
        key = tuple(digest(row[name]) for name in ("sessionSha256", "originalSha256",
                    "clientOperationSha256", "placementSha256", "partSha256"))
        facts = (prefix["bytes"], prefix["sha256"])
        if key in accepted and accepted[key] != facts:
            raise ValueError("Same original part offered different bytes")
        accepted[key] = facts
    return {"attempts": len(attempts), "uniqueAcceptedPartCommitments": len(accepted),
            "uniqueAcknowledgedOfferedBytes": str(sum(item[0] for item in accepted.values())),
            "allAttemptOfferedBytes": str(offered_attempt_bytes), "unresolvedAttempts": unresolved,
            "providerConsumedBytes": None, "wireBytes": None, "settlement": "not_observed",
            "mapping": "independent_authenticated_original_geometry_and_binding_required"}


def sdk_summary(rows, worker_digest):
    grouped = {}
    for row in rows:
        if (row["purpose"] != "direct_upload_sdk"
                or row["sourceDigest"] != worker_digest
                or row["operation"] not in {"create_multipart", "empty_put", "complete", "abort", "get", "head", "delete", "upload_part"}
                or row["outcome"] not in {"dispatch_attempt", "sdk_returned", "unknown"}):
            raise ValueError("SDK source or purpose differs")
        identity = (digest(row["isolateSha256"]), row["attemptOrdinal"])
        digest(row["keySha256"])
        original = row["original"]
        if original is not None:
            closed(original, {"session", "clientOperationDigest", "placementDigest", "operationDigest",
                              "completeOperationDigest", "dependencyPhase", "byteSize"})
            closed(original["session"], {"sessionDigest", "originalDigest"})
            for name in ("sessionDigest", "originalDigest"):
                digest(original["session"][name])
            for name in ("clientOperationDigest", "placementDigest"):
                digest(original[name])
            for name in ("operationDigest", "completeOperationDigest"):
                if original[name] is not None:
                    digest(original[name])
            decimal(original["byteSize"])
            if original["dependencyPhase"] not in {"content", "leaf_metadata", "visibility"}:
                raise ValueError("SDK dependency phase differs")
        grouped.setdefault(identity, []).append(row)
    missing = 0
    for records in grouped.values():
        if len(records) > 2 or records[0]["outcome"] != "dispatch_attempt":
            raise ValueError("SDK lifecycle ownership differs")
        if len(records) == 2 and (records[1]["outcome"] == "dispatch_attempt"
                or any(records[0][key] != records[1][key] for key in
                       ("operation", "keySha256", "original", "observerSourceSha256"))):
            raise ValueError("SDK terminal belongs to another dispatch")
        missing += len(records) != 2 or records[-1]["outcome"] != "sdk_returned" or records[0]["original"] is None
    return {"dispatches": len(grouped), "unresolvedDispatches": missing,
            "httpRequests": None, "bodyBytes": None, "settlement": "not_observed"}


def index_parity(selected):
    """Replay exact retained SQL query transcripts through unchanged projections."""
    if selected is None:
        return {"state": "incomplete", "missing": ["independent_three_mode_sql_transcripts"]}
    closed(selected, {"registrySlug", "signedSourceCommit", "modes"})
    closed(selected["modes"], {"hybrid", "native_only", "worker_only"})
    projection = runpy.run_path(str(SOURCE / "tests/fleet/_hub-index-parity.py"))
    parity = runpy.run_path(str(SOURCE / "tests/fleet/_hub-direct-index-parity.py"))
    projection["registry_index_observations"].__globals__["sql_literal"] = lambda value: "'" + value.replace("'", "''") + "'"
    parity["assert_direct_registry_index_parity"].__globals__.update(
        registry_index_observations=projection["registry_index_observations"],
        retain_direct_flow=lambda *_: None)
    readers, identities, references = {}, set(), set()
    for mode, reference in selected["modes"].items():
        transcript = parsed(reference, 16 * MAX_JSON)
        closed(transcript, {"version", "mode", "databaseIdentitySha256", "readerProcessReference", "queries"})
        if transcript["version"] != 1 or transcript["mode"] != mode:
            raise ValueError("SQL reader mode differs")
        identity = digest(transcript["databaseIdentitySha256"])
        info = os.stat(reference["file"], follow_symlinks=False)
        file_identity = (info.st_dev, info.st_ino)
        if identity in identities or file_identity in references:
            raise ValueError("Three modes reuse one database or transcript")
        identities.add(identity)
        references.add(file_identity)
        # This reference selects reader custody; it is not a verifier of that
        # process's SQL authority. The resulting state preserves that limit.
        read(transcript["readerProcessReference"])
        queries = unique(transcript["queries"], lambda item: item["statementSha256"])

        def query(statement, records=queries):
            key = sha(statement.encode())
            if key not in records:
                raise ValueError("Required actual SQL statement is absent")
            row = records[key]
            closed(row, {"statementSha256", "rows"})
            return row["rows"]

        readers[mode] = query
    result = parity["assert_direct_registry_index_parity"](
        readers, selected["registrySlug"], source_commit=selected["signedSourceCommit"])
    return {"state": "retained_contents_match", "comparison": result,
            "readerAuthority": "independent_current_reader_process_and_source_review_required"}


def inbound_inventory(selection, manifest, codec_report=None):
    """Invoke the selected reader without changing the original body manifest."""
    if selection.get('nativeInventory') is None:
        return None
    path = Path(__file__).resolve(strict=True).parent / 'native_inventory.py'
    raw = PACKAGE_READER['installed_bytes'](path, MAX_JSON)
    namespace = {'__file__': str(path), '__name__': 'selected_inventory_reader'}
    exec(compile(raw, str(path), 'exec'), namespace)
    return namespace['assess'](
        selection['nativeInventory'], SOURCE, READERS,
        PACKAGE_READER['installed_bytes'], manifest, codec_report)


def assess(selection):
    expected = {"version", "runtime", "runtimeProvenance", "bodyManifest", "observerExecutable", "authSidecar",
                       "capturePolicy", "captureExport", "sdkApplicationLog", "clientApplicationLog", "indexSnapshots",
                       "workloadWindows", "wireMetrics"}
    if 'nativeInventory' in selection:
        expected.add('nativeInventory')
    closed(selection, expected)
    if selection["version"] != 1:
        raise ValueError("Assessment version differs")
    runtime = selection["runtime"]
    closed(runtime, {"runtimeCodecRevision", "workerSourceDigest", "sourceArchiveSha256", "nativeExecutableSha256"})
    if runtime != RUNTIME:
        raise ValueError("Selected installed runtime differs")
    provenance = parsed(selection["runtimeProvenance"])
    closed(provenance, {"version", "runtimeCodecRevision", "nativeExecutableSha256",
                        "workerSourceDigest", "sourceArchiveSha256", "browserSource"})
    if any(provenance[name] != value for name, value in runtime.items()):
        raise ValueError("Actual runtime provenance differs")
    if selection["observerExecutable"] != PACKAGE["observerExecutable"]:
        raise ValueError("Selected observer differs from installed code")
    windows = []
    for reference in selection["workloadWindows"]:
        raw = read(reference)
        windows.append({"sha256": sha(raw), "byteSize": str(len(raw))})
    manifest, report, codec_error = observe(selection, selection["bodyManifest"])
    body = {"state": "incomplete", "nativeBulkBytes": None,
            "nativeCapturedObjectPayloadBytes": None, "receiverJoins": [], "ingressAuthentication": None,
            "directControlUnmatchedOffers": [], "directControlUnmatchedTerminals": [],
            "missing": ["whole_native_original_inventory_and_current_policy_mapping",
                        "unselected_GET_identity_session_and_other_routes",
                        "independent_authenticated_control_and_provider_integrity_joins"]}
    if codec_error:
        body["missing"].append(codec_error)
    sidecar = parsed(selection["authSidecar"]) if selection["authSidecar"] else None
    records = {"attempts": [], "finalContexts": [], "directOffered": [], "directTerminal": []}
    if sidecar:
        body["ingressAuthentication"] = READERS["assess"](sidecar, manifest)
        records = execute_records(sidecar)
    else:
        body["missing"].append("selected_current_native_context_log_and_process")
    if selection["captureExport"] and report:
        if selection["capturePolicy"] is None:
            raise ValueError("Receiver export lacks selected capture policy")
        policy = capture_policy(selection["capturePolicy"])
        export = parsed(selection["captureExport"], 16 * MAX_JSON)
        closed(export, {"version", "runtime", "windows", "receipts"})
        if export["version"] != 1 or export["runtime"] != runtime:
            raise ValueError("Receiver export runtime differs")
        corpus = 0
        for window in export["windows"]:
            summary = parsed(window)
            if (summary["captureCompleteness"] != "unknown"
                    or summary["qualificationClaim"] is not False
                    or any(summary[name] != policy[name] for name in
                           ("corpusId", "windowId", "sourceCommit", "sourceTree"))):
                raise ValueError("Capture export invents producer completeness")
        grouped = {}
        receipt_ids = set()
        for item in export["receipts"]:
            receipt, retained = exported_receipt(item, policy)
            identity = (receipt["captureId"], receipt["direction"])
            if identity in receipt_ids:
                raise ValueError("Duplicate captured body inventory")
            receipt_ids.add(identity)
            corpus += retained
            if corpus > MAX_CORPUS:
                raise ValueError("Exported image corpus exceeds bound")
            if receipt["role"] != "storage_wrapper":
                continue
            call = receipt["transportCallId"]
            if call is None:
                body["missing"].append("receiver_missing_actual_transport_call_id")
                continue
            directions = grouped.setdefault(call, {})
            if receipt["direction"] in directions:
                raise ValueError("Duplicate receiver direction")
            directions[receipt["direction"]] = receipt
        attempts = unique([row["value"] for row in records["attempts"]], lambda row: row["transportCallId"])
        contexts = unique([row["value"] for row in records["finalContexts"]], lambda row: row["attempt"]["transportCallId"])
        controls = unique([row["value"] for row in records["directOffered"]], lambda row: row["transportCallId"])
        terminals = unique([row["value"] for row in records["directTerminal"]], lambda row: row["transportCallId"])
        if set(controls) & set(attempts):
            raise ValueError("Control and execute calls reuse an identity")
        codecs = unique(report["captures"], lambda row: row["requestIdSha256"])
        for call, receipts in grouped.items():
            ids = {item["requestId"] for item in receipts.values()}
            codec = codecs.get(sha(next(iter(ids)).encode())) if len(ids) == 1 and None not in ids else None
            if call in controls or codec is not None and codec.get("control") is not None:
                joined = direct_control_receiver_pair(call, receipts,
                    [controls[call]] if call in controls else [],
                    [terminals[call]] if call in terminals else [], codec)
            else:
                joined = receiver_pair(call, receipts, attempts.get(call), contexts.get(call), codec)
            body["receiverJoins"].append(joined)
        body["missing"].append("capture_producer_completeness_unknown")
    control_calls = {row["transportCallId"] for row in body["receiverJoins"]}
    body["directControlUnmatchedOffers"] = [
        {"transportCallId": row["value"]["transportCallId"], "route": row["value"]["route"],
         "offeredRequestBytes": row["value"]["offeredRequestBytes"], "delivery": "unknown",
         "missing": ["independent_directional_receiver_and_call_id_retention_required"]}
        for row in records["directOffered"] if row["value"]["transportCallId"] not in control_calls]
    offered_calls = {row["value"]["transportCallId"] for row in records["directOffered"]}
    body["directControlUnmatchedTerminals"] = [
        {"transportCallId": row["value"]["transportCallId"], "outcome": row["value"]["outcome"],
         "nativeReplyExposedBytes": row["value"]["exposedReplyBytes"],
         "missing": ["exclusive_current_offered_event_required"]}
        for row in records["directTerminal"] if row["value"]["transportCallId"] not in offered_calls]
    provider = {"state": "incomplete", "sdk": None, "client": None,
                "httpProviderRows": None, "billedWireBytes": None,
                "missing": ["source_process_window_and_authenticated_original_binding_mapping"]}
    for slot, kind, marker, fields in (
            ("clientApplicationLog", "client", "direct_upload_part_application_observation ", CLIENT_FIELDS),
            ("sdkApplicationLog", "sdk", "direct_sdk_application_observation ", SDK_FIELDS)):
        if selection[slot]:
            selected = selection[slot]
            closed(selected, {"log", "processWindow", "producerSourceSha256"})
            read(selected["processWindow"])
            expected = PRODUCER_SHA[kind]
            if expected is None:
                raise ValueError("Application producer is unavailable in selected runtime")
            if selected["producerSourceSha256"] != expected:
                raise ValueError("Application producer source differs")
            rows = application_records(selected["log"], marker, fields)
            if any(row["observerSourceSha256"] != expected for row in rows):
                raise ValueError("Application record source differs")
            provider[kind] = client_summary(rows) if kind == "client" else sdk_summary(rows, runtime["workerSourceDigest"])
    if selection["wireMetrics"] is not None:
        read(selection["wireMetrics"])
    selected_inventory = inbound_inventory(
        selection, manifest, report if codec_error is None else None)
    if selected_inventory is not None:
        body['nativeInboundInventory'] = selected_inventory
        body['missing'].extend(body['nativeInboundInventory']['missing'])
        # Router inventory does not cover Native outbound metadata or close
        # independent original/auth/SQL projections for dynamic bodies.
        body['missing'].append('independent_outbound_and_dynamic_member_projections')
    return {"version": 1, "hostedAcceptance": "incomplete", "applicationBodyAssessment": body,
            "applicationProviderLedger": provider, "indexParity": index_parity(selection["indexSnapshots"]),
            "wireMetrics": {"reference": selection["wireMetrics"], "assessment": "separate_unverified_aggregate"},
            "loadedWindowReferences": windows, "runtime": runtime}


RUNTIME = PACKAGE["runtime"]
SOURCE_COMMIT = RUNTIME["runtimeCodecRevision"]
SOURCE_TREE = PACKAGE["sourceTree"]
PRODUCER_SHA = PACKAGE["producerSha256"]
READERS = private_reader()


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("Expected one private selection")
        selection = READERS["closed_json"](READERS["private_bytes"](sys.argv[1], MAX_JSON))
        result = assess(selection)
        print(json.dumps(result, separators=(",", ":")))
        raise SystemExit(2)  # The selected producers do not establish whole-window coverage.
    except Exception as error:
        print("Private hosted assessment refused: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
