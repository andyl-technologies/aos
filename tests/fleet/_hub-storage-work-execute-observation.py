"""Join actual ordinary Native reply prefixes to independently captured bodies.

Existing process/window custody and selected compiled codecs remain mandatory.
A checked typed result is distinct from final current-state context; neither
this parser nor payload partition grants current authority or provider proof.
"""

import hashlib
import json
import re


EXECUTE_ROUTE = "/_internal/storage/v1/execute"
EXECUTE_RECORD_LIMIT = 2 * (12_535 + 3) * 8 + 4096
EXECUTE_BODY_LIMIT = 8 * 1024 * 1024
EXECUTE_ATTEMPT_FIELDS = frozenset((
    "version", "invocationId", "transportCallId", "attempt", "planId", "operation",
    "endpointScheme", "offeredRequestSha256", "offeredRequestBytes", "replyStatus",
    "exposedReplySha256", "exposedReplyBytes", "replyEof", "unreadResponse", "outcome",
    "elapsedMicros", "observedAtUnixMicros", "replyMacAuthentication",
))
EXECUTE_OUTCOMES = frozenset((
    "transport_retry", "transport_failed", "http_status_retry", "response_too_large",
    "http_rejected", "response_read_failed", "malformed_result", "invalid_result",
    "expired_result", "typed_result_checked", "cancelled",
))
EXECUTE_CONTEXT_KEYS = frozenset(("placementStateSha256", "bindingStateSha256"))
EXECUTE_PAYLOAD_KEYS = frozenset(("requestRawObjectBytes", "replyRawObjectBytes",
                                "selectedDataBytes", "semanticOciProjectionBytes"))
EXECUTE_CODEC_FIELDS = frozenset(("requestId", "sourceDigest", "requestSha256", "replySha256",
    "codecSourceSha256", "exchangeIdSha256", "originalContextSha256", "operation", "class", "payload"))
EXECUTE_CLASSES = frozenset(("storage_work_gc_metadata", "storage_work_not_found_metadata",
                            "storage_work_typed_observation", "storage_work_refusal_metadata"))


def _execute_decimal(value, maximum=2**64 - 1):
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        raise ValueError("ordinary execute count is not canonical")
    count = int(value)
    if count > maximum:
        raise ValueError("ordinary execute count exceeds its observation bound")
    return count


def _execute_digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("ordinary execute digest differs")
    return value


def validate_storage_work_attempt(value):
    """Check actual event shape without promoting it to execution permission."""
    if (not isinstance(value, dict) or set(value) != EXECUTE_ATTEMPT_FIELDS
            or type(value["version"]) is not int or value["version"] != 1
            or type(value["attempt"]) is not int or not 1 <= value["attempt"] <= 3
            or value["outcome"] not in EXECUTE_OUTCOMES
            or value["endpointScheme"] not in {"http", "https"}
            or not isinstance(value["operation"], str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value["operation"])
            or value["replyMacAuthentication"] is not None):
        raise ValueError("ordinary execute attempt shape differs")
    for field in ("invocationId", "transportCallId", "planId"):
        if not isinstance(value[field], str) or not re.fullmatch(r"[0-9a-f]{32}", value[field]):
            raise ValueError("ordinary execute attempt identity differs")
    for field in ("offeredRequestSha256", "exposedReplySha256"):
        _execute_digest(value[field])
    _execute_decimal(value["offeredRequestBytes"], 1024 * 1024)
    consumed = _execute_decimal(value["exposedReplyBytes"], EXECUTE_BODY_LIMIT)
    _execute_decimal(value["elapsedMicros"])
    if value["observedAtUnixMicros"] is not None:
        _execute_decimal(value["observedAtUnixMicros"])
    if any(type(value[field]) is not bool for field in ("replyEof", "unreadResponse")):
        raise ValueError("ordinary execute stream markers differ")
    status = value["replyStatus"]
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        raise ValueError("ordinary execute actual HTTP status differs")
    if (value["unreadResponse"] and (status is None or consumed or value["replyEof"])
            or status is None and (consumed or value["replyEof"])
            or consumed == 0 and value["exposedReplySha256"] != hashlib.sha256(b"").hexdigest()
            or value["outcome"] == "typed_result_checked" and (status != 200 or not value["replyEof"])):
        raise ValueError("ordinary execute stream facts conflict")
    return value


def storage_work_execute_receipts(source, native_process, file_provenance=None):
    """Reuse the existing actual journal or pinned private plain-log reader."""
    records = {"version": 1, "attempts": [], "finalContexts": []}
    for message, journal_at in observed_native_messages(source, native_process, file_provenance):
        if not isinstance(message, str):
            continue
        selected = [(kind, "[INFO] message=" + marker + " ") for kind, marker in (
            ("attempts", "storage_work_attempt_observed"),
            ("finalContexts", "storage_work_final_sql_checked"))]
        matched = [(kind, prefix) for kind, prefix in selected if message.startswith(prefix)]
        if not matched:
            continue
        kind, prefix = matched[0]
        encoded = message[len(prefix):]
        if len(encoded.encode()) > 4096 + 4096:
            raise ValueError("ordinary execute retained event exceeds its bound")
        _, end = json.JSONDecoder().raw_decode(encoded)
        if encoded[end:] and not encoded[end:].startswith(" span="):
            raise ValueError("ordinary execute event suffix differs")
        value = _closed_review_json(encoded[:end])
        if kind == "attempts":
            validate_storage_work_attempt(value)
        else:
            if (not isinstance(value, dict) or set(value) != {"version", "attempt", "contextKind",
                    "commitments", "completedAtUnixMicros"} or value["version"] != 1
                    or type(value["version"]) is not int
                    or value["contextKind"] != "surface_fetch_current_sql"
                    or not isinstance(value["commitments"], dict)
                    or set(value["commitments"]) not in (EXECUTE_CONTEXT_KEYS,
                        EXECUTE_CONTEXT_KEYS | {"credentialSnapshotSha256"})):
                raise ValueError("ordinary execute final context differs")
            validate_storage_work_attempt(value["attempt"])
            if value["attempt"]["outcome"] != "typed_result_checked":
                raise ValueError("ordinary execute final context has no checked typed result")
            for digest in value["commitments"].values():
                _execute_digest(digest)
            if value["completedAtUnixMicros"] is not None:
                _execute_decimal(value["completedAtUnixMicros"])
        records[kind].append({"value": value, "journalAtUnixMicros": journal_at,
            "receiptSha256": hashlib.sha256(encoded[:end].encode()).hexdigest()})
        if sum(len(records[name]) for name in ("attempts", "finalContexts")) > EXECUTE_RECORD_LIMIT:
            raise ValueError("ordinary execute event corpus exceeds its bound")
    calls = [record["value"]["transportCallId"] for record in records["attempts"]]
    if len(calls) != len(set(calls)):
        raise ValueError("ordinary execute attempt IDs are reused")
    return records


def _execute_body(reference):
    """Reopen the independently captured private body with existing custody."""
    count = reference["byteSize"]
    if type(count) is int and 0 <= count <= EXECUTE_BODY_LIMIT:
        expected = count
    else:
        expected = _execute_decimal(count, EXECUTE_BODY_LIMIT)
    body = direct_selected_bytes({"path": reference["file"],
        "sha256": _execute_digest(reference["sha256"])}, EXECUTE_BODY_LIMIT)
    if len(body) != expected:
        raise ValueError("ordinary execute body count differs")
    return body


def _execute_unique(rows, key):
    if not isinstance(rows, list) or len(rows) > EXECUTE_RECORD_LIMIT:
        raise ValueError("ordinary execute selection exceeds its bound")
    selected = {}
    for row in rows:
        if row[key] in selected:
            raise ValueError("ordinary execute selection has duplicate ownership")
        selected[row[key]] = row
    return selected


def join_storage_work_execute(originals, received, original_headers, received_headers,
                              records, codec_rows, source_digest, codec_source_sha256):
    """Partition captured bytes per actual attempt; leave authority joins absent."""
    _execute_digest(source_digest)
    _execute_digest(codec_source_sha256)
    original_by_id = _execute_unique(originals, "requestId")
    received_by_id = _execute_unique(received, "requestId")
    codecs = _execute_unique(codec_rows, "requestId")
    attempts = _execute_unique([row["value"] for row in records["attempts"]], "transportCallId")
    contexts = {}
    for row in records["finalContexts"]:
        contexts.setdefault(row["value"]["attempt"]["transportCallId"], []).append(row)
    owners, received_owners = {}, {}
    for identity, header in original_headers.items():
        owners.setdefault(header["transportCallId"], []).append(identity)
    for header in received_headers.values():
        received_owners.setdefault(header["originalRequestId"], []).append(header)
    report = {"version": 1, "joined": [], "unresolvedNativeRequestIds": [],
        "unassignedAttemptCallIds": [], "unassignedFinalContextCallIds": [],
        "nativeBulkBytes": None,
        "scope": "actual ordinary offered and exposed body partition only; current auth/SQL/provider remain independent"}
    used, used_context = set(), set()
    for identity, original in original_by_id.items():
        if original["procedure"] != EXECUTE_ROUTE:
            continue
        try:
            first = original_headers.get(identity)
            candidates = received_owners.get(identity, [])
            if first is None or len(candidates) != 1:
                raise ValueError("ordinary execute dual header ownership differs")
            second = candidates[0]
            call = first["transportCallId"]
            actual = received_by_id.get(second["requestId"])
            record = attempts.get(call)
            codec = codecs.get(identity)
            if (call is None or owners.get(call) != [identity] or second["transportCallId"] != call
                    or actual is None or record is None or codec is None or call in used):
                raise ValueError("ordinary execute actual call ownership differs")
            validate_storage_work_attempt(record)
            if (original["method"] != "POST" or original["phase"]
                    or original["responseContentEncoding"] not in (None, "", "identity")
                    or any(original[field] != actual[field] for field in (
                        "procedure", "method", "phase", "status", "responseContentType", "responseContentEncoding"))):
                raise ValueError("ordinary execute transport selection differs")
            for header, body_row in ((first, original), (second, actual)):
                if any(header[field] != body_row[field] for field in ("method", "phase", "status")):
                    raise ValueError("ordinary execute header/body transport selection differs")
            for field in ("request_signature", "path_and_query"):
                before, after = first["files"].get(field), second["files"].get(field)
                if before is None or after is None or (before["sha256"], before["byteSize"]) != (
                        after["sha256"], after["byteSize"]):
                    raise ValueError("ordinary execute signed original header differs")
            if any(header["queryClass"] != "absent" for header in (first, second)):
                raise ValueError("ordinary execute unexpected query differs")
            target = first["files"]["path_and_query"]
            if (target["sha256"] != hashlib.sha256(EXECUTE_ROUTE.encode()).hexdigest()
                    or target["byteSize"] != len(EXECUTE_ROUTE.encode())):
                raise ValueError("ordinary execute retained target differs")
            before_request, after_request = (_execute_body(row["bodies"]["request"]) for row in (original, actual))
            before_reply, after_reply = (_execute_body(row["bodies"]["response"]) for row in (original, actual))
            if before_request != after_request or before_reply != after_reply:
                raise ValueError("ordinary execute independent body pair differs")
            if (record["offeredRequestSha256"] != hashlib.sha256(before_request).hexdigest()
                    or _execute_decimal(record["offeredRequestBytes"]) != len(before_request)
                    or record["replyStatus"] != original["status"]):
                raise ValueError("ordinary execute offered bytes or status differ")
            consumed = _execute_decimal(record["exposedReplyBytes"])
            if (consumed > len(before_reply)
                    or record["exposedReplySha256"] != hashlib.sha256(before_reply[:consumed]).hexdigest()
                    or record["replyEof"] and consumed != len(before_reply)):
                raise ValueError("ordinary execute actual consumed prefix differs")
            if (set(codec) != EXECUTE_CODEC_FIELDS or codec["sourceDigest"] != source_digest or codec["codecSourceSha256"] != codec_source_sha256
                    or codec["class"] not in EXECUTE_CLASSES or codec["operation"] != record["operation"]
                    or codec["requestSha256"] != record["offeredRequestSha256"]
                    or codec["replySha256"] != hashlib.sha256(before_reply).hexdigest()
                    or codec["exchangeIdSha256"] != hashlib.sha256(record["planId"].encode()).hexdigest()
                    or codec["originalContextSha256"] != record["offeredRequestSha256"]
                    or set(codec["payload"]) != EXECUTE_PAYLOAD_KEYS):
                raise ValueError("ordinary execute selected compiled body partition differs")
            payload = {key: _execute_decimal(value) for key, value in codec["payload"].items()}
            if (payload["requestRawObjectBytes"] > len(before_request)
                    or sum(value for key, value in payload.items() if key != "requestRawObjectBytes") > len(before_reply)):
                raise ValueError("ordinary execute payload partition exceeds actual bytes")
            full = record["replyEof"] and consumed == len(before_reply)
            if not full and any(payload[key] for key in EXECUTE_PAYLOAD_KEYS - {"requestRawObjectBytes"}):
                raise ValueError("partial content-bearing reply partition remains unknown")
            context = None
            rows = contexts.get(call, [])
            if rows:
                stable = EXECUTE_ATTEMPT_FIELDS - {"elapsedMicros", "observedAtUnixMicros"}
                if (len(rows) != 1 or any(rows[0]["value"]["attempt"][field] != record[field]
                        for field in stable)):
                    raise ValueError("ordinary execute final context ownership differs")
                context = rows[0]
                used_context.add(call)
            used.add(call)
            report["joined"].append({"nativeRequestId": identity, "receivedRequestId": actual["requestId"],
                "transportCallId": call, "attempt": record, "payload": codec["payload"],
                "nativeExposedReplyBytes": str(consumed), "fullReplyConsumed": full,
                "finalContext": context, "currentActorEvidence": None,
                "purposeArtifactEvidence": None, "providerObjectPartition": None})
        except (ValueError, KeyError, TypeError):
            report["unresolvedNativeRequestIds"].append(identity)
    report["unassignedAttemptCallIds"] = sorted(set(attempts) - used)
    report["unassignedFinalContextCallIds"] = sorted(set(contexts) - used_context)
    return report
