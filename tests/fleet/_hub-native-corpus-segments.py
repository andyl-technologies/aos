"""Partition retained observations without changing any executable codec bound.

Every original belongs to one global inventory before bounded codec selections
are made. Membership and receipt ownership are global, never reset per segment.
These checks establish coverage/custody only; they authenticate no traffic and
cannot supply missing actor, purpose, provider or Native-bulk evidence.
"""

import hashlib
import json
import re


NATIVE_CODEC_SEGMENT_COUNT_LIMIT = 4096
NATIVE_CODEC_SEGMENT_MANIFEST_LIMIT = 1024 * 1024
NATIVE_CODEC_SEGMENT_REFERENCE_LIMIT = 512 * 1024 * 1024
NATIVE_CODEC_BODY_LIMIT = 8 * 1024 * 1024
# Each independently retained inbound/outbound role has the existing allowance.
NATIVE_RETAINED_ROLE_COUNT_LIMIT = 2 * (12_535 + 3) * 8 + 4096
NATIVE_INVENTORY_COUNT_LIMIT = 2 * NATIVE_RETAINED_ROLE_COUNT_LIMIT
NATIVE_INVENTORY_BYTE_LIMIT = 256 * 1024 * 1024
NATIVE_INVENTORY_ROW_LIMIT = 2048
NATIVE_SEGMENT_REPORT_BYTE_LIMIT = 256 * 1024 * 1024
NATIVE_SEGMENT_DIAGNOSTIC_BYTE_LIMIT = 4096


def native_corpus_json(value):
    """Encode exact private selections and commitment projections consistently."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def _commitment(value):
    return hashlib.sha256(native_corpus_json(value)).hexdigest()


def _identity(value):
    if (not isinstance(value, str) or not value or len(value) > 256
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError("corpus identity is not bounded")
    return value


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("corpus commitment differs")
    return value


def _count(value):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        return int(value)
    raise ValueError("corpus byte count is not canonical")


def native_corpus_inventory(originals):
    """Commit every retained original, including unsupported or incomplete rows.

    Each row supplies its observation role and complete captured original. This
    inventory is retained before any codec or authority assessment can refuse.
    Private bodies stay separate; no input is removed to obtain a positive page.
    """
    rows, seen, size, role_counts = [], set(), 0, {}
    for role, original in originals:
        if role not in {"inbound", "outbound"}:
            raise ValueError("corpus observation role differs")
        role_counts[role] = role_counts.get(role, 0) + 1
        if role_counts[role] > NATIVE_RETAINED_ROLE_COUNT_LIMIT:
            raise ValueError("retained observation role exceeds its corpus allowance")
        identifier = role + ":" + _identity(original["requestId"])
        if identifier in seen or len(rows) >= NATIVE_INVENTORY_COUNT_LIMIT:
            raise ValueError("corpus originals are duplicate or excessive")
        seen.add(identifier)
        row = {"originalId": identifier, "originalSha256": _commitment(original)}
        length = len(native_corpus_json(row))
        size += length
        if length > NATIVE_INVENTORY_ROW_LIMIT or size > NATIVE_INVENTORY_BYTE_LIMIT:
            raise ValueError("corpus inventory exceeds its representation bound")
        rows.append(row)
    if not rows:
        raise ValueError("retained corpus is empty")
    return {"version": 1, "originalCount": len(rows), "originals": rows,
            "membershipSha256": _commitment(rows),
            "scope": "all retained original commitments; no authentication or byte classification"}


def _reference_bytes(value):
    if isinstance(value, dict):
        if set(value) == {"file", "sha256", "byteSize"}:
            if not isinstance(value["file"], str) or not value["file"] or "\0" in value["file"]:
                raise ValueError("selected body pathname differs")
            _digest(value["sha256"])
            count = _count(value["byteSize"])
            if count > NATIVE_CODEC_BODY_LIMIT:
                raise ValueError("individual selected body exceeds the existing codec limit")
            return count
        return sum(_reference_bytes(child) for child in value.values())
    if isinstance(value, list):
        return sum(_reference_bytes(child) for child in value)
    return 0


def partition_native_codec_corpus(inventory, template, field, records, ownership):
    """Create bounded selections only after exact global ownership is checked.

    ``ownership`` maps selected request IDs to their original inventory IDs and
    independently retained received/accepted receipt IDs when available. The
    caller must perform actual authentication joins; their commitments are not
    authority. Missing required production evidence still refuses downstream.
    """
    if field not in {"captures", "cases"} or field in template:
        raise ValueError("codec segment template differs")
    originals = inventory["originals"]
    if (inventory["version"] != 1 or inventory["originalCount"] != len(originals)
            or inventory["membershipSha256"] != _commitment(originals)):
        raise ValueError("frozen corpus inventory differs")
    expected = {row["originalId"] for row in originals}
    if len(expected) != len(originals) or not expected:
        raise ValueError("frozen corpus inventory ownership differs")
    if len(records) != len(ownership) or len(records) != len(expected):
        raise ValueError("codec selection omits a retained original")
    seen_originals, seen_requests, seen_received, seen_receipts, seen_calls = (set() for _ in range(5))
    members = []
    for record, owner in zip(records, ownership):
        if set(owner) != {"originalId", "receivedId", "receiptIdSha256", "transportCallIdSha256"}:
            raise ValueError("codec ownership projection differs")
        original = _identity(owner["originalId"])
        request = _identity(record["requestId"])
        if original not in expected or original in seen_originals or request in seen_requests:
            raise ValueError("codec original/request ownership is ambiguous")
        seen_originals.add(original)
        seen_requests.add(request)
        for key, seen in (("receivedId", seen_received), ("receiptIdSha256", seen_receipts),
                          ("transportCallIdSha256", seen_calls)):
            value = owner[key]
            if value is not None:
                (_identity if key == "receivedId" else _digest)(value)
                if value in seen:
                    raise ValueError("received call or accepted receipt is reused across the corpus")
                seen.add(value)
        members.append({"originalId": original, "selectedRequestIdSha256":
                        hashlib.sha256(request.encode()).hexdigest(),
                        "selectedCaptureSha256": _commitment(record),
                        "ownershipSha256": _commitment(owner)})
    if seen_originals != expected:
        raise ValueError("codec membership is not the complete original partition")

    segments, selected, selected_members, consumed = [], [], [], 0
    empty_size = len(native_corpus_json({**template, field: []}))
    encoded_size = empty_size
    for record, member in zip(records, members):
        reference_bytes = _reference_bytes(record)
        row_size = len(native_corpus_json(record))
        candidate_size = encoded_size + row_size + bool(selected)
        if selected and (len(selected) >= NATIVE_CODEC_SEGMENT_COUNT_LIMIT
                or consumed + reference_bytes > NATIVE_CODEC_SEGMENT_REFERENCE_LIMIT
                or candidate_size > NATIVE_CODEC_SEGMENT_MANIFEST_LIMIT):
            _append_segment(segments, template, field, selected, selected_members, consumed)
            selected, selected_members, consumed = [], [], 0
            encoded_size = empty_size
            candidate_size = empty_size + row_size
        if (reference_bytes > NATIVE_CODEC_SEGMENT_REFERENCE_LIMIT
                or candidate_size > NATIVE_CODEC_SEGMENT_MANIFEST_LIMIT):
            raise ValueError("one selected original cannot fit the existing codec limits")
        selected.append(record)
        selected_members.append(member)
        consumed += reference_bytes
        encoded_size = candidate_size
    if selected:
        _append_segment(segments, template, field, selected, selected_members, consumed)
    bundle = {"version": 1, "inventorySha256": _commitment(inventory),
              "originalCount": len(members), "membershipSha256": _commitment(members),
              "templateSha256": _commitment(template), "field": field, "segments": segments,
              "scope": "complete bounded codec selections; all authority and provider joins remain independent"}
    if len(native_corpus_json(bundle)) > NATIVE_INVENTORY_BYTE_LIMIT:
        raise ValueError("complete codec selection representation exceeds its bound")
    return bundle


def _append_segment(segments, template, field, rows, members, consumed):
    manifest = {**template, field: rows}
    segments.append({"index": len(segments), "manifest": manifest,
                     "manifestSha256": _commitment(manifest), "members": members,
                     "membershipSha256": _commitment(members),
                     "count": len(rows), "selectedReferenceBytes": consumed})


def validate_native_segment_outputs(bundle, outcomes, executable_sha256, provenance_sha256):
    """Check terminal coverage without interpreting codec semantics or permission.

    Every segment must succeed with the same independently selected executable
    and provenance and exactly its original membership. Any failed, omitted,
    duplicate or substituted terminal outcome refuses the complete assessment.
    """
    _digest(executable_sha256)
    _digest(provenance_sha256)
    segments = bundle["segments"]
    if len(outcomes) != len(segments):
        raise ValueError("codec terminal segment coverage is incomplete")
    # Exact retained JSON array includes brackets, commas and its final newline.
    members, seen, total = [], set(), 3
    for index, (segment, outcome) in enumerate(zip(segments, outcomes)):
        if set(outcome) != {"index", "status", "manifestSha256", "membershipSha256",
                           "executableSha256", "provenanceSha256", "report"}:
            raise ValueError("codec terminal outcome shape differs")
        total += len(native_corpus_json(outcome)) + bool(index)
        if total > NATIVE_SEGMENT_REPORT_BYTE_LIMIT:
            raise ValueError("terminal envelopes exceed the exact aggregate representation bound")
        rows = segment["manifest"][bundle["field"]]
        template = {name: value for name, value in segment["manifest"].items() if name != bundle["field"]}
        if (_commitment(template) != bundle["templateSha256"]
                or len(rows) > NATIVE_CODEC_SEGMENT_COUNT_LIMIT
                or len(native_corpus_json(segment["manifest"])) > NATIVE_CODEC_SEGMENT_MANIFEST_LIMIT
                or _reference_bytes(rows) != segment["selectedReferenceBytes"]
                or segment["selectedReferenceBytes"] > NATIVE_CODEC_SEGMENT_REFERENCE_LIMIT):
            raise ValueError("codec segment changed source template or existing bounds")
        if (segment["index"] != index or segment["count"] != len(rows)
                or segment["manifestSha256"] != _commitment(segment["manifest"])
                or segment["membershipSha256"] != _commitment(segment["members"])
                or outcome["index"] != index or outcome["status"] != "success"
                or outcome["manifestSha256"] != segment["manifestSha256"]
                or outcome["membershipSha256"] != segment["membershipSha256"]
                or outcome["executableSha256"] != executable_sha256
                or outcome["provenanceSha256"] != provenance_sha256):
            raise ValueError("codec segment/source/custody outcome differs")
        for record, member in zip(rows, segment["members"]):
            if member["originalId"] in seen or member["selectedCaptureSha256"] != _commitment(record):
                raise ValueError("codec cross-segment original ownership differs")
            seen.add(member["originalId"])
        if len(rows) != len(segment["members"]):
            raise ValueError("codec segment membership is incomplete")
        members.extend(segment["members"])
    if (len(members) != bundle["originalCount"]
            or _commitment(members) != bundle["membershipSha256"]):
        raise ValueError("terminal codec membership omits or substitutes an original")
    return {"version": 1, "inventorySha256": bundle["inventorySha256"],
            "membershipSha256": bundle["membershipSha256"],
            "originalCount": len(members), "segmentCount": len(segments),
            "executableSha256": executable_sha256, "provenanceSha256": provenance_sha256,
            "terminalReportsSha256": _commitment(outcomes), "nativeBulkBytes": None,
            "scope": "complete successful observational segments only; semantic/authentication/provider assessment remains required"}


def native_corpus_receipt_identity(receipt):
    """Commit actual accepted-event identity, excluding assigned proxy IDs.

    Distinct proxy requests must never make one retained accepted event appear
    distinct. Ambiguous handler timestamps refuse; execution messages without
    per-call IDs conservatively retain their real plan/operation/count identity.
    This identity authenticates nothing by itself.
    """
    if "transportCallIdSha256" in receipt:
        value = {name: receipt[name] for name in
                 ("transportCallIdSha256", "requestSha256", "replySha256")}
    elif "handlerReceiptSemanticSha256" in receipt:
        times = receipt["handlerCompletedAtUnixMillis"]
        if not isinstance(times, list) or len(times) != 1:
            raise ValueError("accepted handler event has ambiguous per-call ownership")
        value = {"handlerReceiptSemanticSha256": receipt["handlerReceiptSemanticSha256"],
                 "handlerCompletedAtUnixMillis": times[0]}
    elif "executorSourceBytes" in receipt:
        value = {name: receipt[name] for name in
                 ("planIdSha256", "operation", "requestBytes", "replyBytes", "executorSourceBytes")}
    else:
        value = {name: receipt[name] for name in
                 ("step", "publicRequestSha256", "requestSha256", "replySha256",
                  "requestBytes", "replyBytes", "sessions")}
    return _commitment(value)
