"""Join exact workflow bodies with selected compiled codecs and real byte events.

This consumer does not authenticate traffic or establish capture completeness.
The fixture must independently retain the complete window, installed source and
observer provenance, accepted purpose/current actor evidence, and provider logs.
Absent or inconsistent inputs produce an unresolved result, never a configured
zero. Counters describe application payload rather than TLS or provider billing.
"""

import hashlib
import os
import re
import stat


BODY_LIMIT = 8 * 1024 * 1024
CORPUS_LIMIT = 512 * 1024 * 1024
CAPTURE_LIMIT = 4096
OPERATIONS = {
    "external_copy_control": "/_internal/storage/external-copy/v1",
    "external_copy_metadata": "/_internal/storage/external-copy-metadata/v1",
    "OciDocumentProjection": "/_internal/storage/oci-document-projection",
}
DISTRIBUTION_OPERATIONS = {
    "oci_manifest_authorize", "oci_manifest_preflight", "oci_manifest_complete",
    "oci_chunk_preflight", "oci_chunk_complete", "oci_blob_download", "oci_document_download",
}

CONTENT_CLASSES = {
    "external_copy_control_metadata", "external_copy_profile_metadata",
    "oci_stored_document_projection", "oci_distribution_control_metadata",
    "oci_distribution_blob_body", "oci_distribution_document_body",
}

OPERATION_CLASSES = {
    "external_copy_control": "external_copy_control_metadata",
    "external_copy_metadata": "external_copy_profile_metadata",
    "OciDocumentProjection": "oci_stored_document_projection",
    "oci_manifest_authorize": "oci_distribution_control_metadata",
    "oci_manifest_preflight": "oci_distribution_control_metadata",
    "oci_manifest_complete": "oci_distribution_control_metadata",
    "oci_chunk_preflight": "oci_distribution_control_metadata",
    "oci_chunk_complete": "oci_distribution_control_metadata",
    "oci_blob_download": "oci_distribution_blob_body",
    "oci_document_download": "oci_distribution_document_body",
}

CODEC_FIELDS = {
    "requestId", "sourceDigest", "requestSha256", "replySha256",
    "codecSourceSha256", "exchangeIdSha256", "originalContextSha256",
    "operation", "class", "payload",
}


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("workflow digest is not closed")
    return value


def _count(value):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        return int(value)
    raise ValueError("workflow byte count is not canonical")


def _body(reference):
    if set(reference) != {"file", "sha256", "byteSize"}:
        raise ValueError("workflow body reference shape differs")
    expected = _count(reference["byteSize"])
    if expected > BODY_LIMIT:
        raise ValueError("workflow body exceeds existing capture bound")
    descriptor = os.open(reference["file"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o077 or before.st_size != expected):
            raise ValueError("workflow body custody or size differs")
        digest = hashlib.sha256()
        consumed = 0
        while block := os.read(descriptor, 64 * 1024):
            consumed += len(block)
            if consumed > expected:
                raise ValueError("workflow body grew while reading")
            digest.update(block)
        after = os.fstat(descriptor)
        if (consumed != expected or digest.hexdigest() != _digest(reference["sha256"])
                or any(getattr(before, field) != getattr(after, field)
                       for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
            raise ValueError("workflow body changed or its commitment differs")
    finally:
        os.close(descriptor)
    return consumed


def _unique(rows, key):
    if not isinstance(rows, list) or len(rows) > CAPTURE_LIMIT:
        raise ValueError("workflow evidence collection differs")
    selected = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("workflow evidence row differs")
        identity = row[key]
        if not isinstance(identity, str) or not identity:
            raise ValueError("workflow evidence identity differs")
        if identity in selected:
            raise ValueError("workflow evidence is ambiguous")
        selected[identity] = row
    return selected


def assess_storage_workflow_bodies(captures, originals, codec_rows, contexts,
                                   exchanges, provider_window, source_digest,
                                   selected_codec_source_sha256):
    """Derive payload counts only for a fully joined selected workflow window.

    ``codec_rows`` are outputs of an independently selected source-built codec,
    not caller classifications. ``contexts`` must join actual accepted-handler
    or post-authentication Native evidence, current actor snapshots and selected
    purpose artifacts. Their retained hashes are evidence references, not a
    substitute for signature/SQL/provider verification by the fixture.
    """
    report = {"version": 1, "nativeBulkBytes": None, "nativeTransportBodyBytes": None,
              "nativeNonBulkTransportBodyBytes": None,
              "nativeSelectedDataBytes": None,
              "semanticOciProjectionBytes": None, "unresolvedRequestIds": [],
              "scope": "application payload observations; no TLS billing or execution permission"}
    try:
        _digest(source_digest)
        _digest(selected_codec_source_sha256)
        if not captures or len(captures) > CAPTURE_LIMIT:
            raise ValueError("workflow capture coverage is empty or excessive")
        actual = _unique(captures, "requestId")
        original = _unique(originals, "requestId")
        codecs = _unique(codec_rows, "requestId")
        accepted = _unique(contexts, "requestId")
        records = _unique(exchanges, "requestId")
        if not (set(actual) == set(original) == set(codecs) == set(accepted) == set(records)):
            raise ValueError("workflow original, codec or accepted exchange coverage differs")
        if (provider_window is None or provider_window["unresolvedReceiptIndexes"]
                or provider_window["unknownCallers"] or provider_window["nativeProviderCalls"]
                or len(provider_window["classified"]) != provider_window["observedReceiptCount"]):
            raise ValueError("provider window remains unresolved or includes Native provider calls")
        _digest(provider_window["rawReportSha256"])
        indexes = [row["receiptIndex"] for row in provider_window["classified"]]
        if any(type(index) is not int for index in indexes) or sorted(indexes) != list(range(provider_window["observedReceiptCount"])):
            raise ValueError("provider receipt partition differs from actual observed window")

        bulk = transport = selected = semantic = 0
        for identifier, capture in actual.items():
            previous, codec, context, exchange = (
                original[identifier], codecs[identifier], accepted[identifier], records[identifier])
            for field in ("procedure", "method", "phase", "status"):
                if capture[field] != previous[field]:
                    raise ValueError("original and received request selectors differ")
            if capture["responseContentEncoding"] not in (None, "", "identity"):
                raise ValueError("encoded workflow payload remains unsupported")
            request = capture["bodies"]["request"]
            reply = capture["bodies"]["response"]
            for direction in ("request", "response"):
                current_body = capture["bodies"][direction]
                prior_body = previous["bodies"][direction]
                if (current_body["sha256"], _count(current_body["byteSize"])) != (
                        prior_body["sha256"], _count(prior_body["byteSize"])):
                    raise ValueError("original and received body commitments differ")
                _body(prior_body)
            request_bytes, reply_bytes = _body(request), _body(reply)
            for evidence in (codec, context):
                if (evidence["sourceDigest"] != source_digest
                        or evidence["requestSha256"] != request["sha256"]
                        or evidence["replySha256"] != reply["sha256"]):
                    raise ValueError("compiled observation or accepted context differs from actual bodies")
            if (set(codec) != CODEC_FIELDS
                    or codec["codecSourceSha256"] != selected_codec_source_sha256):
                raise ValueError("selected compiled codec shape or provenance differs")
            if codec["class"] not in CONTENT_CLASSES:
                raise ValueError("workflow codec is unsupported")
            operation = codec["operation"]
            if operation not in OPERATIONS and operation not in DISTRIBUTION_OPERATIONS:
                raise ValueError("workflow operation is unsupported")
            if codec["class"] != OPERATION_CLASSES[operation]:
                raise ValueError("workflow operation and payload class differ")
            if operation in OPERATIONS and capture["procedure"] != OPERATIONS[operation]:
                raise ValueError("workflow operation and route differ")
            if operation != context["operation"] or operation != exchange["operation"]:
                raise ValueError("workflow operation substituted")
            if (codec["exchangeIdSha256"] != context["exchangeIdSha256"]
                    or codec["exchangeIdSha256"] != hashlib.sha256(exchange["plan_id"].encode()).hexdigest()):
                raise ValueError("application accounting belongs to another original exchange")
            if codec["originalContextSha256"] != context["originalContextSha256"]:
                raise ValueError("workflow original context substituted")
            for field in ("originalContextSha256", "purposeArtifactSha256", "actorSnapshotSha256"):
                _digest(context[field])
            _digest(codec["codecSourceSha256"])
            if (exchange["outcome"] != "success" or _count(exchange["exchange_attempts"]) != 1
                    or _count(exchange["discarded_status_responses"]) != 0
                    or _count(exchange["offered_plan_bytes"]) != request_bytes
                    or _count(exchange["observed_body_bytes"]) != reply_bytes):
                raise ValueError("workflow application consumption is partial, unread or unverified")
            payload = codec["payload"]
            if set(payload) != {"requestRawObjectBytes", "replyRawObjectBytes",
                                "selectedDataBytes", "semanticOciProjectionBytes"}:
                raise ValueError("workflow decoded payload categories differ")
            request_raw = _count(payload["requestRawObjectBytes"])
            reply_raw = _count(payload["replyRawObjectBytes"])
            selected_bytes = _count(payload["selectedDataBytes"])
            semantic_bytes = _count(payload["semanticOciProjectionBytes"])
            if (request_raw > request_bytes or reply_raw > reply_bytes
                    or selected_bytes + semantic_bytes > reply_bytes):
                raise ValueError("decoded workflow payload exceeds actual consumed bytes")
            if codec["class"] in {"external_copy_control_metadata", "external_copy_profile_metadata",
                                 "oci_stored_document_projection", "oci_distribution_control_metadata"}:
                if request_raw or reply_raw or selected_bytes:
                    raise ValueError("raw object bytes cannot be relabeled as metadata")
            if codec["class"] == "oci_distribution_blob_body" and reply_raw != reply_bytes:
                raise ValueError("whole blob reply must count every actual body byte")
            if codec["class"] == "oci_distribution_document_body" and reply_raw != reply_bytes:
                raise ValueError("original document reply must count every actual body byte")
            bulk += request_raw + reply_raw
            selected += selected_bytes
            semantic += semantic_bytes
            transport += request_bytes + reply_bytes
            if transport > CORPUS_LIMIT:
                raise ValueError("workflow corpus exceeds existing aggregate capture bound")
        report.update(nativeBulkBytes=bulk, nativeTransportBodyBytes=transport,
                      nativeNonBulkTransportBodyBytes=transport-bulk,
                      nativeSelectedDataBytes=selected, semanticOciProjectionBytes=semantic)
    except (KeyError, TypeError, ValueError, OSError):
        if isinstance(captures, list):
            report["unresolvedRequestIds"] = [
                row.get("requestId") if isinstance(row, dict) else None
                for row in captures
            ]
        else:
            report["unresolvedRequestIds"] = [None]
    return report
