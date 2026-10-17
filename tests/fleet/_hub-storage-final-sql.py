"""Correlate actual post-SQL receipts with exclusive authenticated transports.

This projection observes the state checked by the production caller. Independent
SQL/API observations, actual actor acceptance, installed purpose verification
and complete provider partitions remain required. Digests grant no authority.
"""

import hashlib
import json
import re


STORAGE_FINAL_SQL_COMMITMENTS = {
    "managed_oci_cleanup_delete_checked": frozenset((
        "requestSha256", "replySha256", "uploadStateSha256", "chunkStateSha256",
        "placementStateSha256", "bindingStateSha256", "deleteCapabilitySha256",
    )),
    "external_copy_current_sql": frozenset((
        "topologySha256", "sourcePlacementSha256", "destinationPlacementSha256",
        "bindingStateSha256", "writeRevisionStateSha256", "consumerGrantStateSha256",
        "claimSha256", "catalogueStateSha256", "profileDigest", "snapshotRevision",
    )),
    "managed_oci_current_sql": frozenset((
        "placementStateSha256", "bindingStateSha256", "lookupSha256",
        "storedObjectSha256", "descriptorSha256", "profileDigest",
    )),
    "external_oci_stage_snapshot_checked": frozenset((
        "stagePermitSha256", "requestSha256", "snapshotSha256", "profileDigest",
    )),
    "external_oci_stage_writer_checked": frozenset((
        "stagePermitSha256", "actorOriginalSha256", "writerSha256", "uploadOriginalSha256",
        "uploadStateSha256", "profileDigest",
    )),
    "external_oci_source_writer_checked": frozenset((
        "sourceOriginalSha256", "sourceClosureSha256", "profileDigest",
    )),
    "external_oci_projection_writer_checked": frozenset((
        "placementStateSha256", "bindingStateSha256", "lookupSha256",
        "storedObjectSha256", "descriptorSha256", "profileDigest",
    )),
    "external_oci_materialization_source_checked": frozenset((
        "requestSemanticSha256", "replySemanticSha256", "actorOriginalSha256", "writerSha256",
        "uploadStateSha256", "expectedDigestSha256", "outcomeSha256",
    )),
    "external_oci_materialization_control_checked": frozenset((
        "requestSemanticSha256", "replySemanticSha256", "actorOriginalSha256", "writerSha256",
        "uploadStateSha256", "expectedDigestSha256", "outcomeSha256",
    )),
    "external_oci_cleanup_delete_checked": frozenset((
        "requestSha256", "replySha256", "uploadStateSha256", "chunkStateSha256",
        "placementStateSha256", "bindingStateSha256", "deleteCredentialSha256", "deleteCapabilitySha256",
    )),
}

STORAGE_FINAL_SQL_ROUTES = {
    "managed_oci_cleanup_delete_checked": {
        MANAGED_CLEANUP_CAPTURE_ROUTE: "managed_oci_cleanup"},
    "external_copy_current_sql": COPY_CAPTURE_ROUTES,
    "managed_oci_current_sql": {OCI_CAPTURE_ROUTE: "OciDocumentProjection"},
    "external_oci_projection_writer_checked": {OCI_CAPTURE_ROUTE: "OciDocumentProjection"},
    "external_oci_stage_snapshot_checked": {
        "/_internal/storage/external-oci/v1": "external_oci_control"},
    "external_oci_stage_writer_checked": {
        "/_internal/storage/external-oci/v1": "external_oci_control"},
    "external_oci_source_writer_checked": {
        "/_internal/storage/external-oci-source/v1": "external_oci_source"},
    "external_oci_materialization_source_checked": {
        "/_internal/storage/external-oci-source/v1": "external_oci_source"},
    "external_oci_materialization_control_checked": {
        "/_internal/storage/external-oci/v1": "external_oci_control"},
    "external_oci_cleanup_delete_checked": {
        "/_internal/storage/external-oci-cleanup/v1": "external_oci_cleanup"},
}


def validate_storage_final_sql_value(value):
    """Check the shared closed final-context shape without granting SQL authority."""
    if (not isinstance(value, dict) or set(value) != {
            "version", "exchange", "contextKind", "commitments", "completedAtUnixMicros"}
            or type(value["version"]) is not int or value["version"] != 1
            or not isinstance(value["contextKind"], str)
            or value["contextKind"] not in STORAGE_FINAL_SQL_COMMITMENTS
            or not isinstance(value["commitments"], dict)
            or not re.fullmatch(r"[1-9][0-9]{0,19}", value["completedAtUnixMicros"])):
        raise ValueError("final SQL event shape differs")
    kind = value["contextKind"]
    fields = set(value["commitments"])
    expected = STORAGE_FINAL_SQL_COMMITMENTS[kind]
    if (fields != expected and not (kind == "managed_oci_current_sql"
            and fields == expected | {"purposeEvidenceSha256", "documentEffectSha256"})):
        raise ValueError("final SQL commitment projection differs")
    if any(not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            for digest in value["commitments"].values()):
        raise ValueError("final SQL commitment differs")
    exchange = value["exchange"]
    routes = STORAGE_FINAL_SQL_ROUTES[kind]
    if (not isinstance(exchange, dict) or set(exchange) != STORAGE_AUTHENTICATED_FIELDS
            or type(exchange["version"]) is not int or exchange["version"] != 2
            or exchange["route"] not in routes
            or exchange["operation"] != routes[exchange["route"]]
            or not re.fullmatch(r"[0-9a-f]{32}", exchange["transportCallId"])
            or not re.fullmatch(r"[0-9a-f]{32}" if kind == "external_copy_current_sql"
                else r"[0-9a-f]{64}", exchange["planId"])):
        raise ValueError("final SQL exchange differs")
    for field in ("requestSha256", "replySha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", exchange[field]):
            raise ValueError("final SQL body commitment differs")
    for field in ("requestBytes", "replyBytes"):
        maximum = storage_transport_body_limit(exchange["route"], field)
        if type(exchange[field]) is not int or not 0 <= exchange[field] <= maximum:
            raise ValueError("final SQL consumed body bound differs")
    return value


def storage_final_sql_receipts(text, native_process, file_provenance=None):
    """Parse only bounded source-bound events from the actual pinned process."""
    receipts = []
    prefix = "[INFO] message=storage_final_sql_checked "
    for message, observed_at in observed_native_messages(text, native_process, file_provenance):
        if not isinstance(message, str) or not message.startswith(prefix):
            continue
        encoded = message[len(prefix):]
        if len(encoded.encode()) > 16 * 1024 + 4096:
            raise ValueError("final SQL event exceeds its retained bound")
        _, end = json.JSONDecoder().raw_decode(encoded)
        if encoded[end:] and not encoded[end:].startswith(" span="):
            raise ValueError("final SQL event suffix differs")
        value = _closed_review_json(encoded[:end])
        validate_storage_final_sql_value(value)
        receipts.append({**value, "journalAtUnixMicros": observed_at,
            "receiptSha256": hashlib.sha256(encoded[:end].encode()).hexdigest()})
        if len(receipts) > PROTECTED_HEADER_RECORD_LIMIT:
            raise ValueError("final SQL event corpus exceeds its observation bound")
    return receipts


def join_storage_final_sql(transport, receipts):
    """Require one exact final SQL event for each already authenticated call."""
    by_call = {}
    for receipt in receipts:
        call_sha = hashlib.sha256(receipt["exchange"]["transportCallId"].encode()).hexdigest()
        by_call.setdefault(call_sha, []).append(receipt)
    joined, unresolved, used = [], [], set()
    for call in transport["joined"]:
        rows = by_call.get(call["transportCallIdSha256"], [])
        if len(rows) != 1:
            unresolved.append(call["nativeRequestId"])
            continue
        row, exchange = rows[0], rows[0]["exchange"]
        if (STORAGE_CAPTURE_ROUTES.get(exchange["route"]) != call["operation"]
                or exchange["operation"] != call["operation"]
                or hashlib.sha256(exchange["planId"].encode()).hexdigest() != call["planIdSha256"]
                or exchange["requestSha256"] != call["requestSha256"]
                or exchange["replySha256"] != call["replySha256"]
                or exchange["requestBytes"] != call["offeredRequestBytes"]
                or exchange["replyBytes"] != call["consumedReplyBytes"]
                or call["transportCallIdSha256"] in used):
            unresolved.append(call["nativeRequestId"])
            continue
        used.add(call["transportCallIdSha256"])
        joined.append({"nativeRequestId": call["nativeRequestId"],
            "transportCallIdSha256": call["transportCallIdSha256"],
            "finalSqlReceiptSha256": row["receiptSha256"], "contextKind": row["contextKind"],
            "commitments": row["commitments"], "completedAtUnixMicros": row["completedAtUnixMicros"],
            "journalAtUnixMicros": row["journalAtUnixMicros"],
            "independentSqlEvidence": None, "actorEvidence": None,
            "purposeEvidence": None, "providerPartition": None})
    return {"version": 1, "joined": joined, "unresolvedNativeRequestIds": unresolved,
        "unassignedReceiptSha256": [row["receiptSha256"] for call_sha, rows in by_call.items()
            if call_sha not in used for row in rows], "nativeBulkBytes": None,
        "scope": "actual final caller SQL checks only; independent current SQL/actor/purpose/provider joins remain required"}


def external_admission_actor_receipts(text, native_process, file_provenance=None):
    """Read the actual post-recheck admission bridge without granting IAM."""
    rows = []
    prefix = "[INFO] message=external_oci_admission_actor_checked "
    for message, observed_at in observed_native_messages(text, native_process, file_provenance):
        if not isinstance(message, str) or not message.startswith(prefix):
            continue
        encoded = message[len(prefix):]
        if len(encoded.encode()) > 8192:
            raise ValueError("admission actor event exceeds its bound")
        _, end = json.JSONDecoder().raw_decode(encoded)
        if encoded[end:] and not encoded[end:].startswith(" span="):
            raise ValueError("admission actor event suffix differs")
        value = _closed_review_json(encoded[:end])
        fields = {"stagePermitSha256", "actorOriginalSha256", "writerSha256",
            "uploadOriginalSha256", "profileDigest"}
        if (not isinstance(value, dict) or set(value) != fields | {
                "version", "phase", "completedAtUnixMicros"}
                or type(value["version"]) is not int or value["version"] != 1
                or value["phase"] not in {"chunk", "manifest"}
                or not re.fullmatch(r"[1-9][0-9]{0,19}", value["completedAtUnixMicros"])
                or any(not isinstance(value[field], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", value[field]) for field in fields)):
            raise ValueError("admission actor event shape differs")
        rows.append({**value, "receiptSha256": hashlib.sha256(encoded[:end].encode()).hexdigest(),
            "journalAtUnixMicros": observed_at})
        if len(rows) > PROTECTED_HEADER_RECORD_LIMIT:
            raise ValueError("admission actor event corpus exceeds its bound")
    return rows


def join_external_admission_actor(final_sql, receipts):
    """Join the exact writer permit to one later actual actor-recheck event.

    Source/readback and terminal Delete checks remain distinct. Independent SQL
    state, accepted purpose and provider original partitions are still required.
    """
    by_permit = {}
    for row in receipts:
        by_permit.setdefault(row["stagePermitSha256"], []).append(row)
    joined, unresolved, used = [], [], set()
    for call in final_sql["joined"]:
        if call["contextKind"] != "external_oci_stage_writer_checked":
            continue
        facts = call["commitments"]
        rows = by_permit.get(facts["stagePermitSha256"], [])
        if len(rows) != 1 or rows[0]["receiptSha256"] in used:
            unresolved.append(call["nativeRequestId"])
            continue
        row = rows[0]
        if (any(row[field] != facts[field] for field in (
                "actorOriginalSha256", "writerSha256", "uploadOriginalSha256", "profileDigest"))
                or int(row["completedAtUnixMicros"]) < int(call["completedAtUnixMicros"])):
            unresolved.append(call["nativeRequestId"])
            continue
        used.add(row["receiptSha256"])
        joined.append({"nativeRequestId": call["nativeRequestId"],
            "transportCallIdSha256": call["transportCallIdSha256"],
            "stagePermitSha256": facts["stagePermitSha256"], "phase": row["phase"],
            "actorReceiptSha256": row["receiptSha256"],
            "completedAtUnixMicros": row["completedAtUnixMicros"],
            "independentSqlEvidence": None, "purposeEvidence": None, "providerPartition": None,
            "scope": "actual admission actor recheck after this exact Native writer permit; no subsequent commit or fresh permission assertion"})
    return {"version": 1, "joined": joined, "unresolvedNativeRequestIds": unresolved,
        "unassignedReceiptSha256": [row["receiptSha256"] for row in receipts
            if row["receiptSha256"] not in used], "nativeBulkBytes": None}
