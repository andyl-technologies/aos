"""Retain compact controls and correlate authenticated Copy/OCI transports.

Header values and selected journal records remain owner-private. Public numeric
projections contain commitments only. Transport acceptance is not a current SQL
actor, purpose artifact, provider partition or permission to perform new work.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat


PROTECTED_HEADER_V2_FIELDS = frozenset((
    "version", "request_id", "origin_request_id", "path_and_query", "method",
    "phase", "status", "ingress", "request_signature", "reply_signature", "query_class",
    "transport_call_id", "oci_request_signature", "oci_reply_signature",
))
EXTERNAL_OCI_SIGNATURE_FIELDS = frozenset((
    "external_oci_request_signature", "external_oci_reply_signature",
    "external_oci_source_request_signature", "external_oci_source_reply_signature",
    "external_oci_cleanup_request_signature", "external_oci_cleanup_reply_signature",
))
PROTECTED_HEADER_FIELDS = PROTECTED_HEADER_V2_FIELDS | EXTERNAL_OCI_SIGNATURE_FIELDS
MANAGED_OCI_CLEANUP_SIGNATURE_FIELDS = frozenset((
    "managed_oci_cleanup_request_signature", "managed_oci_cleanup_reply_signature",
))
PROTECTED_HEADER_V4_FIELDS = PROTECTED_HEADER_FIELDS | MANAGED_OCI_CLEANUP_SIGNATURE_FIELDS
STORAGE_AUTHENTICATED_FIELDS = frozenset((
    "version", "route", "planId", "operation", "requestSha256", "replySha256",
    "requestBytes", "replyBytes", "transportCallId",
))
COPY_CAPTURE_ROUTES = {
    "/_internal/storage/external-copy/v1": "external_copy_control",
    "/_internal/storage/external-copy-metadata/v1": "external_copy_metadata",
}
OCI_CAPTURE_ROUTE = "/_internal/storage/oci-document-projection"
EXTERNAL_OCI_CAPTURE_ROUTES = {
    "/_internal/storage/external-oci/v1": "external_oci_control",
    "/_internal/storage/external-oci-source/v1": "external_oci_source",
    "/_internal/storage/external-oci-cleanup/v1": "external_oci_cleanup",
}
STORAGE_CAPTURE_ROUTES = {**COPY_CAPTURE_ROUTES, **EXTERNAL_OCI_CAPTURE_ROUTES,
    OCI_CAPTURE_ROUTE: "OciDocumentProjection"}
STORAGE_SIGNATURE_FIELDS = {
    **{route: ("request_signature", "reply_signature") for route in COPY_CAPTURE_ROUTES},
    OCI_CAPTURE_ROUTE: ("oci_request_signature", "oci_reply_signature"),
    "/_internal/storage/external-oci/v1": ("external_oci_request_signature", "external_oci_reply_signature"),
    "/_internal/storage/external-oci-source/v1": ("external_oci_source_request_signature", "external_oci_source_reply_signature"),
    "/_internal/storage/external-oci-cleanup/v1": ("external_oci_cleanup_request_signature", "external_oci_cleanup_reply_signature"),
}


def storage_transport_body_limit(route, side):
    if route == OCI_CAPTURE_ROUTE and side == "replyBytes":
        return 4 * 1024 * 1024 + 64 * 1024
    if route == "/_internal/storage/external-oci/v1" and side == "replyBytes":
        return 16 * 1024
    if route == "/_internal/storage/external-oci-source/v1":
        return 32 * 1024
    if route == "/_internal/storage/external-oci-cleanup/v1":
        return 16 * 1024
    return 64 * 1024

AUTHENTICATED_EVENT_ROUTES = {
    "external_copy_authenticated": COPY_CAPTURE_ROUTES,
    "oci_projection_authenticated": {OCI_CAPTURE_ROUTE: "OciDocumentProjection"},
    "external_oci_authenticated": EXTERNAL_OCI_CAPTURE_ROUTES,
}

# Two stock publications each contain 12,535 metadata objects and 3 large originals.
# Eight records per original plus 4,096 other records is an observation budget,
# not a protocol guarantee or a measured cost. Every actual row stays retained.
PROTECTED_HEADER_RECORD_LIMIT = 2 * (12_535 + 3) * 8 + 4096
PROTECTED_HEADER_LOG_BYTE_LIMIT = 512 * 1024 * 1024
PROTECTED_HEADER_ROW_BYTE_LIMIT = 48 * 1024
PROTECTED_HEADER_SUMMARY_BYTE_LIMIT = 256 * 1024 * 1024
PROTECTED_HEADER_SUMMARY_ROW_LIMIT = 2048


def begin_native_copy_capture(native, tools, native_process):
    """Pin the actual Native process and a journal cursor before the workload."""
    return json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        process = Path('/proc') / str(selected['pid'])
        before = (process / 'stat').read_text().rpartition(') ')[2].split()[19]
        with (process / 'exe').open('rb') as source:
            executable = hashlib.file_digest(source, 'sha256').hexdigest()
        if before != selected['startTicks'] or executable != selected['executableSha256']:
            raise ValueError('Native capture process differs from the actual selected lifetime')
        root = Path('/var/lib/hybrid-native-exchange-observations')
        root.mkdir(mode=0o700, exist_ok=False)
        arguments = ['journalctl', '--no-pager', '--output=json', '--output-fields=__CURSOR',
            '--unit=aos-hub.service', '-n', '1']
        result = subprocess.run(arguments, capture_output=True, check=False, timeout=20)
        for name, body in [('cursor.jsonl', result.stdout), ('cursor.stderr', result.stderr)]:
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(body)
        rows = result.stdout.splitlines()
        if result.returncode or len(rows) != 1 or len(rows[0]) > 1048576:
            raise ValueError('Native journal cursor is unavailable; diagnostics retained privately')
        cursor = json.loads(rows[0]).get('__CURSOR')
        if not isinstance(cursor, str) or not cursor or len(cursor) > 4096:
            raise ValueError('Native journal cursor differs')
        after = (process / 'stat').read_text().rpartition(') ')[2].split()[19]
        if before != after:
            raise ValueError('Native process changed while selecting its journal')
        print(json.dumps({**selected, 'executablePath': os.readlink(process / 'exe'),
            'journalCursor': cursor, 'root': str(root)}))
    """, native_process, timeout=30))


def finish_native_copy_capture(native, tools, selected):
    """Retain exact journal bytes with unchanged Native lifetime and executable."""
    observed = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        def check_process():
            process = Path('/proc') / str(selected['pid'])
            ticks = (process / 'stat').read_text().rpartition(') ')[2].split()[19]
            with (process / 'exe').open('rb') as source:
                executable = hashlib.file_digest(source, 'sha256').hexdigest()
            if (ticks != selected['startTicks'] or executable != selected['executableSha256']
                    or os.readlink(process / 'exe') != selected['executablePath']):
                raise ValueError('Native runtime changed inside the captured workload')
        check_process()
        root = Path(selected['root'])
        path = root / 'runtime.jsonl'
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        errors = os.open(root / 'runtime.stderr', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output, os.fdopen(errors, 'wb') as error:
            result = subprocess.run(['journalctl', '--no-pager', '--output=json',
                '--output-fields=__REALTIME_TIMESTAMP,_PID,_EXE,_SYSTEMD_UNIT,MESSAGE',
                r'--grep=^\\[INFO\\] message=(external_copy_authenticated|oci_projection_authenticated|external_oci_authenticated|storage_final_sql_checked|external_oci_admission_actor_checked) ',
                '--unit=aos-hub.service', '--after-cursor=' + selected['journalCursor']],
                stdout=output, stderr=error, check=False, timeout=45)
            output.flush()
            os.fsync(output.fileno())
        check_process()
        metadata = path.stat()
        if result.returncode or metadata.st_size > 64 * 1024 * 1024:
            raise ValueError('Native journal capture refused; actual bytes retained privately')
        print(json.dumps({'path': str(path), 'device': str(metadata.st_dev),
            'inode': str(metadata.st_ino), 'byteSize': 0}))
    """, selected, timeout=60))
    path, receipt = retain_direct_log_window(native, tools["python"], observed,
        "publication-native-authenticated-storage.jsonl")
    return path, receipt


def capture_protected_headers(source, label, artifact_prefix=None):
    """Stream retained rows and store only allowlisted compact controls.

    Paths are read one bounded line at a time. String inputs serve controlled
    fixtures only; the main window passes an already retained private path.
    Retained summaries have separate record and serialized-byte ceilings.
    """
    if label not in {"native-inbound", "native-outbound", "worker-received", "worker-original"}:
        raise ValueError("protected header observation role differs")
    if artifact_prefix is not None and not re.fullmatch(
            r"managed-[0-9a-f]{32}-[a-z][a-z0-9-]{0,63}", artifact_prefix):
        raise ValueError("Managed protected header artifact namespace differs")
    projected = {}
    total_bytes = summary_bytes = 0
    for line, byte_size in _protected_header_lines(source):
        total_bytes += byte_size
        if total_bytes > PROTECTED_HEADER_LOG_BYTE_LIMIT or len(projected) >= PROTECTED_HEADER_RECORD_LIMIT:
            raise ValueError("protected header corpus exceeds its bound")
        raw = _closed_review_json(line)
        if (not isinstance(raw, dict) or (raw.get("version") == "2" and set(raw) != PROTECTED_HEADER_V2_FIELDS)
                or (raw.get("version") == "3" and set(raw) != PROTECTED_HEADER_FIELDS)
                or (raw.get("version") == "4" and set(raw) != PROTECTED_HEADER_V4_FIELDS)
                or raw.get("version") not in {"2", "3", "4"}):
            raise ValueError("protected header capture shape differs")
        if (not re.fullmatch(r"[0-9a-f]{32}", raw["request_id"])
                or raw["request_id"] in projected
                or not re.fullmatch(r"(?:[0-9a-f]{32})?", raw["origin_request_id"])
                or not re.fullmatch(r"(?:[0-9a-f]{32})?", raw["transport_call_id"])
                or raw["method"] not in {"GET", "POST", "PUT", "PATCH", "HEAD", "DELETE", "OPTIONS"}
                or not re.fullmatch(r"[a-z0-9-]{0,64}", raw["phase"])
                or not re.fullmatch(r"[1-5][0-9]{2}", raw["status"])):
            raise ValueError("protected header selectors differ")
        target = raw["path_and_query"]
        if (raw["query_class"] not in {"absent", "retained", "unsupported"}
                or not isinstance(target, str)
                or (raw["query_class"] == "unsupported" and target)
                or (raw["query_class"] == "unsupported" and raw["ingress"])
                or (raw["query_class"] != "unsupported" and not target.startswith("/"))
                or len(target.encode()) > 4096
                or any(ord(value) < 32 or ord(value) == 127 for value in target)):
            raise ValueError("protected target is not bounded")
        files = {}
        for field in ("path_and_query", "ingress", "request_signature", "reply_signature",
                "oci_request_signature", "oci_reply_signature",
                *sorted(EXTERNAL_OCI_SIGNATURE_FIELDS | MANAGED_OCI_CLEANUP_SIGNATURE_FIELDS)):
            if field in MANAGED_OCI_CLEANUP_SIGNATURE_FIELDS and raw["version"] != "4":
                continue
            value = raw.get(field, "")
            if not isinstance(value, str) or len(value.encode()) > 16 * 1024:
                raise ValueError("protected compact control exceeds its bound")
            if field.endswith("signature") and value and not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError("protected control MAC framing differs")
            if field == "ingress" and value and not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value):
                raise ValueError("protected ingress compact framing differs")
            files[field] = None
            if value:
                body = value.encode()
                name = "protected-" + label + "-" + raw["request_id"] + "." + field
                if artifact_prefix is not None:
                    name = artifact_prefix + "-" + name
                digest = retain_direct_flow(name, body)
                files[field] = {"file": str(Path("external-direct-flow") / name),
                    "sha256": digest, "byteSize": len(body)}
        projected[raw["request_id"]] = {
            "requestId": raw["request_id"], "originalRequestId": raw["origin_request_id"] or None,
            "method": raw["method"], "phase": raw["phase"], "status": int(raw["status"]),
            "queryClass": raw["query_class"],
            "transportCallId": raw["transport_call_id"] or None,
            "files": files,
        }
        summary_size = len(json.dumps(projected[raw["request_id"]], separators=(",", ":")).encode())
        summary_bytes += summary_size
        if (summary_size > PROTECTED_HEADER_SUMMARY_ROW_LIMIT
                or summary_bytes > PROTECTED_HEADER_SUMMARY_BYTE_LIMIT):
            raise ValueError("protected header retained summary exceeds its bound")
    return projected


def _protected_header_lines(source):
    retained_file = isinstance(source, Path)
    stream = source.open("rb") if retained_file else io.BytesIO(source.encode())
    with stream:
        while True:
            line = stream.readline(PROTECTED_HEADER_ROW_BYTE_LIMIT + 1)
            if not line:
                return
            if len(line) > PROTECTED_HEADER_ROW_BYTE_LIMIT:
                raise ValueError("protected header row exceeds its bound")
            if retained_file and not line.endswith(b"\n"):
                raise ValueError("protected header retained row is incomplete")
            yield line.decode("utf-8"), len(line)


def observed_native_messages(source, native_process, file_provenance=None):
    """Read exact journal records or a separately pinned plain Native log.

    Plain logs expose no event wall clock. Their real file collection brackets
    remain custody observations only; no journald timestamp is manufactured.
    """
    if file_provenance is None:
        for line in source.splitlines():
            if len(line.encode()) > PROTECTED_HEADER_ROW_BYTE_LIMIT:
                raise ValueError("Native journal row exceeds its bound")
            raw = _closed_review_json(line)
            if (raw.get("_PID") != str(native_process["pid"])
                    or raw.get("_EXE") != native_process["executablePath"]
                    or raw.get("_SYSTEMD_UNIT") != "aos-hub.service"
                    or not re.fullmatch(r"[1-9][0-9]{0,19}", raw.get("__REALTIME_TIMESTAMP", ""))):
                raise ValueError("Native journal event has a foreign process")
            yield raw.get("MESSAGE"), raw["__REALTIME_TIMESTAMP"]
        return
    if (not isinstance(source, Path) or not isinstance(file_provenance, dict)
            or set(file_provenance) != {"beforeProcess", "afterProcess", "window"}):
        raise ValueError("Native plain log lacks its exact process/window provenance")
    before, after, window = (file_provenance[name] for name in (
        "beforeProcess", "afterProcess", "window"))
    for field in ("pid", "ownerUid", "startTicks", "executableSha256", "commandLineSha256",
            "commandLineBytes", "environmentSha256"):
        if before[field] != after[field] or before[field] != native_process[field]:
            raise ValueError("Native plain log process changed inside the window")
    if (window["file"] != str(source) or window["before"]["path"] != native_process["logFile"]
            or window["after"]["path"] != native_process["logFile"]
            or any(window["before"][field] != window["after"][field]
                for field in ("device", "inode"))):
        raise ValueError("Native plain log selected file/window differs")
    expected = window["capturedBytes"]
    if (type(expected) is not int or not 0 <= expected <= PROTECTED_HEADER_LOG_BYTE_LIMIT
            or expected != window["after"]["byteSize"] - window["before"]["byteSize"]):
        raise ValueError("Native plain log window length differs")
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    digest, count = hashlib.sha256(), 0
    with os.fdopen(descriptor, "rb") as stream:
        first = os.fstat(stream.fileno())
        if (not stat.S_ISREG(first.st_mode) or first.st_uid != os.geteuid()
                or first.st_mode & 0o077 or first.st_size != expected):
            raise ValueError("Native retained plain log custody differs")
        while True:
            line = stream.readline(PROTECTED_HEADER_ROW_BYTE_LIMIT + 1)
            if not line:
                break
            count += len(line)
            if (len(line) > PROTECTED_HEADER_ROW_BYTE_LIMIT or count > expected
                    or not line.endswith(b"\n")):
                raise ValueError("Native plain log row is oversized or incomplete")
            digest.update(line)
            yield line.decode().rstrip("\n"), None
        last = os.fstat(stream.fileno())
    if (count != expected or digest.hexdigest() != window["sha256"]
            or any(getattr(first, field) != getattr(last, field) for field in (
                "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
        raise ValueError("Native retained plain log changed")


def authenticated_storage_transport_receipts(text, native_process, file_provenance=None):
    """Read post-authentication events from the selected actual Native journal.

    The collector checks the process lifetime and executable on both sides of
    the journal read. A parsed event never establishes SQL or provider facts.
    """
    receipts = []
    for message, observed_at in observed_native_messages(text, native_process, file_provenance):
        selected = [("[INFO] message=" + event + " ", routes)
            for event, routes in AUTHENTICATED_EVENT_ROUTES.items()
            if isinstance(message, str) and message.startswith("[INFO] message=" + event + " ")]
        if not selected:
            continue
        prefix, routes = selected[0]
        encoded = message[len(prefix):]
        _, end = json.JSONDecoder().raw_decode(encoded)
        suffix = encoded[end:]
        if suffix and not suffix.startswith(" span="):
            raise ValueError("authenticated transport event suffix differs")
        value = _closed_review_json(encoded[:end])
        if (not isinstance(value, dict) or set(value) != STORAGE_AUTHENTICATED_FIELDS
                or type(value["version"]) is not int or value["version"] != 2
                or value["route"] not in routes
                or value["operation"] != routes[value["route"]]
                or not re.fullmatch(r"[0-9a-f]{32}", value["transportCallId"])
                or not re.fullmatch(r"[0-9a-f]{32}" if value["route"] in COPY_CAPTURE_ROUTES
                    else r"[0-9a-f]{64}", value["planId"])):
            raise ValueError("authenticated storage receipt shape differs")
        for field in ("requestSha256", "replySha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", value[field]):
                raise ValueError("authenticated storage body commitment differs")
        for field in ("requestBytes", "replyBytes"):
            maximum = storage_transport_body_limit(value["route"], field)
            if type(value[field]) is not int or not 0 <= value[field] <= maximum:
                raise ValueError("authenticated storage byte count differs")
        receipts.append({**value, "nativeCompletedAtUnixMicros": observed_at})
        if len(receipts) > PROTECTED_HEADER_RECORD_LIMIT:
            raise ValueError("authenticated storage receipt corpus exceeds its bound")
    return receipts


def join_authenticated_storage_transports(originals, received, original_headers, received_headers, receipts):
    """Join exclusive call IDs, independent bytes and existing Native MAC acceptance."""
    original_by_id = {row["requestId"]: row for row in originals}
    received_by_id = {row["requestId"]: row for row in received}
    if len(original_by_id) != len(originals) or len(received_by_id) != len(received):
        raise ValueError("Copy body ownership is ambiguous")

    # A fresh observational ID identifies each actual call independently of its
    # immutable plan/body. Reusing that ID across calls is always ambiguous.
    original_owners = {}
    for original in originals:
        header = original_headers.get(original["requestId"])
        if header is not None and header["transportCallId"] is not None:
            original_owners.setdefault(header["transportCallId"], []).append(original["requestId"])

    received_headers_by_original = {}
    for row in received_headers.values():
        received_headers_by_original.setdefault(row["originalRequestId"], []).append(row)
    receipts_by_call = {}
    for row in receipts:
        receipts_by_call.setdefault(row["transportCallId"], []).append(row)

    joined, unresolved = [], []
    for identifier, original in original_by_id.items():
        if original["procedure"] not in STORAGE_CAPTURE_ROUTES:
            # The complete boundary keeps unsupported routes for other codecs.
            unresolved.append(identifier)
            continue
        first = original_headers.get(identifier)
        candidates = received_headers_by_original.get(identifier, [])
        if first is None or len(candidates) != 1:
            unresolved.append(identifier)
            continue
        second = candidates[0]
        actual = received_by_id.get(second["requestId"])
        if actual is None or any(original["bodies"][side] is None or actual["bodies"][side] is None
                for side in ("request", "response")):
            unresolved.append(identifier)
            continue
        if any(original[field] != actual[field] for field in
                ("procedure", "method", "phase", "status", "responseContentType", "responseContentEncoding")):
            unresolved.append(identifier)
            continue
        if (original["method"] != "POST" or original["phase"] or original["status"] != 200
                or original["responseContentType"] != "application/json"
                or original["responseContentEncoding"]):
            unresolved.append(identifier)
            continue
        call_id = first["transportCallId"]
        if (call_id is None or call_id != second["transportCallId"]
                or len(original_owners[call_id]) != 1):
            unresolved.append(identifier)
            continue
        equal = True
        route_digest = hashlib.sha256(original["procedure"].encode()).hexdigest()
        equal &= first["queryClass"] == second["queryClass"] == "absent"
        signature_fields = STORAGE_SIGNATURE_FIELDS[original["procedure"]]
        for field in (*signature_fields, "path_and_query"):
            before, after = first["files"][field], second["files"][field]
            if before is None or after is None or (before["sha256"], before["byteSize"]) != (
                    after["sha256"], after["byteSize"]):
                equal = False
            if field == "path_and_query" and before is not None:
                equal &= (before["sha256"], before["byteSize"]) == (
                    route_digest, len(original["procedure"].encode()))
        for field in ("method", "phase", "status"):
            equal &= first[field] == second[field] == original[field]
        for side in ("request", "response"):
            before, after = original["bodies"][side], actual["bodies"][side]
            equal &= (before["sha256"], before["byteSize"]) == (after["sha256"], after["byteSize"])
        owned_receipts = receipts_by_call.get(call_id, [])
        matches = [row for row in owned_receipts if row["route"] == original["procedure"]
            and row["requestSha256"] == original["bodies"]["request"]["sha256"]
            and row["replySha256"] == original["bodies"]["response"]["sha256"]
            and row["requestBytes"] == original["bodies"]["request"]["byteSize"]
            and row["replyBytes"] == original["bodies"]["response"]["byteSize"]]
        if not equal or len(owned_receipts) != 1 or len(matches) != 1:
            unresolved.append(identifier)
            continue
        receipt = matches[0]
        joined.append({"nativeRequestId": identifier, "receivedRequestId": actual["requestId"],
            "operation": receipt["operation"], "planIdSha256": hashlib.sha256(receipt["planId"].encode()).hexdigest(),
            "transportCallIdSha256": hashlib.sha256(call_id.encode()).hexdigest(),
            "requestSha256": receipt["requestSha256"], "replySha256": receipt["replySha256"],
            "offeredRequestBytes": receipt["requestBytes"], "consumedReplyBytes": receipt["replyBytes"],
            "headerCommitments": first["files"],
            "completionObservationsUnixMicros": sorted({row["nativeCompletedAtUnixMicros"] for row in matches}),
            "currentActorEvidence": None, "purposeArtifactEvidence": None,
            "providerObjectPartition": None,
            "scope": "existing Native transport authenticator accepted this exact call and consumed reply; no current SQL or provider conclusion"})
    return {"version": 1, "joined": joined, "unresolvedNativeRequestIds": unresolved,
        "nativeBulkBytes": None,
        "scope": "actual original/received compact and body equality plus post-authentication consumption; complete authority/provider joins pending"}


def prepare_storage_codec_cases(transport, originals, received, source_digest, deployment_id):
    """Select private codec inputs from accepted Copy/OCI projection transport joins.

    This prepares source-bound observation inputs only. Missing actor, purpose
    and provider evidence remains missing even when a closed codec succeeds.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", source_digest):
        raise ValueError("selected runtime source commitment differs")
    original_by_id = {row["requestId"]: row for row in originals}
    received_by_id = {row["requestId"]: row for row in received}
    cases = []
    for joined in transport["joined"]:
        original = original_by_id[joined["nativeRequestId"]]
        actual = received_by_id[joined["receivedRequestId"]]
        def wire_file(value):
            return {**value, "byteSize": str(value["byteSize"])}
        cases.append({"requestId": joined["nativeRequestId"], "method": "POST",
            "pathAndQuery": original["procedure"], "phase": None, "status": 200,
            "responseContentType": actual["responseContentType"],
            "responseContentEncoding": actual["responseContentEncoding"] or None,
            "originalRequest": wire_file(original["bodies"]["request"]),
            "receivedRequest": wire_file(actual["bodies"]["request"]),
            "receivedReply": wire_file(actual["bodies"]["response"]),
            "originalIngress": None, "receivedIngress": None})
    return {"version": 1, "sourceDigest": source_digest, "deploymentId": deployment_id,
        "cases": cases} if cases else None


def prepare_storage_codec_segment_bundle(transport, originals, received, source_digest, deployment_id):
    """Account for all originals while preparing bounded positive codec pages.

    Unsupported/unjoined originals stay explicitly unresolved in the complete
    inventory. A positive subset cannot establish complete workload coverage.
    No observational page creates actor, purpose or provider evidence.
    """
    inventory = native_corpus_inventory(("outbound", row) for row in originals)
    selection = prepare_storage_codec_cases(transport, originals, received, source_digest, deployment_id)
    joined = {row["nativeRequestId"]: row for row in transport["joined"]}
    unresolved = transport["unresolvedNativeRequestIds"]
    expected = {row["requestId"] for row in originals}
    if (len(joined) != len(transport["joined"]) or len(set(unresolved)) != len(unresolved)
            or set(joined) & set(unresolved) or set(joined) | set(unresolved) != expected):
        raise ValueError("storage transport assignments omit or duplicate an original")
    bundle = None
    if selection is not None:
        selected_originals = native_corpus_inventory(("outbound", row) for row in originals
            if row["requestId"] in joined)
        ownership = [{"originalId": "outbound:" + row["requestId"],
            "receivedId": joined[row["requestId"]]["receivedRequestId"],
            "receiptIdSha256": native_corpus_receipt_identity(joined[row["requestId"]]),
            "transportCallIdSha256": joined[row["requestId"]]["transportCallIdSha256"]}
            for row in selection["cases"]]
        template = {name: value for name, value in selection.items() if name != "cases"}
        bundle = partition_native_codec_corpus(selected_originals, template, "cases", selection["cases"], ownership)
    return {"version": 1, "completeOriginalInventory": inventory,
        "selectedCodecSegments": bundle, "unresolvedNativeRequestIds": unresolved,
        "allOriginalsSelected": not unresolved, "nativeBulkBytes": None,
        "scope": "complete original assignments, including unresolved rows; positive pages alone are not workload qualification"}
