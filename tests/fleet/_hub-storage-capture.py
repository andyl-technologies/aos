"""Retain compact controls and correlate actual authenticated Copy transports.

Header values and selected journal records remain owner-private. Public numeric
projections contain commitments only. Transport acceptance is not a current SQL
actor, purpose artifact, provider partition or permission to perform new work.
"""

import hashlib
import io
import json
from pathlib import Path
import re


PROTECTED_HEADER_FIELDS = frozenset((
    "version", "request_id", "origin_request_id", "path_and_query", "method",
    "phase", "status", "ingress", "request_signature", "reply_signature", "query_class",
))
COPY_AUTHENTICATED_FIELDS = frozenset((
    "version", "route", "planId", "operation", "requestSha256", "replySha256",
    "requestBytes", "replyBytes",
))
COPY_CAPTURE_ROUTES = {
    "/_internal/storage/external-copy/v1": "external_copy_control",
    "/_internal/storage/external-copy-metadata/v1": "external_copy_metadata",
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
                r'--grep=^\\[INFO\\] message=external_copy_authenticated ',
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
        "publication-native-authenticated-copy.jsonl")
    return path, receipt


def capture_protected_headers(source, label):
    """Stream retained rows and store only allowlisted compact controls.

    Paths are read one bounded line at a time. String inputs serve controlled
    fixtures only; the main window passes an already retained private path.
    Retained summaries have separate record and serialized-byte ceilings.
    """
    if label not in {"native-inbound", "native-outbound", "worker-received"}:
        raise ValueError("protected header observation role differs")
    projected = {}
    total_bytes = summary_bytes = 0
    for line, byte_size in _protected_header_lines(source):
        total_bytes += byte_size
        if total_bytes > PROTECTED_HEADER_LOG_BYTE_LIMIT or len(projected) >= PROTECTED_HEADER_RECORD_LIMIT:
            raise ValueError("protected header corpus exceeds its bound")
        raw = _closed_review_json(line)
        if not isinstance(raw, dict) or set(raw) != PROTECTED_HEADER_FIELDS:
            raise ValueError("protected header capture shape differs")
        if (raw["version"] != "1" or not re.fullmatch(r"[0-9a-f]{32}", raw["request_id"])
                or raw["request_id"] in projected
                or not re.fullmatch(r"(?:[0-9a-f]{32})?", raw["origin_request_id"])
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
        for field in ("path_and_query", "ingress", "request_signature", "reply_signature"):
            value = raw[field]
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
                digest = retain_direct_flow(name, body)
                files[field] = {"file": str(Path("external-direct-flow") / name),
                    "sha256": digest, "byteSize": len(body)}
        projected[raw["request_id"]] = {
            "requestId": raw["request_id"], "originalRequestId": raw["origin_request_id"] or None,
            "method": raw["method"], "phase": raw["phase"], "status": int(raw["status"]),
            "queryClass": raw["query_class"],
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


def copy_authenticated_transport_receipts(text, native_process):
    """Read post-authentication events from the selected actual Native journal.

    The collector checks the process lifetime and executable on both sides of
    the journal read. A parsed event never establishes SQL or provider facts.
    """
    receipts = []
    for line in text.splitlines():
        raw = _closed_review_json(line)
        message = raw.get("MESSAGE")
        prefix = "[INFO] message=external_copy_authenticated "
        if not isinstance(message, str) or not message.startswith(prefix):
            continue
        if (raw.get("_PID") != str(native_process["pid"])
                or raw.get("_EXE") != native_process["executablePath"]
                or raw.get("_SYSTEMD_UNIT") != "aos-hub.service"
                or not re.fullmatch(r"[1-9][0-9]{0,19}", raw.get("__REALTIME_TIMESTAMP", ""))):
            raise ValueError("authenticated transport event has a foreign process")
        encoded = message[len(prefix):]
        _, end = json.JSONDecoder().raw_decode(encoded)
        suffix = encoded[end:]
        if suffix and not suffix.startswith(" span="):
            raise ValueError("authenticated transport event suffix differs")
        value = _closed_review_json(encoded[:end])
        if (not isinstance(value, dict) or set(value) != COPY_AUTHENTICATED_FIELDS
                or type(value["version"]) is not int or value["version"] != 1
                or value["route"] not in COPY_CAPTURE_ROUTES
                or value["operation"] != COPY_CAPTURE_ROUTES[value["route"]]
                or not re.fullmatch(r"[0-9a-f]{32}", value["planId"])):
            raise ValueError("authenticated Copy receipt shape differs")
        for field in ("requestSha256", "replySha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", value[field]):
                raise ValueError("authenticated Copy body commitment differs")
        for field in ("requestBytes", "replyBytes"):
            if type(value[field]) is not int or not 0 <= value[field] <= 64 * 1024:
                raise ValueError("authenticated Copy byte count differs")
        receipts.append({**value, "nativeCompletedAtUnixMicros": raw["__REALTIME_TIMESTAMP"]})
        if len(receipts) > 4096:
            raise ValueError("authenticated Copy receipt corpus exceeds its bound")
    return receipts


def join_copy_captured_transports(originals, received, original_headers, received_headers, receipts):
    """Join exact independent bytes and MACs to the existing Native authenticator."""
    original_by_id = {row["requestId"]: row for row in originals}
    received_by_id = {row["requestId"]: row for row in received}
    if len(original_by_id) != len(originals) or len(received_by_id) != len(received):
        raise ValueError("Copy body ownership is ambiguous")

    # The post-authentication event has no proxy request ID. Identical original
    # bodies therefore cannot share a receipt, even if only one call succeeded.
    original_owners = {}
    for original in originals:
        if original["procedure"] in COPY_CAPTURE_ROUTES and all(
                original["bodies"][side] is not None for side in ("request", "response")):
            commitment = _copy_body_commitment(original)
            original_owners.setdefault(commitment, []).append(original["requestId"])

    joined, unresolved = [], []
    for identifier, original in original_by_id.items():
        if original["procedure"] not in COPY_CAPTURE_ROUTES:
            # The complete boundary keeps unsupported rows; they are not Copy.
            unresolved.append(identifier)
            continue
        first = original_headers.get(identifier)
        candidates = [row for row in received_headers.values()
            if row["originalRequestId"] == identifier]
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
        if len(original_owners[_copy_body_commitment(original)]) != 1:
            unresolved.append(identifier)
            continue
        equal = True
        route_digest = hashlib.sha256(original["procedure"].encode()).hexdigest()
        equal &= first["queryClass"] == second["queryClass"] == "absent"
        for field in ("request_signature", "reply_signature", "path_and_query"):
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
        matches = [row for row in receipts if row["route"] == original["procedure"]
            and row["requestSha256"] == original["bodies"]["request"]["sha256"]
            and row["replySha256"] == original["bodies"]["response"]["sha256"]
            and row["requestBytes"] == original["bodies"]["request"]["byteSize"]
            and row["replyBytes"] == original["bodies"]["response"]["byteSize"]]
        # Multiple retained success events cannot be assigned to one exchange
        # without a per-call identifier. Preserve their actual times in the raw
        # journal and refuse the join instead of collapsing them into one event.
        if not equal or len(matches) != 1:
            unresolved.append(identifier)
            continue
        receipt = matches[0]
        joined.append({"nativeRequestId": identifier, "receivedRequestId": actual["requestId"],
            "operation": receipt["operation"], "planIdSha256": hashlib.sha256(receipt["planId"].encode()).hexdigest(),
            "requestSha256": receipt["requestSha256"], "replySha256": receipt["replySha256"],
            "offeredRequestBytes": receipt["requestBytes"], "consumedReplyBytes": receipt["replyBytes"],
            "headerCommitments": first["files"],
            "completionObservationsUnixMicros": sorted({row["nativeCompletedAtUnixMicros"] for row in matches}),
            "currentActorEvidence": None, "purposeArtifactEvidence": None,
            "providerObjectPartition": None,
            "scope": "existing Native transport authenticator accepted exact consumed reply; no current SQL or provider conclusion"})
    return {"version": 1, "joined": joined, "unresolvedNativeRequestIds": unresolved,
        "nativeBulkBytes": None,
        "scope": "actual original/received compact and body equality plus post-authentication consumption; complete authority/provider joins pending"}


def _copy_body_commitment(original):
    request = original["bodies"]["request"]
    reply = original["bodies"]["response"]
    return (original["procedure"], request["sha256"], request["byteSize"],
        reply["sha256"], reply["byteSize"])


def prepare_copy_codec_cases(transport, originals, received, source_digest, deployment_id):
    """Select private codec inputs from actual accepted Copy transport joins.

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
