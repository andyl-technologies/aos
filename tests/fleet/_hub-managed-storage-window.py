"""Retain the separate Managed pair's actual process and transport windows.

Native plain logs have no wall-clock prefix. File collection brackets and process
pins describe their custody; they never become a journald or authorization clock.
Closed body decoding remains separate from current actor, purpose and provider
evidence, even when a successful protected-handler event matches exact bytes.
"""

import hashlib
import ipaddress
import json
from pathlib import Path
import re


MANAGED_PROCESS_PIN_FIELDS = frozenset((
    "version", "pid", "ownerUid", "startTicks", "arguments", "executableSha256",
    "logFile", "environmentSha256", "commandLineSha256", "commandLineBytes",
    "invocationObservationMode",
))


def managed_window_selector(prepared, boundaries, label):
    """Select one explicit fresh pair without deriving authority from its fields."""
    selected = prepared.get("captureSelection")
    if (not isinstance(selected, dict) or set(selected) != {"run", "sourceDigest", "nativeAddress"}
            or not re.fullmatch(r"[0-9a-f]{32}", selected["run"])
            or not re.fullmatch(r"[0-9a-f]{64}", selected["sourceDigest"])
            or boundaries.get("run") != selected["run"]
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label)):
        raise ValueError("Managed window source, run or label differs")
    address = ipaddress.ip_address(selected["nativeAddress"])
    if address.version != 4 or not address.is_private or address.is_loopback:
        raise ValueError("Managed selected Native address differs")
    return dict(selected)


def observe_managed_process(machine, tools, selected):
    """Recheck the selected live executable, environment and exact invocation."""
    if (not isinstance(selected, dict) or not MANAGED_PROCESS_PIN_FIELDS <= set(selected)
            or selected["version"] != 1 or type(selected["pid"]) is not int
            or selected["pid"] <= 0 or type(selected["ownerUid"]) is not int
            or selected["invocationObservationMode"] not in {
                "original_argv", "nginx_linux_master_title"}):
        raise ValueError("Managed process pin differs")
    return json.loads(direct_guest_python(machine, tools["python"],
        DIRECT_NGINX_PROCESS_OBSERVATION + r"""
        import hashlib, os, time
        from pathlib import Path

        process = Path('/proc') / str(selected['pid'])
        before = (process / 'stat').read_text().rpartition(') ')[2].split()[19]
        if before != selected['startTicks'] or process.stat().st_uid != selected['ownerUid']:
            raise ValueError('Managed process lifetime or owner differs')
        with (process / 'exe').open('rb') as source:
            executable = hashlib.file_digest(source, 'sha256').hexdigest()
        with (process / 'cmdline').open('rb') as source:
            command = source.read(65537)
        with (process / 'environ').open('rb') as source:
            environment = source.read(262145)
        if selected['invocationObservationMode'] == 'nginx_linux_master_title':
            nginx_observed_command(command, selected['arguments'])
            with Path(selected['configurationFile']).open('rb') as source:
                configuration = source.read(65537)
            if (len(configuration) > 65536
                    or hashlib.sha256(configuration).hexdigest() != selected['configurationSha256']):
                raise ValueError('Managed proxy configuration changed')
        elif command != b''.join(value.encode() + b'\x00' for value in selected['arguments']):
            raise ValueError('Managed original invocation changed')
        if (len(command) > 65536 or len(environment) > 262144
                or executable != selected['executableSha256']
                or hashlib.sha256(command).hexdigest() != selected['commandLineSha256']
                or str(len(command)) != selected['commandLineBytes']
                or hashlib.sha256(environment).hexdigest() != selected['environmentSha256']):
            raise ValueError('Managed process executable, invocation or environment changed')
        after = (process / 'stat').read_text().rpartition(') ')[2].split()[19]
        if before != after:
            raise ValueError('Managed process changed during observation')
        print(json.dumps({'pid': selected['pid'], 'ownerUid': selected['ownerUid'],
            'startTicks': after, 'executableSha256': executable,
            'commandLineSha256': selected['commandLineSha256'],
            'commandLineBytes': str(len(command)),
            'environmentSha256': selected['environmentSha256'],
            'observedAtUnixMicros': str(time.time_ns() // 1000)}))
        """, selected, timeout=30))


def managed_private_log_position(machine, tools, path):
    """Pin a no-follow owner-private regular log before selecting its suffix."""
    return json.loads(direct_guest_python(machine, tools["python"], """
        import os, stat, time
        from pathlib import Path

        descriptor = os.open(selected['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            metadata = os.fstat(source.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or metadata.st_mode & 0o077):
                raise ValueError('Managed log custody differs')
        print(json.dumps({'path': selected['path'], 'device': str(metadata.st_dev),
            'inode': str(metadata.st_ino), 'byteSize': metadata.st_size,
            'collectedAtUnixMicros': str(time.time_ns() // 1000)}))
    """, {"path": path}))


def begin_managed_storage_window(native, worker, tools, prepared, processes, boundaries, label):
    """Pin all four processes and actual private log offsets before the actions."""
    selected = managed_window_selector(prepared, boundaries, label)
    if set(processes) != {"native", "worker", "nativeProxy", "workerProxy"}:
        raise ValueError("Managed complete process selection differs")
    observations = {}
    for role, machine in (("native", native), ("worker", worker),
            ("nativeProxy", native), ("workerProxy", worker)):
        if role.endswith("Proxy"):
            expected = boundaries[role]
            if (processes[role]["arguments"] != expected["arguments"]
                    or processes[role].get("configurationFile") != expected["configurationFile"]
                    or processes[role].get("configurationSha256") != expected["configurationSha256"]):
                raise ValueError("Managed launched proxy differs from its prepared configuration")
        observations[role] = observe_managed_process(machine, tools, processes[role])
    run = selected["run"]
    native_root = "/var/lib/hybrid-managed-native/" + run
    worker_root = "/var/lib/hybrid-managed-worker/" + run
    if (processes["native"]["logFile"] != native_root + "/native-accepted.log"
            or processes["worker"]["logFile"] != worker_root + "/worker.log"):
        raise ValueError("Managed selected main process log differs")
    positions = {}
    for name, machine, path in (
            ("nativeOutbound", native, native_root + "/outbound/requests.jsonl"),
            ("workerReceived", worker, worker_root + "/boundary/requests.jsonl"),
            ("nativeHeaders", native, native_root + "/outbound/protected-headers.jsonl"),
            ("workerHeaders", worker, worker_root + "/boundary/protected-headers.jsonl"),
            ("workerOriginal", worker, worker_root + "/native-outbound/requests.jsonl"),
            ("workerOriginalHeaders", worker, worker_root + "/native-outbound/protected-headers.jsonl"),
            ("nativeReceived", native, native_root + "/inbound/requests.jsonl"),
            ("nativeReceivedHeaders", native, native_root + "/inbound/protected-headers.jsonl"),
            ("nativeLog", native, processes["native"]["logFile"]),
            ("workerLog", worker, processes["worker"]["logFile"])):
        positions[name] = managed_private_log_position(machine, tools, path)
    token = {"version": 1, "selection": selected, "label": label,
        "processes": processes, "beforeProcesses": observations, "positions": positions}
    retain_direct_flow("managed-" + run + "-" + label + "-window-begin.json", token)
    return token


def finish_managed_storage_window(native, worker, tools, prepared, processes, boundaries, token, label):
    """Retain the fixed actual window and its independently received body joins."""
    selected = managed_window_selector(prepared, boundaries, label)
    if (token.get("version") != 1 or token.get("selection") != selected
            or token.get("label") != label or token.get("processes") != processes):
        raise ValueError("Managed window original selection changed")
    prefix = "managed-" + selected["run"] + "-" + label
    paths, receipts, observations = {}, {}, {}
    for role, machine in (("native", native), ("worker", worker),
            ("nativeProxy", native), ("workerProxy", worker)):
        observations[role] = observe_managed_process(machine, tools, processes[role])
    for name, before in token["positions"].items():
        machine = native if name.startswith("native") else worker
        current = managed_private_log_position(machine, tools, before["path"])
        if any(before[field] != current[field] for field in ("device", "inode")):
            raise ValueError("Managed observation log was replaced")
        path, receipt = retain_direct_log_window(machine, tools["python"], before,
            prefix + "-" + name + ".jsonl")
        paths[name] = path
        receipts[name] = {**receipt, "collectionStartedAtUnixMicros": before["collectedAtUnixMicros"],
            "collectionFinishedAtUnixMicros": current["collectedAtUnixMicros"]}
    for role, machine in (("native", native), ("worker", worker),
            ("nativeProxy", native), ("workerProxy", worker)):
        observations[role] = observe_managed_process(machine, tools, processes[role])
    worker_text = paths["workerLog"].read_text()
    boundary = capture_direct_storage_boundary(native, worker, tools,
        paths["nativeOutbound"].read_text(), paths["workerReceived"].read_text(),
        worker_text, selected["sourceDigest"], selected["nativeAddress"],
        managed_run=selected["run"], artifact_label=label)
    boundary["captureProvenance"] = {"sourceDigest": selected["sourceDigest"],
        "nativeExecutableSha256": observations["native"]["executableSha256"],
        "run": selected["run"], "deploymentId": tools["deploymentId"],
        "rawWindowReceiptsSha256": hashlib.sha256(native_corpus_json(receipts)).hexdigest()}
    file_provenance = {"beforeProcess": token["beforeProcesses"]["native"],
        "afterProcess": observations["native"],
        "window": {"file": str(paths["nativeLog"]), **receipts["nativeLog"]}}
    native_headers = capture_protected_headers(paths["nativeHeaders"], "native-outbound", prefix)
    worker_headers = capture_protected_headers(paths["workerHeaders"], "worker-received", prefix)
    authenticated_rows = authenticated_storage_transport_receipts(
        paths["nativeLog"], processes["native"], file_provenance)
    context_rows = storage_final_sql_receipts(paths["nativeLog"], processes["native"], file_provenance)
    transport = join_authenticated_storage_transports(
        boundary["nativeOriginalBodies"]["bodies"], boundary["workerReceivedBodies"]["bodies"],
        native_headers, worker_headers,
        authenticated_rows)
    final_sql = join_storage_final_sql(transport, context_rows)
    final_sql["externalAdmissionActorObservations"] = join_external_admission_actor(final_sql,
        external_admission_actor_receipts(paths["nativeLog"], processes["native"], file_provenance))
    ingress = capture_managed_native_ingress(native, worker, tools, boundaries,
        paths, selected, label, prefix)
    ingress["decoded"] = None
    if ingress["codecInput"]["selectedCodecSegments"] is not None:
        if boundaries.get("codecSelection") is None or boundaries.get("codecProvenance") is None:
            ingress["codecRefusal"] = "current_selected_codec_missing"
        else:
            provenance = validate_managed_codec_selection(boundaries["codecSelection"],
                boundaries["codecProvenance"], selected["sourceDigest"],
                observations["native"]["executableSha256"])
            ingress["decoded"] = run_storage_workflow_codec_segments(boundaries["codecSelection"],
                ingress["codecInput"]["selectedCodecSegments"], provenance["codecSourceSha256"],
                selected["sourceDigest"], artifact_namespace="managed-codec-" + label + "-" + selected["run"])
    report = {"version": 1, "storageBoundary": boundary, "workerLogText": worker_text,
        "rawWindowReceipts": {name: {"file": str(paths[name]), **receipt}
            for name, receipt in receipts.items()}, "processObservations": observations,
        "nativeAuthenticatedTransports": transport, "nativeFinalContextObservations": final_sql,
        "nativeServiceAuthenticatedRows": authenticated_rows, "nativeServiceFinalSqlRows": context_rows,
        "nativeIngressBoundary": ingress,
        "nativeBulkBytes": None,
        "scope": "actual separate Managed transport/log window; no actor, purpose, provider or zero conclusion"}
    retain_direct_flow(prefix + "-window-finish.json", {
        **report, "workerLogText": None,
        "scope": report["scope"] + "; raw Worker text remains in the private referenced file"})
    return report


def validate_managed_codec_selection(selection, expected, source_digest, executable_digest):
    """Bind the held selected decoder provenance to the actual observed pair."""
    provenance = _closed_review_json(direct_selected_bytes(selection["runtimeProvenance"], 65536))
    fields = {"version", "runtimeCodecRevision", "nativeExecutableSha256", "workerSourceDigest",
        "sourceArchiveSha256", "codecSourceSha256"}
    if (not isinstance(provenance, dict) or set(provenance) != fields or provenance != expected
            or type(provenance["version"]) is not int or provenance["version"] != 1
            or not re.fullmatch(r"[0-9a-f]{40}", provenance["runtimeCodecRevision"])
            or provenance["nativeExecutableSha256"] != executable_digest
            or provenance["workerSourceDigest"] != source_digest
            or any(not re.fullmatch(r"[0-9a-f]{64}", provenance[field]) for field in
                ("nativeExecutableSha256", "workerSourceDigest", "sourceArchiveSha256", "codecSourceSha256"))):
        raise ValueError("Managed selected codec provenance differs from the actual pair")
    return provenance


def managed_ingress_completion_receipts(text, received=False):
    """Separate actual completed transfer facts from proxy completion UTC."""
    normalized, evidence = [], {}
    for line in text.splitlines():
        if len(line.encode()) > 48 * 1024:
            raise ValueError("Managed ingress record exceeds its row bound")
        row = _closed_review_json(line)
        if not isinstance(row, dict) or not {"request_completion", "upstream_response_bytes"} <= set(row):
            raise ValueError("Managed ingress transfer observations are missing")
        completed, count = row.pop("request_completion"), row.pop("upstream_response_bytes")
        if (completed not in {"", "OK"} or not isinstance(count, str)
                or not re.fullmatch(r"-|0|[1-9][0-9]{0,19}", count)):
            raise ValueError("Managed ingress transfer observation differs")
        identifier = row.get("request_id")
        if identifier in evidence:
            raise ValueError("Managed ingress transfer request ownership is ambiguous")
        evidence[identifier] = {"requestCompletion": completed,
            "upstreamResponseBytes": None if count == "-" else int(count)}
        normalized.append(json.dumps(row))
    rows, clocks = direct_storage_completion_receipts("\n".join(normalized), received)
    return rows, clocks, evidence


def capture_managed_native_ingress(native, worker, tools, boundaries, paths, selected, label, prefix):
    """Retain independent Worker originals and Native received application bytes.

    Fixture request IDs establish exclusive capture ownership only. Compact
    ingress equality and shared decoding do not verify IAM, a MAC or a purpose.
    Every received row and unsupported original remains in the private corpus.
    """
    run = selected["run"]
    worker_root = "/var/lib/hybrid-managed-worker/" + run + "/native-outbound"
    native_root = "/var/lib/hybrid-managed-native/" + run + "/inbound"
    original_rows, original_completed, original_transfer = managed_ingress_completion_receipts(
        paths["workerOriginal"].read_text())
    received_rows, received_completed, received_transfer = managed_ingress_completion_receipts(
        paths["nativeReceived"].read_text(), True)
    originals = native_control_observations(
        "\n".join(json.dumps(row) for row in original_rows), worker_root)
    correlations, normalized = {}, []
    for row in received_rows:
        origin, caller = row.pop("origin_request_id"), row.pop("caller")
        normalized.append(row)
        if caller == boundaries["workerAddress"]:
            if not re.fullmatch(r"[0-9a-f]{32}", origin):
                raise ValueError("Managed Worker original correlation is missing")
            correlations.setdefault(origin, []).append(row["request_id"])
    received = native_control_observations(
        "\n".join(json.dumps(row) for row in normalized), native_root)
    _, original_bodies = capture_direct_native_bodies(worker, tools, originals,
        worker_root, prefix + "-worker-original", empty_response_observations=original_transfer)
    _, received_bodies = capture_direct_native_bodies(native, tools, received,
        native_root, prefix + "-native", empty_response_observations=received_transfer)
    original_headers = capture_protected_headers(paths["workerOriginalHeaders"], "worker-original", prefix)
    received_headers = capture_protected_headers(paths["nativeReceivedHeaders"], "native-inbound", prefix)
    projection = prepare_managed_ingress_codec_segments(original_bodies["bodies"],
        received_bodies["bodies"], correlations, original_headers, received_headers,
        selected["sourceDigest"], tools["deploymentId"])
    return {"version": 1, "workerOriginalBodies": original_bodies,
        "nativeReceivedBodies": received_bodies, "codecInput": projection,
        "workerProxyCompletionObservations": original_completed,
        "nativeProxyCompletionObservations": received_completed,
        "nativeBulkBytes": None,
        "scope": "independent application bytes and shape-only ingress correlation; no authenticated actor/purpose/provider conclusion"}


def prepare_managed_ingress_codec_segments(originals, received, correlations,
        original_headers, received_headers, source_digest, deployment_id):
    """Prepare bounded exact byte/compact pairs without accepting their signatures."""
    received_by_id = {row["requestId"]: row for row in received}
    if len(received_by_id) != len(received):
        raise ValueError("Managed received request ownership is ambiguous")
    original_ids = {row["requestId"] for row in originals}
    if len(original_ids) != len(originals):
        raise ValueError("Managed original ownership is ambiguous")
    all_inventory = native_corpus_inventory(
        [("outbound", row) for row in originals] + [("inbound", row) for row in received]
    ) if originals or received else None
    cases, ownership, selected_originals, unresolved, used = [], [], [], [], set()
    for original in originals:
        identifier = original["requestId"]
        matches = correlations.get(identifier, [])
        actual = received_by_id.get(matches[0]) if len(matches) == 1 else None
        before = original_headers.get(identifier)
        after = received_headers.get(actual["requestId"]) if actual else None
        valid = actual is not None and actual["requestId"] not in used and before is not None and after is not None
        if valid:
            valid = (after["originalRequestId"] == identifier
                and all(original[field] == actual[field] for field in
                    ("procedure", "method", "phase", "status", "responseContentType", "responseContentEncoding"))
                and all(before[field] == after[field] for field in ("method", "phase", "status", "queryClass"))
                and all(before[field] == original[field] for field in ("method", "phase", "status"))
                and before["queryClass"] != "unsupported")
        for direction in ("request", "response"):
            left = original["bodies"].get(direction)
            right = actual["bodies"].get(direction) if actual else None
            valid = valid and left is not None and right is not None and all(
                left[field] == right[field] for field in ("sha256", "byteSize"))
        for field in ("path_and_query", "ingress"):
            left = before["files"].get(field) if before else None
            right = after["files"].get(field) if after else None
            valid = valid and left is not None and right is not None and all(
                left[key] == right[key] for key in ("sha256", "byteSize"))
        if not valid:
            unresolved.append(identifier)
            continue
        target = direct_selected_bytes({"path": before["files"]["path_and_query"]["file"],
            "sha256": before["files"]["path_and_query"]["sha256"]}, 4096).decode()
        if target.split("?", 1)[0] != original["procedure"] or not target.startswith("/v2/"):
            unresolved.append(identifier)
            continue
        used.add(actual["requestId"])
        def reference(value):
            return {**value, "byteSize": str(value["byteSize"])}
        cases.append({"requestId": identifier, "method": original["method"],
            "pathAndQuery": target, "phase": original["phase"] or None, "status": original["status"],
            "responseContentType": actual["responseContentType"] or None,
            "responseContentEncoding": actual["responseContentEncoding"] or None,
            "originalRequest": reference(original["bodies"]["request"]),
            "receivedRequest": reference(actual["bodies"]["request"]),
            "receivedReply": reference(actual["bodies"]["response"]),
            "originalIngress": reference(before["files"]["ingress"]),
            "receivedIngress": reference(after["files"]["ingress"])})
        selected_originals.append(("outbound", original))
        ownership.append({"originalId": "outbound:" + identifier,
            "receivedId": actual["requestId"], "receiptIdSha256": None,
            "transportCallIdSha256": None})
    bundle = partition_native_codec_corpus(native_corpus_inventory(selected_originals),
        {"version": 1, "sourceDigest": source_digest, "deploymentId": deployment_id},
        "cases", cases, ownership) if cases else None
    return {"version": 1, "completeOriginalInventory": all_inventory,
        "selectedCodecSegments": bundle, "unresolvedOriginalRequestIds": unresolved,
        "unselectedReceivedRequestIds": sorted(set(received_by_id) - used),
        "nativeBulkBytes": None,
        "scope": "exclusive original/received byte equality only; successful codec shapes do not authenticate signatures or current permission"}


def classify_managed_storage_capture(capture, storage_boundary, label, codec_selection, codec_provenance):
    """Execute the selected current shared codec before returning typed GC bodies.

    The returned receipt describes a real local decoder invocation over the
    captured bytes. Authentication and current action SQL must be joined by the
    caller; the decoder performs structural/correlation validation only.
    """
    if (not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label)
            or not re.fullmatch(r"[0-9a-f]{32}", capture["requestId"])
            or capture["procedure"] != "/_internal/storage/v1/execute"
            or "storageWorkSelection" not in capture
            or capture not in storage_boundary["captures"]):
        raise ValueError("Managed selected execute capture differs")
    pins = storage_boundary.get("captureProvenance")
    provenance = _closed_review_json(direct_selected_bytes(codec_selection["runtimeProvenance"], 65536))
    if (not isinstance(pins, dict) or provenance != codec_provenance
            or set(provenance) != {"version", "runtimeCodecRevision", "nativeExecutableSha256",
                "workerSourceDigest", "sourceArchiveSha256", "codecSourceSha256"}
            or type(provenance["version"]) is not int or provenance["version"] != 1
            or not re.fullmatch(r"[0-9a-f]{40}", provenance["runtimeCodecRevision"])
            or provenance["workerSourceDigest"] != pins["sourceDigest"]
            or provenance["nativeExecutableSha256"] != pins["nativeExecutableSha256"]
            or any(not re.fullmatch(r"[0-9a-f]{64}", provenance[field])
                for field in ("sourceArchiveSha256", "codecSourceSha256"))):
        raise ValueError("Managed codec does not match the captured current runtime tuple")
    completions = [row for row in storage_boundary["authenticatedCompletions"]
        if row["requestId"] == capture["requestId"]]
    if len(completions) != 1:
        raise ValueError("Managed exact protected handler completion is missing or ambiguous")
    completion = completions[0]
    original = capture["storageWorkSelection"]["originalPlan"]
    request, reply = capture["bodies"]["request"], capture["bodies"]["response"]
    def reference(body):
        return {"file": str(Path(body["file"]).resolve()), "sha256": body["sha256"],
            "byteSize": str(body["byteSize"])}
    case = {"requestId": capture["requestId"], "method": capture["method"],
        "pathAndQuery": capture["procedure"], "phase": capture["phase"] or None,
        "status": capture["status"], "responseContentType": capture["responseContentType"] or None,
        "responseContentEncoding": capture["responseContentEncoding"] or None,
        "originalRequest": reference(original), "receivedRequest": reference(request),
        "receivedReply": reference(reply), "originalIngress": None, "receivedIngress": None}
    manifest = {"version": 1, "sourceDigest": pins["sourceDigest"],
        "deploymentId": pins["deploymentId"], "cases": [case]}
    prefix = "managed-codec-" + label + "-" + capture["requestId"]
    manifest_sha = retain_direct_flow(prefix + "-selection.json", native_corpus_json(manifest))
    observed = run_direct_native_codec_observer(codec_selection,
        Path("external-direct-flow") / (prefix + "-selection.json"), artifact_prefix=prefix)
    if not isinstance(observed, list) or len(observed) != 1:
        raise ValueError("Managed codec omitted the selected original")
    row = observed[0]
    if (not isinstance(row, dict) or set(row) != STORAGE_CODEC_ROW_FIELDS
            or row["requestId"] != capture["requestId"]
            or row["sourceDigest"] != pins["sourceDigest"]
            or row["codecSourceSha256"] != provenance["codecSourceSha256"]
            or row["class"] not in {"storage_work_gc_metadata", "storage_work_not_found_metadata"}
            or row["operation"] != completion["operation"]
            or row["requestSha256"] != request["sha256"]
            or row["replySha256"] != reply["sha256"]
            or row["exchangeIdSha256"] != completion["planIdSha256"]
            or row["originalContextSha256"] != original["sha256"]
            or row["payload"] != {"requestRawObjectBytes": "0", "replyRawObjectBytes": "0",
                "selectedDataBytes": "0", "semanticOciProjectionBytes": "0"}
            or (completion["requestSha256"], completion["replySha256"],
                completion["requestBytes"], completion["replyBytes"]) != (
                request["sha256"], reply["sha256"], int(request["byteSize"]), int(reply["byteSize"]))):
        raise ValueError("Managed shared codec/handler/source/body projection differs")
    # Reopen with the same private custody/hash/count checks after the actual
    # codec succeeds. The caller independently joins its authoritative action.
    def body_bytes(body):
        raw = direct_selected_bytes({"path": body["file"], "sha256": body["sha256"]},
            WORKER_CONTROL_REPLY_LIMIT)
        if len(raw) != int(body["byteSize"]):
            raise ValueError("Managed consumed body size changed after decoding")
        return raw
    original_bytes, request_bytes, reply_bytes = body_bytes(original), body_bytes(request), body_bytes(reply)
    if original_bytes != request_bytes:
        raise ValueError("Managed original and received plan differ after decoding")
    receipt = {"version": 1, "manifestSha256": manifest_sha,
        "sourceDigest": pins["sourceDigest"], "codecRevision": provenance["runtimeCodecRevision"],
        "codecSourceSha256": provenance["codecSourceSha256"],
        "executableSha256": codec_selection["observerExecutable"]["sha256"],
        "provenanceSha256": codec_selection["runtimeProvenance"]["sha256"],
        "requestSha256": request["sha256"], "replySha256": reply["sha256"],
        "requestBytes": str(len(request_bytes)), "replyBytes": str(len(reply_bytes)),
        "exitCode": 0, "observation": row,
        "scope": "actual shared structural decoder invocation; no HMAC, action SQL or permission claim"}
    retain_direct_flow(prefix + "-classification.json", receipt)
    return {"version": 1, "plan": _closed_review_json(request_bytes),
        "result": _closed_review_json(reply_bytes), "validationReceipt": receipt,
        "originalPlan": reference(original), "request": reference(request), "reply": reference(reply),
        "handlerCompletion": completion, "nativeBulkBytes": None}
