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
    if (not isinstance(selected, dict) or set(selected) not in ({"run", "sourceDigest", "nativeAddress"},
                {"run", "sourceDigest", "nativeAddress", "kind", "nativeRole"})
            or not re.fullmatch(r"[0-9a-f]{32}", selected["run"])
            or not re.fullmatch(r"[0-9a-f]{64}", selected["sourceDigest"])
            or boundaries.get("run") != selected["run"]
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label)):
        raise ValueError("Managed window source, run or label differs")
    if "kind" in selected and (selected["kind"] != "external_oci"
            or selected["nativeRole"] not in {"ordinary_native", "controlled_external_oci_native"}):
        raise ValueError("External window process role differs")
    address = ipaddress.ip_address(selected["nativeAddress"])
    if address.version != 4 or not address.is_private or address.is_loopback:
        raise ValueError("Managed selected Native address differs")
    return dict(selected)


def selected_storage_window_roots(selected):
    """Resolve only the two fixed, independently configured fixture layouts."""
    run = selected["run"]
    if selected.get("kind") == "external_oci":
        return {"native": "/var/lib/hybrid-native/external-oci/" + run,
            "worker": "/var/lib/hybrid-worker/external-oci/" + run,
            "prefix": "external-oci-" + run}
    return {"native": "/var/lib/hybrid-managed-native/" + run,
        "worker": "/var/lib/hybrid-managed-worker/" + run, "prefix": "managed-" + run}


def validate_selected_storage_logs(selected, processes, roots):
    """Bind a separate helper lifetime to its own log without service relabeling."""
    native_log = processes["native"]["logFile"]
    worker_log = processes["worker"]["logFile"]
    if selected.get("kind") == "external_oci":
        native_label = ("native-bootstrap" if selected["nativeRole"] == "ordinary_native"
            else "native-controlled")
        allowed_workers = {"worker-bootstrap", "external-oci-installed", "external-oci-final"}
        valid = native_log == roots["native"] + "/" + native_label + ".log" and any(
            worker_log == roots["worker"] + "/" + label + ".log" for label in allowed_workers)
    else:
        valid = (native_log == roots["native"] + "/native-accepted.log"
            and worker_log == roots["worker"] + "/worker.log")
    if not valid:
        raise ValueError("Selected storage process role or actual log differs")


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
    roots = selected_storage_window_roots(selected)
    native_root, worker_root = roots["native"], roots["worker"]
    validate_selected_storage_logs(selected, processes, roots)
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
    retain_direct_flow(roots["prefix"] + "-" + label + "-window-begin.json", token)
    return token


def finish_managed_storage_window(native, worker, tools, prepared, processes, boundaries, token, label):
    """Retain the fixed actual window and its independently received body joins."""
    selected = managed_window_selector(prepared, boundaries, label)
    if (token.get("version") != 1 or token.get("selection") != selected
            or token.get("label") != label or token.get("processes") != processes):
        raise ValueError("Managed window original selection changed")
    prefix = selected_storage_window_roots(selected)["prefix"] + "-" + label
    codec_scope = "external-oci" if selected.get("kind") == "external_oci" else "managed"
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
        managed_run=selected["run"] if "kind" not in selected else None,
        external_run=selected["run"] if selected.get("kind") == "external_oci" else None,
        artifact_label=label)
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
    outbound_codec = prepare_managed_outbound_codec_segments(
        boundary["nativeOriginalBodies"]["bodies"], boundary["workerReceivedBodies"]["bodies"],
        native_headers, worker_headers, selected["sourceDigest"], tools["deploymentId"])
    outbound_decoded, execute_observed = None, None
    if outbound_codec["selectedCodecSegments"] is not None:
        if boundaries.get("codecSelection") is not None and boundaries.get("codecProvenance") is not None:
            provenance = validate_managed_codec_selection(boundaries["codecSelection"],
                boundaries["codecProvenance"], selected["sourceDigest"],
                observations["native"]["executableSha256"])
            outbound_decoded = run_storage_workflow_codec_segments(boundaries["codecSelection"],
                outbound_codec["selectedCodecSegments"], provenance["codecSourceSha256"],
                selected["sourceDigest"], artifact_namespace=codec_scope + "-outbound-" + label + "-" + selected["run"])
            records = storage_work_execute_receipts(paths["nativeLog"], processes["native"], file_provenance)
            execute_observed = join_storage_work_execute(
                boundary["nativeOriginalBodies"]["bodies"], boundary["workerReceivedBodies"]["bodies"],
                native_headers, worker_headers, records,
                outbound_decoded["observations"] if outbound_decoded.get("complete") is True else [],
                selected["sourceDigest"], provenance["codecSourceSha256"])
    final_sql["externalAdmissionActorObservations"] = join_external_admission_actor(final_sql,
        external_admission_actor_receipts(paths["nativeLog"], processes["native"], file_provenance))
    ingress = capture_managed_native_ingress(native, worker, tools, boundaries,
        paths, selected, label, prefix)
    sources = boundaries.get("ingressObservationSources")
    ingress["applicationObservations"] = None
    if sources is not None:
        rows = ingress_application_observations(paths["nativeLog"], processes["native"],
            file_provenance, sources)
        def read_actual_body(reference):
            raw = direct_selected_bytes({"path": reference["file"], "sha256": reference["sha256"]},
                max(WORKER_CONTROL_REPLY_LIMIT, 4 * 1024 * 1024))
            if len(raw) != int(reference["byteSize"]):
                raise ValueError("Managed ingress captured body size changed")
            return raw
        ingress["applicationObservations"] = join_ingress_application_observations(
            ingress["workerOriginalBodies"]["bodies"], ingress["nativeReceivedBodies"]["bodies"],
            ingress["originalHeaders"], ingress["receivedHeaders"], rows, read_actual_body)
        ingress["applicationObservationProvenance"] = file_provenance
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
                selected["sourceDigest"], artifact_namespace=codec_scope + "-codec-" + label + "-" + selected["run"])
    report = {"version": 1, "storageBoundary": boundary, "workerLogText": worker_text,
        "rawWindowReceipts": {name: {"file": str(paths[name]), **receipt}
            for name, receipt in receipts.items()}, "processObservations": observations,
        "nativeAuthenticatedTransports": transport, "nativeFinalContextObservations": final_sql,
        "nativeServiceAuthenticatedRows": authenticated_rows, "nativeServiceFinalSqlRows": context_rows,
        "nativeIngressBoundary": ingress,
        "nativeOutboundCodecInput": outbound_codec, "nativeOutboundDecoded": outbound_decoded,
        "nativeExecuteObservations": execute_observed,
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
    roots = selected_storage_window_roots(selected)
    worker_root = roots["worker"] + "/native-outbound"
    native_root = roots["native"] + "/inbound"
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
        "originalHeaders": original_headers, "receivedHeaders": received_headers,
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
        if target.split("?", 1)[0] != original["procedure"]:
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


INGRESS_EVENT_PREFIX = "[INFO] message=native_ingress_application_body_observation "
INGRESS_EVENT_FIELDS = frozenset((
    "version", "requestId", "method", "pathSha256", "compactSha256", "originalSha256", "phase",
    "nativeHandlerSourceSha256", "checkedContextSourceSha256", "envelopeAuthenticated",
    "bodyAuthenticated", "stage", "status", "checkedContexts", "requestConsumed", "replyOffered",
    "completedAtUnixMicros",
))
INGRESS_CHECK_KINDS = frozenset((
    "permission_read", "permission_publish", "oci_actor_current", "oci_manifest_catalog_current",
    "oci_chunk_catalog_current", "oci_public_pull_policy", "oci_repository_grant",
    "registry_public_read_policy", "cache_public_read_policy", "registry_session_read",
    "cache_session_read", "browse_registry_read_policy", "browse_session_read",
))
INGRESS_EVENT_STAGES = frozenset((
    "cancelled", "envelope_refused", "body_limit_refused", "request_body_failed", "body_mac_refused",
    "transport_context_refused", "delivery_signing_refused", "handler_completed",
))


def validate_ingress_application_observation(value, expected_sources):
    """Validate a closed observation, never an authorization request or proof."""
    def require(condition):
        if not condition:
            raise ValueError("Native ingress application observation differs")

    def digest(value):
        return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None

    def decimal(value):
        return isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is not None

    require(isinstance(expected_sources, dict) and set(expected_sources) == {
        "nativeHandlerSourceSha256", "checkedContextSourceSha256"}
        and all(digest(item) for item in expected_sources.values()))
    require(isinstance(value, dict) and set(value) == INGRESS_EVENT_FIELDS
        and type(value["version"]) is int and value["version"] == 1
        and (value["requestId"] is None or isinstance(value["requestId"], str)
             and re.fullmatch(r"[0-9a-f]{32}", value["requestId"]))
        and value["method"] in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
        and digest(value["pathSha256"])
        and all(value[field] == selected for field, selected in expected_sources.items())
        and all(value[field] is None or digest(value[field])
                for field in ("compactSha256", "originalSha256"))
        and (value["phase"] is None or value["phase"] in {
            "authorize", "authorize-final", "preflight", "complete"})
        and value["stage"] in INGRESS_EVENT_STAGES
        and (value["status"] is None or type(value["status"]) is int and 100 <= value["status"] <= 599)
        and decimal(value["completedAtUnixMicros"]))
    require(all(type(value[field]) is bool for field in ("envelopeAuthenticated", "bodyAuthenticated")))
    require(not value["bodyAuthenticated"] or value["envelopeAuthenticated"])
    for name in ("requestConsumed", "replyOffered"):
        frames = value[name]
        require(isinstance(frames, dict) and set(frames) == {
            "exposedBytes", "exposedSha256", "eof", "failed", "overflow"}
            and decimal(frames["exposedBytes"]) and digest(frames["exposedSha256"])
            and all(type(frames[field]) is bool for field in ("eof", "failed", "overflow")))
    checked = value["checkedContexts"]
    require(checked is None or isinstance(checked, dict) and set(checked) == {"checks", "incomplete"}
        and type(checked["incomplete"]) is bool and isinstance(checked["checks"], list)
        and len(checked["checks"]) <= 32)
    if checked is not None:
        for item in checked["checks"]:
            require(isinstance(item, dict) and set(item) == {
                "kind", "accepted", "checkedContextSha256", "observedAtUnixMicros"}
                and item["kind"] in INGRESS_CHECK_KINDS and type(item["accepted"]) is bool
                and digest(item["checkedContextSha256"]) and decimal(item["observedAtUnixMicros"])
                and int(item["observedAtUnixMicros"]) <= int(value["completedAtUnixMicros"]))
    if value["stage"] == "handler_completed":
        require(value["envelopeAuthenticated"] and value["bodyAuthenticated"]
            and checked is not None and value["status"] is not None)
    return value


def ingress_application_observations(path, process, provenance, expected_sources):
    """Read all actual events from the independently pinned process/log window.

    The existing reader verifies file custody and the unchanged process at both
    collection boundaries. The source selection must come from the reviewed
    common artifact tuple; it is not an actor or provider authorization flag.
    """
    rows, retained_bytes = [], 2
    for message, _ in observed_native_messages(path, process, provenance):
        if not message.startswith(INGRESS_EVENT_PREFIX):
            continue
        encoded = message[len(INGRESS_EVENT_PREFIX):]
        _, end = json.JSONDecoder().raw_decode(encoded)
        if encoded[end:] and not encoded[end:].startswith(" span="):
            raise ValueError("Native ingress event has an unsupported suffix")
        value = validate_ingress_application_observation(_closed_review_json(encoded[:end]), expected_sources)
        retained_bytes += len(native_corpus_json(value)) + 1
        if len(rows) >= 204704 or retained_bytes > 256 * 1024 * 1024:
            raise ValueError("Native ingress event summaries exceed their observation bound")
        rows.append(value)
    return rows


def join_ingress_application_observations(originals, received, original_headers, received_headers,
                                           observations, read_body):
    """Join exclusive actual frames to two independent application transports.

    Native offered reply frames never stand for Worker-received bytes. Refused,
    unread and partial observations remain distinct; an event cannot authorize
    another identical call or be reused for a second original.
    """
    by_id, by_original, by_event = {}, {}, {}
    for row in received:
        if row["requestId"] in by_id:
            raise ValueError("Native received ingress identity is repeated")
        by_id[row["requestId"]] = row
    for header in received_headers.values():
        by_original.setdefault(header["originalRequestId"], []).append(header)
    for row in observations:
        by_event.setdefault(row["requestId"], []).append(row)
    if len({row["requestId"] for row in originals}) != len(originals):
        raise ValueError("Worker original ingress identity is repeated")
    joined, unresolved, used = [], [], set()
    for original in originals:
        identity = original["requestId"]
        candidates, events = by_original.get(identity, []), by_event.get(identity, [])
        first = original_headers.get(identity)
        if first is None or len(candidates) != 1 or len(events) != 1:
            unresolved.append({"requestId": identity, "reason": "missing_or_ambiguous_ingress_event"})
            continue
        second, event = candidates[0], events[0]
        actual = by_id.get(second["requestId"])
        if actual is None or actual["requestId"] in used:
            unresolved.append({"requestId": identity, "reason": "missing_or_reused_received_ingress"})
            continue
        equal = all(original[field] == actual[field] == event[field] for field in ("method", "status"))
        equal &= (original["phase"] or None) == (actual["phase"] or None)
        # An envelope refusal has not decoded an authenticated phase. The
        # independently retained offered phase still binds the exact codec case.
        equal &= event["phase"] == ((original["phase"] or None)
            if event["envelopeAuthenticated"] else None)
        path_reference = first["files"].get("path_and_query")
        equal &= path_reference is not None and event["pathSha256"] == path_reference["sha256"]
        for field in ("path_and_query", "ingress"):
            before, after = first["files"].get(field), second["files"].get(field)
            equal &= before is not None and after is not None and all(
                before[key] == after[key] for key in ("sha256", "byteSize"))
        if first["files"].get("ingress") is not None:
            equal &= event["compactSha256"] == first["files"]["ingress"]["sha256"]
        partitions = {}
        for side, name in (("request", "requestConsumed"), ("response", "replyOffered")):
            left, right = original["bodies"].get(side), actual["bodies"].get(side)
            if left is None or right is None or any(left[field] != right[field]
                    for field in ("sha256", "byteSize")):
                equal = False
                continue
            body = read_body(right)
            count, frames = int(event[name]["exposedBytes"]), event[name]
            equal &= len(body) == int(right["byteSize"]) and hashlib.sha256(body).hexdigest() == right["sha256"]
            equal &= count <= len(body) and hashlib.sha256(body[:count]).hexdigest() == frames["exposedSha256"]
            equal &= not frames["overflow"] and (not frames["eof"] or count == len(body))
            partitions[name] = {**frames, "capturedBytes": str(len(body)), "capturedSha256": right["sha256"]}
        if not equal:
            unresolved.append({"requestId": identity, "reason": "ingress_event_transport_substitution"})
            continue
        used.add(actual["requestId"])
        checked = event["checkedContexts"]
        joined.append({"nativeRequestId": identity, "nativeReceivedRequestId": actual["requestId"],
            "requestSha256": actual["bodies"]["request"]["sha256"],
            "replySha256": actual["bodies"]["response"]["sha256"], "observation": event,
            "partitions": partitions, "checkedContexts": checked,
            "handlerOutcome": "refused" if event["status"] is not None and event["status"] >= 400
                else "completed" if event["stage"] == "handler_completed" else "incomplete",
            "scope": "actual existing handler/check and application-frame observations; no new authorization or provider proof"})
    assigned_events = {row["nativeRequestId"] for row in joined}
    return {"version": 1, "joined": joined, "unresolved": unresolved,
        "unassignedEventCount": sum(len(rows) for key, rows in by_event.items()
            if key not in assigned_events), "nativeBulkBytes": None}


def prepare_managed_outbound_codec_segments(originals, received, original_headers, received_headers,
                                             source_digest, deployment_id):
    """Execute closed codecs over all actual outbound originals, without filtering failures.

    Every captured original remains in the inventory. Missing, partial or
    unsupported bodies remain unresolved or produce a failed terminal segment;
    neither preparation nor successful structural decoding authenticates a reply.
    """
    by_id, owners = {}, {}
    for row in received:
        if row['requestId'] in by_id:
            raise ValueError('Managed received outbound identity repeated')
        by_id[row['requestId']] = row
    for header in received_headers.values():
        owners.setdefault(header['originalRequestId'], []).append(header)
    if len({row['requestId'] for row in originals}) != len(originals):
        raise ValueError('Managed outbound original identity repeated')
    inventory = native_corpus_inventory([('outbound', row) for row in originals]) if originals else None
    cases, ownership, selected, unresolved, used = [], [], [], [], set()
    for original in originals:
        identity = original['requestId']
        first = original_headers.get(identity)
        matches = owners.get(identity, [])
        second = matches[0] if len(matches) == 1 else None
        actual = by_id.get(second['requestId']) if second else None
        equal = first is not None and actual is not None and actual['requestId'] not in used
        equal &= actual is not None and all(original[field] == actual[field] for field in (
            'procedure', 'method', 'phase', 'status', 'responseContentType', 'responseContentEncoding'))
        for side in ('request', 'response'):
            left = original['bodies'].get(side)
            right = actual['bodies'].get(side) if actual else None
            equal &= left is not None and right is not None and all(left[field] == right[field]
                for field in ('sha256', 'byteSize'))
        left = first['files'].get('path_and_query') if first else None
        right = second['files'].get('path_and_query') if second else None
        equal &= left is not None and right is not None and all(left[field] == right[field]
            for field in ('sha256', 'byteSize'))
        if not equal:
            unresolved.append(identity)
            continue
        target = direct_selected_bytes({'path': left['file'], 'sha256': left['sha256']}, 4096).decode()
        if target.split('?', 1)[0] != original['procedure']:
            unresolved.append(identity)
            continue
        def reference(value):
            return {**value, 'byteSize': str(value['byteSize'])}
        used.add(actual['requestId'])
        cases.append({'requestId': identity, 'method': original['method'], 'pathAndQuery': target,
            'phase': original['phase'] or None, 'status': original['status'],
            'responseContentType': original['responseContentType'] or None,
            'responseContentEncoding': original['responseContentEncoding'] or None,
            'originalRequest': reference(original['bodies']['request']),
            'receivedRequest': reference(actual['bodies']['request']),
            'receivedReply': reference(actual['bodies']['response']),
            'originalIngress': None, 'receivedIngress': None})
        selected.append(('outbound', original))
        ownership.append({'originalId': 'outbound:' + identity, 'receivedId': actual['requestId'],
            'receiptIdSha256': None, 'transportCallIdSha256': hashlib.sha256(
                first['transportCallId'].encode()).hexdigest() if first['transportCallId'] else None})
    bundle = partition_native_codec_corpus(native_corpus_inventory(selected),
        {'version': 1, 'sourceDigest': source_digest, 'deploymentId': deployment_id},
        'cases', cases, ownership) if cases else None
    return {'version': 1, 'completeOriginalInventory': inventory, 'selectedCodecSegments': bundle,
        'unresolvedOriginalRequestIds': unresolved,
        'unselectedReceivedRequestIds': sorted(set(by_id) - used), 'nativeBulkBytes': None}
