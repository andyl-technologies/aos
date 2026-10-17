"""Join a real pending Copy range to the normal cancellation control.

The provider listener only offers a prefix. A separately retained Worker event
must show actual source consumption, and the shared request-only codec selects
the genuine original. Neither observation supplies transport authentication or
remote-drain proof. The complete outer capture retains all other operations.
"""

import base64
import hashlib
import json
from pathlib import Path
import sys
import time


def external_copy_pending_files(machine, tools, directory, process, *, operation_id=None, before=()):
    """Snapshot fixed proxy request files under the selected live lifetime."""
    return json.loads(direct_guest_python(machine, tools["python"], """
        import hashlib, os, stat
        from pathlib import Path

        pin=selected['process']; proc=Path('/proc')/str(pin['pid'])
        ticks=(proc/'stat').read_text().rpartition(') ')[2].split()
        if ticks[19]!=pin['startTicks'] or ticks[0]=='Z' or proc.stat().st_uid!=pin['ownerUid']:
            raise ValueError('Pending Copy proxy lifetime changed')
        root=Path(selected['directory']); rows=[]; candidates=[]
        for directory,children,files in os.walk(root,followlinks=False):
            if any((Path(directory)/name).is_symlink() for name in children):
                raise ValueError('Pending Copy request directory contains a symlink')
            for name in files:
                path=Path(directory)/name; metadata=path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=pin['ownerUid']:
                    raise ValueError('Pending Copy request custody differs')
                rows.append(str(path))
                if len(rows)>4096: raise ValueError('Pending Copy request inventory exceeds its bound')
                if selected['operationId'] is None or str(path) in selected['before']:
                    continue
                if not 0<metadata.st_size<=65536: continue
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as source:
                    first=os.fstat(source.fileno()); body=source.read(65537); last=os.fstat(source.fileno())
                if len(body)!=first.st_size or any(getattr(first,key)!=getattr(last,key)
                        for key in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):
                    continue
                try: value=json.loads(body)
                except (ValueError,UnicodeError): continue
                if not isinstance(value,dict) or value.get('control')!='advance': continue
                original=value.get('original')
                if not isinstance(original,dict) or original.get('topology',{}).get('operation_id')!=selected['operationId']:
                    continue
                candidates.append({'path':str(path),'device':str(first.st_dev),'inode':str(first.st_ino),
                    'sha256':hashlib.sha256(body).hexdigest(),'byteSize':str(len(body)),
                    'body':base64.b64encode(body).decode()})
                if len(candidates)>8: raise ValueError('Pending Copy invocation candidates exceed bound')
        after=(proc/'stat').read_text().rpartition(') ')[2].split()
        if after[19]!=ticks[19] or after[0]=='Z': raise ValueError('Pending Copy proxy changed during read')
        print(json.dumps({'paths':sorted(rows),'candidates':candidates,
            'process':{'pid':pin['pid'],'startTicks':pin['startTicks'],'ownerUid':pin['ownerUid']}}))
    """, {"directory": directory, "process": process, "operationId": operation_id,
        "before": list(before)}))


def external_copy_pending_log(worker, tools, position, process):
    """Read one bounded current suffix without consuming its final capture."""
    captured = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, stat
        from pathlib import Path

        pin=selected['process']; proc=Path('/proc')/str(pin['pid'])
        ticks=(proc/'stat').read_text().rpartition(') ')[2].split()
        if ticks[19]!=pin['startTicks'] or ticks[0]=='Z' or proc.stat().st_uid!=pin['ownerUid']:
            raise ValueError('Pending Copy Worker lifetime differs')
        before=selected['position']; fd=os.open(before['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as source:
            metadata=os.fstat(source.fileno()); length=metadata.st_size-before['byteSize']
            if (not stat.S_ISREG(metadata.st_mode) or str(metadata.st_dev)!=before['device']
                    or str(metadata.st_ino)!=before['inode'] or not 0<=length<=8*1024*1024):
                raise ValueError('Pending Copy Worker log prefix differs')
            source.seek(before['byteSize']); body=source.read(length)
        if len(body)!=length: raise ValueError('Pending Copy Worker log prefix truncated')
        after=(proc/'stat').read_text().rpartition(') ')[2].split()
        if after[19]!=ticks[19] or after[0]=='Z': raise ValueError('Pending Copy Worker changed during read')
        print(json.dumps({'body':base64.b64encode(body).decode(),'sha256':hashlib.sha256(body).hexdigest(),
            'after':{'path':before['path'],'device':before['device'],'inode':before['inode'],
                'byteSize':metadata.st_size}}))
    """, {"position": position, "process": process}))
    body = base64.b64decode(captured.pop("body"), validate=True)
    if hashlib.sha256(body).hexdigest() != captured["sha256"]:
        raise ValueError("Pending Copy Worker suffix changed in transport")
    return body.decode(), captured


def decode_external_copy_pending_pair(tools, workflow, label, sequence, original, received, *, artifact_case):
    """Retain both real proxy bodies and invoke the selected intrinsic decoder."""
    references = {}
    for role, row in (("originalRequest", original), ("receivedRequest", received)):
        body = base64.b64decode(row["body"], validate=True)
        name = label + "-pending-" + str(sequence) + "-" + role.lower() + ".json"
        digest = retain_direct_flow(name, body)
        if digest != row["sha256"] or str(len(body)) != row["byteSize"]:
            raise ValueError("Pending Copy body differs from actual proxy bytes")
        references[role] = {"file": str(Path("external-direct-flow") / name),
            "sha256": digest, "byteSize": str(len(body))}
    selection = {"version": 1, "sourceDigest": workflow.prepared["captureSelection"]["sourceDigest"],
        "deploymentId": tools["deploymentId"], **references}
    name = label + "-pending-" + str(sequence) + "-selection.json"
    retain_direct_flow(name, selection)
    decoded = run_direct_native_codec_observer(workflow.boundaries["codecSelection"],
        Path("external-direct-flow") / name,
        artifact_prefix="external-oci-codec-" + artifact_case + "-" + workflow.prepared["captureSelection"]["run"],
        segment_label="segment-" + str(sequence).zfill(6), command="copy-request")
    if (decoded["codecSourceSha256"] != tools["storageCodecSourceSha256"]
            or decoded["requestSha256"] != original["sha256"]
            or decoded["sourceDigest"] != selection["sourceDigest"]):
        raise ValueError("Pending Copy codec selects another source or request")
    return decoded


def run_external_copy_cancel_window(native, worker, s3, tools, prepared, processes,
                                    workflow, controls, registry, binding, *, ownership):
    """Create a genuinely missing third target and cancel a measured pending read."""
    coordinates = prepared["coordinates"]
    run, source_prefix = coordinates["runId"], coordinates["placementPrefix"]
    label = "copy-" + run + "-cancel"
    surface = {"registrySlug": registry["registry"]["slug"]}
    source_name = registry["placement"]["name"]
    destination = "copy-" + run[:12] + "-cancel"
    controls.reviewed("TopologyService", "PlanCreatePlacement", "CreatePlacement", {
        "surface": surface, "name": destination, "bindingId": binding["stableId"],
        "prefix": source_prefix + "-cancel-" + run, "kind": "complete", "desiredState": "active",
        "desiredReadEnabled": True, "readOrder": "10", "requiresConditionalWrites": False,
        "expectedResourceVersion": "",
    }, label + "-target")
    target = controls.call("TopologyService", "GetPlacement", {"surface": surface, "name": destination})["placement"]
    if target["prefix"] != source_prefix + "-cancel-" + run or target["bindingName"] != binding["spec"]["name"]:
        raise ValueError("Copy cancellation target differs from the initial selected prefix")
    scan = controls.reviewed("TopologyService", "PlanScanPlacement", "ScanPlacement", {
        "surface": surface, "placementName": destination,
        "expectedResourceVersion": target["resourceVersion"],
    }, label + "-scan")["operation"]
    missing = controls.wait_operation(scan["operationId"], {"succeeded"})
    target = controls.call("TopologyService", "GetPlacement", {"surface": surface, "name": destination})["placement"]
    plan = controls.call("TopologyService", "PlanReplicatePlacement", {
        "surface": surface, "sourcePlacementName": source_name, "destinationPlacementName": destination,
        "expectedResourceVersion": target["resourceVersion"], "idempotencyKey": label + "-plan",
    })["plan"]
    retain_direct_flow(label + "-missing-scan.json", missing)
    lifetime = managed_fixture_module(tools["externalCopyLifetime"], "external_copy_lifetime_" + run)
    installation = tools["externalCopyPartialInstallation"]
    provider_prefix = external_oci_provider_prefix(binding["spec"]["s3"]["bucket"],
        binding["spec"]["s3"]["prefix"], source_prefix)
    token, finished = None, False

    def begin_window(window_label):
        nonlocal token
        capture = begin_managed_storage_window(native, worker, tools, workflow.prepared,
            external_capture_processes(processes), workflow.boundaries, "external-cancel")
        originals = external_copy_pending_files(native, tools, coordinates["nativeRoot"] + "/outbound/client-body",
            processes["nativeProxy"])
        received = external_copy_pending_files(worker, tools, coordinates["workerRoot"] + "/boundary/client-body",
            processes["workerProxy"])
        token = {"capture": capture, "originalBefore": originals, "receivedBefore": received,
            "label": window_label, "ceiling": int(time.time() * 1000) + 35000}
        armed = direct_copy_partial_command(s3, tools, installation, {"version": 1, "kind": "arm",
            "targetPrefix": provider_prefix, "holdUntilUnixMillis": token["ceiling"]})
        retain_direct_flow(label + "-partial-arm.json", armed)
        if armed != {"version": 1, "status": "armed"}:
            raise RuntimeError("Copy partial listener refused its one-use selected case")
        return token

    def await_source_progress(window, operation_id):
        attempted, observations = set(), 0
        while time.time() * 1000 < window["ceiling"]:
            text, log = external_copy_pending_log(worker, tools, window["capture"]["positions"]["workerLog"],
                processes["worker"])
            if "external_copy_lifetime_observer " not in text:
                time.sleep(0.1)
                continue
            originals = external_copy_pending_files(native, tools, coordinates["nativeRoot"] + "/outbound/client-body",
                processes["nativeProxy"], operation_id=operation_id, before=window["originalBefore"]["paths"])
            received = external_copy_pending_files(worker, tools, coordinates["workerRoot"] + "/boundary/client-body",
                processes["workerProxy"], operation_id=operation_id, before=window["receivedBefore"]["paths"])
            for original in originals["candidates"]:
                matches = [row for row in received["candidates"] if row["sha256"] == original["sha256"]]
                if not matches or original["sha256"] in attempted:
                    continue
                if len(matches) != 1:
                    raise ValueError("Pending Copy request has ambiguous received custody")
                attempted.add(original["sha256"])
                sequence = len(attempted)
                decoded = decode_external_copy_pending_pair(tools, workflow, label, sequence,
                    original, matches[0], artifact_case="cancel")
                if decoded["request"]["original"]["topology"]["operation_id"] != operation_id:
                    raise ValueError("Pending Copy codec selects another operation")
                window.setdefault("decoded", []).append({"validation": decoded,
                    "original": {key: value for key, value in original.items() if key != "body"},
                    "received": {key: value for key, value in matches[0].items() if key != "body"}})
            for selected in window.get("decoded", []):
                decoded = selected["validation"]
                if decoded["originalSha256"] not in text:
                    continue
                traces = lifetime.select_copy_lifetime_traces(text, run, decoded["originalSha256"])
                if not any(trace["role"] == "source_guard"
                        and trace["rows"][-1]["event"]["kind"] != "terminal"
                        and any(row["event"]["kind"] == "source_progress"
                            and row["event"]["bytes"] >= 65536 and row["event"]["eof"] is False
                            for row in trace["rows"]) for trace in traces["traces"]):
                    continue
                destinations = [trace for trace in traces["traces"]
                    if trace["role"] == "destination_executor"
                    and trace["rows"][0]["request_sha256"] == decoded["requestSha256"]]
                tickets = {row["event"]["ticket_id"] for trace in destinations for row in trace["rows"]
                    if row["event"]["kind"] == "transfer"}
                sources = [trace for trace in traces["traces"] if trace["role"] == "source_guard"
                    and trace["rows"][-1]["event"]["kind"] != "terminal"
                    and any(row["event"]["kind"] == "source_progress" and row["event"]["bytes"] >= 65536
                        and row["event"]["eof"] is False for row in trace["rows"])
                    and any(row["event"]["kind"] == "transfer" and row["event"]["ticket_id"] in tickets
                        for row in trace["rows"])]
                if not destinations or not sources:
                    continue
                name = label + "-pending-worker.log"
                digest = retain_direct_flow(name, text.encode())
                state = direct_copy_partial_command(s3, tools, installation, {"version": 1, "kind": "state",
                    "targetPrefix": provider_prefix})
                if state["pendingLocalHold"] is not True or state["prefixReceipt"] is None:
                    raise RuntimeError("Copy source progress missed the actual partial hold")
                participating = {}
                for trace in destinations + sources:
                    for row in trace["rows"]:
                        pool = row["event"].get("pool")
                        if pool is not None and (pool["maximum"] != 3 or pool["peakActive"] > 3):
                            raise ValueError("Actual Copy participating pool exceeds selected capacity three")
                    entries = [row for row in trace["rows"] if row["event"]["kind"] == "entry"]
                    if len(entries) != 1:
                        raise ValueError("Copy invocation lacks its actual participating pool entry")
                    participating.setdefault(trace["role"], set()).add(entries[0]["event"]["pool"]["isolateId"])
                if set(participating) != {"destination_executor", "source_guard"}:
                    raise ValueError("Copy pending window lacks both participating pool observations")
                pools = {role: sorted(values) for role, values in participating.items()}
                relation = (pools["destination_executor"] == pools["source_guard"]
                    if all(len(values) == 1 for values in participating.values()) else None)
                return {"receipt": {"file": str(Path("external-direct-flow") / name), "sha256": digest,
                            "byteSize": len(text.encode()), "logWindow": log, "proxyFiles": selected,
                            "providerHold": state, "participatingPools": pools,
                            "sameObservedPool": relation,
                            "selectedTraceIds": [trace["traceId"] for trace in destinations + sources]},
                    "originalValidationReceipt": decoded,
                    "originalSha256": decoded["originalSha256"], "original": decoded["request"]["original"],
                    "workerLogText": text, "captureId": run}
            observations += 1
            if observations > 128:
                raise RuntimeError("Copy source progress polling exceeded its fixed bound")
            time.sleep(0.1)
        raise RuntimeError("Copy cancellation missed its genuine pending source window")

    def finish_window(window, window_label):
        nonlocal finished
        state = direct_copy_partial_command(s3, tools, installation,
            {"version": 1, "kind": "state", "targetPrefix": provider_prefix})
        release = None
        if state["pendingLocalHold"] is True:
            release = direct_copy_partial_command(s3, tools, installation,
                {"version": 1, "kind": "release", "targetPrefix": provider_prefix})
        # The actual signed control cutoff, rather than Cancel's SQL reply,
        # bounds the physical observation. An absent terminal remains unknown.
        while time.time() * 1000 <= window["ceiling"] + 1000 and state["terminal"] is None:
            time.sleep(0.1)
            state = direct_copy_partial_command(s3, tools, installation,
                {"version": 1, "kind": "state", "targetPrefix": provider_prefix})
        captured = finish_managed_storage_window(native, worker, tools, workflow.prepared,
            external_capture_processes(processes), workflow.boundaries, window["capture"], "external-cancel")
        finished = True
        return {"capture": captured, "partialState": state, "release": release,
            "remoteDrain": None, "providerSettlement": None}

    try:
        cancelled = lifetime.run_external_copy_cancellation(controls, plan, label,
            surface=surface, destination_name=destination, begin_window=begin_window,
            await_source_progress=await_source_progress, finish_window=finish_window,
            retain=lambda name, value: retain_direct_flow(name + ".json", value))
    finally:
        if token is not None and not finished:
            active_error = sys.exc_info()[1]
            try:
                physical = finish_window(token, label)
                retain_direct_flow(label + "-failed-physical-window.json", physical)
            except Exception as capture_error:
                if active_error is None:
                    raise
                # Capture failure cannot replace the original producer error.
                # The outer collector still retains its complete raw suffix.
                try:
                    retain_direct_flow(label + "-failure-classes.json", {
                        "producerFailureClass": type(active_error).__name__,
                        "captureFailureClass": type(capture_error).__name__,
                        "remoteDrain": None, "providerSettlement": None})
                except Exception:
                    active_error.add_note("Copy cancellation capture diagnostics could not be retained")
    cold = restart_external_copy_worker(worker, tools, prepared, processes, workflow,
        "cancelled", ownership=ownership)
    detail = controls.operation(cancelled["appliedOriginal"]["operationId"])
    if detail["operation"]["state"] != "cancelled":
        raise ValueError("Cold Copy restart changed the retained cancelled original")
    retry_request = {"operationId": detail["operation"]["operationId"],
        "expectedResourceVersion": detail["resourceVersion"], "idempotencyKey": label + "-cold-retry"}
    retry_window = begin_managed_storage_window(native, worker, tools, workflow.prepared,
        external_capture_processes(processes), workflow.boundaries, "external-cancel-cold")
    retry = controls.call("OperationService", "RetryOperation", retry_request)
    current = controls.wait_operation(retry_request["operationId"], {"succeeded", "failed", "cancelled"}, timeout=300)
    cold_capture = finish_managed_storage_window(native, worker, tools, workflow.prepared,
        external_capture_processes(processes), workflow.boundaries, retry_window, "external-cancel-cold")
    retain_direct_flow(label + "-cold-retry.json", {"before": detail, "request": retry_request,
        "reply": retry, "current": current, "capture": cold_capture,
        "remoteDrain": None, "providerRedispatches": None})
    return {"version": 1, "cancelled": cancelled, "cold": cold, "retryRequest": retry_request,
        "retryReply": retry, "operationAfterRetry": current, "coldRetryCapture": cold_capture,
        "scope": "actual cancelled-original cold retry; physical resumption/refusal remains observed separately"}
