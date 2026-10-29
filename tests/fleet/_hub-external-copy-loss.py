"""Exercise a real failed Copy original after an authenticated Closed reply loss.

The listener supplies exact retained envelopes and its local loss action. The
caller independently observes normal Operation failure, cold process custody,
Retry CAS and current catalogue/presence. API idempotence and local destruction
are never substituted for physical redispatch or remote-drain measurements.
"""

import hashlib
import json
import sys
import time


def read_external_copy_loss_reference(worker, tools, installation, reference, maximum):
    """Reopen only a bounded retained file under the actual listener's root."""
    if (not isinstance(reference, dict) or set(reference) != {"file", "sha256", "byteSize"}
            or not reference["file"].startswith(installation["root"] + "/attempt-")
            or "/" in reference["file"][len(installation["root"]) + 1:]
            or not isinstance(reference["byteSize"], str)
            or not reference["byteSize"].isdecimal()
            or str(int(reference["byteSize"])) != reference["byteSize"]
            or not 0 < int(reference["byteSize"]) <= maximum):
        raise ValueError("Copy lost reply private reference differs")
    raw = read_direct_guest_file(worker, tools["python"], reference["file"], maximum)
    if str(len(raw)) != reference["byteSize"] or hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise ValueError("Copy lost reply private bytes changed")
    return raw


def validate_external_copy_loss_observation(state, retained, selected, tools, run):
    """Join the actual authenticated envelopes and loss receipt to one original."""
    observation = state["observation"]
    request, verification, loss = (json.loads(retained[name]) for name in ("request", "verification", "loss"))
    if (state["terminal"] != "authenticated_closed_downstream_destroyed" or state["consumed"] is not True
            or observation["captureId"] != run or observation["originalSha256"] != selected["originalSha256"]
            or request["control"] != "advance" or request["original"] != selected["request"]["original"]
            or verification["scope"] != "authenticated_copy_closed_envelope_only"
            or verification["phase"] != "closed" or verification["version"] != 1
            or verification["sourceDigest"] != selected["sourceDigest"]
            or verification["codecSourceSha256"] != tools["storageCodecSourceSha256"]
            or verification["originalSha256"] != selected["originalSha256"]
            or verification["requestSha256"] != observation["request"]["sha256"]
            or verification["requestBytes"] != observation["request"]["byteSize"]
            or verification["replySha256"] != observation["reply"]["sha256"]
            or verification["replyBytes"] != observation["reply"]["byteSize"]
            or loss["downstreamDestroyInvoked"] is not True
            or any(loss[name] != observation[name] for name in (
                "request", "reply", "selection", "verification", "captureId", "originalSha256"))):
        raise ValueError("Copy lost Closed receipt selects another envelope or original")
    return verification


def run_external_copy_loss_window(native, worker, tools, prepared, processes, workflow,
                                  controls, registry, binding, catalogue, *, ownership, read_sql):
    """Lose a genuinely authenticated Closed reply, then cold-retry its failed operation."""
    coordinates = prepared["coordinates"]
    run = coordinates["runId"]
    label = "copy-" + run + "-lost"
    surface = {"registrySlug": registry["registry"]["slug"]}
    source_name = registry["placement"]["name"]
    destination = "copy-" + run[:12] + "-lost"
    prefix = coordinates["placementPrefix"] + "-lost-" + run
    objects = external_copy_catalog(catalogue["objects"])
    controls.reviewed("TopologyService", "PlanCreatePlacement", "CreatePlacement", {
        "surface": surface, "name": destination, "bindingId": binding["stableId"],
        "prefix": prefix, "kind": "complete", "desiredState": "active", "desiredReadEnabled": True,
        "readOrder": "10", "requiresConditionalWrites": False, "expectedResourceVersion": "",
    }, label + "-target")
    target = controls.call("TopologyService", "GetPlacement", {"surface": surface, "name": destination})["placement"]
    if target["prefix"] != prefix or target["bindingName"] != binding["spec"]["name"]:
        raise ValueError("Lost Copy target differs from its initial selected prefix")
    scan = controls.reviewed("TopologyService", "PlanScanPlacement", "ScanPlacement", {
        "surface": surface, "placementName": destination, "expectedResourceVersion": target["resourceVersion"],
    }, label + "-scan")["operation"]
    missing = controls.wait_operation(scan["operationId"], {"succeeded"})

    def presence():
        return [controls.call("TopologyService", "ListObjectPresence", {
            "surface": surface, "objectRef": row["path"], "pageSize": 16,
        }) for row in objects]

    before = presence()
    require_external_copy_presence(before, objects, source_name, destination, copied=False)
    target = controls.call("TopologyService", "GetPlacement", {"surface": surface, "name": destination})["placement"]
    plan = controls.call("TopologyService", "PlanReplicatePlacement", {
        "surface": surface, "sourcePlacementName": source_name, "destinationPlacementName": destination,
        "expectedResourceVersion": target["resourceVersion"], "idempotencyKey": label + "-plan",
    })["plan"]
    installation = prepared["copyClosedLoss"]
    capture = begin_managed_storage_window(native, worker, tools, workflow.prepared,
        external_capture_processes(processes), workflow.boundaries, "external-lost")
    original_before = external_copy_pending_files(native, tools, coordinates["nativeRoot"] + "/outbound/client-body",
        processes["nativeProxy"])
    received_before = external_copy_pending_files(worker, tools, coordinates["workerRoot"] + "/boundary/client-body",
        processes["workerProxy"])
    result, selected, arm, observed, physical = {}, None, None, None, None
    try:
        apply = {"planId": plan["planId"], "confirmationHash": plan["confirmationHash"],
            "idempotencyKey": label + "-apply"}
        operation = controls.call("TopologyService", "ReplicatePlacement", apply)["operation"]
        result.update(plan=plan, apply=apply, operation=operation, missingScan=missing, presenceBefore=before)
        retain_direct_flow(label + "-applied.json", result)
        deadline = time.monotonic() + 30
        attempted = set()
        while selected is None and time.monotonic() < deadline:
            originals = external_copy_pending_files(native, tools, coordinates["nativeRoot"] + "/outbound/client-body",
                processes["nativeProxy"], operation_id=operation["operationId"], before=original_before["paths"])
            received = external_copy_pending_files(worker, tools, coordinates["workerRoot"] + "/boundary/client-body",
                processes["workerProxy"], operation_id=operation["operationId"], before=received_before["paths"])
            for row in originals["candidates"]:
                matches = [candidate for candidate in received["candidates"] if candidate["sha256"] == row["sha256"]]
                if not matches or row["sha256"] in attempted:
                    continue
                if len(matches) != 1:
                    raise ValueError("Lost Copy request received-side custody is ambiguous")
                attempted.add(row["sha256"])
                decoded = decode_external_copy_pending_pair(tools, workflow, label, len(attempted),
                    row, matches[0], artifact_case="lost")
                original = decoded["request"]["original"]
                if (original["topology"]["operation_id"] != operation["operationId"]
                        or original["destination"]["prefix"] != prefix
                        or original["destination"]["resource_version"] != target["resourceVersion"]):
                    raise ValueError("Lost Copy original differs from current reviewed target")
                if int(original["source_object"]["bytes"]) <= 65536:
                    continue
                selected = decoded
                arm = external_copy_loss_command(worker, tools, installation, {"version": 1, "kind": "arm",
                    "captureId": run, "originalSha256": decoded["originalSha256"],
                    "lossUntilUnixMillis": int(time.time() * 1000) + 35000})
                retain_direct_flow(label + "-selected-original.json", {"decoded": decoded, "arm": arm})
                if arm != {"version": 1, "status": "armed"}:
                    raise RuntimeError("Lost Copy owner refused its actual original")
                break
            if selected is None:
                time.sleep(0.1)
        if selected is None:
            raise RuntimeError("Lost Copy missed a genuine large original before its cutoff")
        deadline = time.monotonic() + 36
        while time.monotonic() < deadline:
            observed = external_copy_loss_command(worker, tools, installation, {"version": 1, "kind": "state"})
            if observed["terminal"] is not None:
                break
            time.sleep(0.1)
        retain_direct_flow(label + "-loss-state.json", observed)
        if observed["observation"] is None:
            raise RuntimeError("Lost Copy has no actual authenticated Closed loss")
        retained = {name: read_external_copy_loss_reference(worker, tools, installation,
            observed["observation"][name], 65536) for name in ("request", "reply", "selection", "verification", "loss")}
        verified = validate_external_copy_loss_observation(observed, retained, selected, tools, run)
        for name, raw in retained.items():
            retain_direct_flow(label + "-retained-" + name + ".json", raw)
        failed = controls.wait_operation(operation["operationId"], {"failed"}, timeout=300)
        result.update(selectedOriginal=selected, arm=arm, lossState=observed,
            authenticatedClosed=verified, failedOperation=failed)
        retain_direct_flow(label + "-failed-original.json", result)
    finally:
        active_error = sys.exc_info()[1]
        try:
            physical = finish_managed_storage_window(native, worker, tools, workflow.prepared,
                external_capture_processes(processes), workflow.boundaries, capture, "external-lost")
            retain_direct_flow(label + "-physical-window.json", {"capture": physical, "selected": selected,
                "arm": arm, "lossState": observed, "nativeBulkBytes": None, "remoteDrain": None})
        except Exception as error:
            if active_error is None:
                raise
            active_error.add_note("Lost Copy physical capture incomplete: " + type(error).__name__)
    cold = restart_external_copy_worker(worker, tools, prepared, processes, workflow, "lost", ownership=ownership)
    current = controls.operation(operation["operationId"])
    if current["operation"]["state"] != "failed":
        raise ValueError("Lost Copy cold transition changed its genuine failed original")
    retry_window = begin_managed_storage_window(native, worker, tools, workflow.prepared,
        external_capture_processes(processes), workflow.boundaries, "external-lost-cold")
    retry_request = {"operationId": operation["operationId"], "expectedResourceVersion": current["resourceVersion"],
        "idempotencyKey": label + "-cold-retry"}
    try:
        retry = controls.call("OperationService", "RetryOperation", retry_request)
        completed = controls.wait_operation(operation["operationId"], {"succeeded"}, timeout=300)
        facts = require_external_copy_operation(completed, "replicate", source_name, destination, len(objects))
        after = presence()
        require_external_copy_presence(after, objects, source_name, destination, copied=True)
        latest = observe_external_copy_catalog(read_sql, registry, catalogue["sourceCommit"],
            label + "-final-catalogue")
        if latest["sql"] != catalogue["sql"]:
            raise ValueError("Lost Copy cold retry changed the actual signed catalogue or index")
    finally:
        active_error = sys.exc_info()[1]
        try:
            cold_capture = finish_managed_storage_window(native, worker, tools, workflow.prepared,
                external_capture_processes(processes), workflow.boundaries, retry_window, "external-lost-cold")
            retain_direct_flow(label + "-cold-window.json", cold_capture)
        except Exception as error:
            if active_error is None:
                raise
            active_error.add_note("Lost Copy cold capture incomplete: " + type(error).__name__)
    result.update(cold=cold, retryRequest=retry_request, retryReply=retry, completed=completed,
        controllerFacts=facts, presenceAfter=after, catalogueAfter=latest,
        physicalWindow=physical, coldWindow=cold_capture,
        providerRedispatches=None, remoteDrain=None,
        scope="actual authenticated Closed loss and failed-original cold Retry; provider deltas remain independently measured")
    retain_direct_flow(label + "-result.json", result)
    return result
