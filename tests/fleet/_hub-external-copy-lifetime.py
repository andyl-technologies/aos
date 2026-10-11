"""Called Copy cancellation and local lifetime facts, never remote-drain proof.

The controller uses real OperationService CAS mutations. Transport callbacks
must retain the selected current process/config/namespace and actual raw
request/reply/log windows. A callback outcome is not provider qualification.
"""

import json
import re
import uuid

PREFIX = "external_copy_lifetime_observer "


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Copy lifetime lacks a selected shared original digest")
    return value


def _integer(value, maximum=(1 << 64) - 1):
    return type(value) is int and 0 <= value <= maximum


def _uuid(value):
    return isinstance(value, str) and str(uuid.UUID(value)) == value


def _pool(value):
    fields = {"isolateId", "maximum", "active", "bulkActive", "metadataActive",
              "peakActive", "metadataAdmissionsDuringBulk", "dispatches"}
    if (not isinstance(value, dict) or set(value) != fields
            or not _uuid(value["isolateId"])
            or not all(_integer(value[name]) for name in fields - {"isolateId"})
            or value["maximum"] < 1 or value["active"] > value["maximum"]
            or value["bulkActive"] + value["metadataActive"] > value["active"]):
        raise ValueError("Copy lifetime pool observation is not closed")


def _event(event):
    if not isinstance(event, dict):
        raise ValueError("Copy lifetime event is not supported")
    kind = event.get("kind")
    fields = {
        "entry": {"kind", "pool"},
        "admission": {"kind", "owned_slots", "pool"},
        "transfer": {"kind", "ticket_id", "origin_isolate", "pool_generation", "request_digest"},
        "source_progress": {"kind", "bytes", "eof"},
        "cleanup": {"kind", "cause", "owned_capacity_released", "source_gate_released",
                    "native_cleanup_invocations", "pool"},
        "terminal": {"kind", "outcome", "healthy", "pool"},
    }
    if kind not in fields or set(event) != fields[kind]:
        raise ValueError("Copy lifetime event fields differ")
    if "pool" in event:
        _pool(event["pool"])
    if kind == "admission" and (type(event["owned_slots"]) is not int
                                or event["owned_slots"] not in {1, 2}):
        raise ValueError("Copy lifetime admission is not an actual bounded reservation")
    if kind == "transfer":
        if not all(_uuid(event[name]) for name in ("ticket_id", "origin_isolate", "pool_generation")):
            raise ValueError("Copy lifetime transfer identity differs")
        _digest(event["request_digest"])
    if kind == "source_progress" and (not _integer(event["bytes"])
                                      or type(event["eof"]) is not bool):
        raise ValueError("Copy lifetime source progress differs")
    if kind == "cleanup" and (
            event["cause"] not in {"native_signal", "owner_drop"}
            or type(event["owned_capacity_released"]) is not bool
            or type(event["source_gate_released"]) is not bool
            or not _integer(event["native_cleanup_invocations"], 32)):
        raise ValueError("Copy lifetime cleanup observation differs")
    if kind == "terminal" and (
            event["outcome"] not in {"returned", "refused", "eof", "incoming_abort", "unknown"}
            or type(event["healthy"]) is not bool):
        raise ValueError("Copy lifetime terminal observation differs")


def select_copy_lifetime_traces(text, capture_id, original_sha256):
    """Decode bounded actual log rows without authenticating their provenance.

    The caller separately joins this exact raw log/process/config receipt to
    current shared-codec validation of the captured signed original. Missing
    brackets stay incomplete. Local cleanup is never remote SDK settlement.
    """
    if (not isinstance(capture_id, str) or not re.fullmatch(r"[0-9a-f]{32}", capture_id)
            or not isinstance(text, str) or len(text.encode()) > 8 * 1024 * 1024):
        raise ValueError("Copy lifetime log selection exceeds its bound")
    _digest(original_sha256)
    groups = {}
    fields = {"version", "scope", "capture_id", "trace_id", "ordinal",
              "original_sha256", "request_sha256", "role", "observed_at", "event"}
    for line in text.splitlines():
        if PREFIX not in line:
            continue
        body = line.split(PREFIX, 1)[1]
        if len(body.encode()) > 4096:
            raise ValueError("Copy lifetime record exceeds its bound")
        row = json.loads(body)
        if not isinstance(row, dict):
            raise ValueError("Copy lifetime row is not an object")
        if row.get("capture_id") != capture_id:
            continue
        if (set(row) != fields or row["version"] != 1
                or row["scope"] != "external_copy_local_lifetime"
                or row["role"] not in {"destination_executor", "source_guard"}
                or not _uuid(row["trace_id"])
                or type(row["observed_at"]) is not int or row["observed_at"] < 0):
            raise ValueError("Copy lifetime row is not a closed intrinsic record")
        _digest(row["original_sha256"])
        _digest(row["request_sha256"])
        if row["original_sha256"] != original_sha256:
            continue
        records = groups.setdefault(row["trace_id"], [])
        if (len(groups) > 128 or len(records) >= 12 or type(row["ordinal"]) is not int
                or row["ordinal"] != len(records) + 1
                or sum(len(json.dumps(value, separators=(",", ":")).encode())
                       for value in records) + len(body.encode()) > 32 * 1024):
            raise ValueError("Copy lifetime rows are excessive or discontinuous")
        if records and any(row[name] != records[0][name] for name in
                           ("role", "request_sha256", "original_sha256")):
            raise ValueError("Copy lifetime invocation identity changed")
        _event(row["event"])
        if records and records[-1]["event"]["kind"] == "terminal":
            raise ValueError("Copy lifetime records continue after their terminal")
        records.append(row)
    if not groups:
        raise ValueError("Actual selected Copy lifetime records are absent")
    results = []
    for trace_id, rows in groups.items():
        closed = (rows[0]["event"]["kind"] == "entry"
                  and rows[-1]["event"]["kind"] == "terminal"
                  and rows[-1]["event"].get("healthy") is True)
        results.append({"traceId": trace_id, "role": rows[0]["role"],
                        "rows": rows, "closedLocalBracket": closed,
                        "remoteDrain": None, "providerSettlement": None})
    return {"version": 1, "captureId": capture_id, "originalSha256": original_sha256,
            "traces": results, "scope": "intrinsic local log records; independent provenance joins required"}


def run_external_copy_cancellation(controls, reviewed_plan, label, *, surface, destination_name,
                                   begin_window, await_source_progress,
                                   finish_window, retain):
    """Apply an actual reviewed copy, then cancel after a source-progress handshake.

    begin_window(label) returns an opaque retained window token.
    await_source_progress(token, operation_id) must wait for the actual selected
    signed original's source read and return its retained raw observation, not a
    success flag. finish_window(token, label) retains physical terminal/unknown
    facts. This helper does not force a socket teardown or infer cleanup.
    """
    if (not isinstance(label, str) or not re.fullmatch(r"[a-z0-9-]{1,128}", label)
            or not reviewed_plan.get("planId") or not reviewed_plan.get("confirmationHash")
            or not reviewed_plan.get("effects")):
        raise ValueError("Copy cancellation lacks its actual reviewed plan")
    token = begin_window(label)
    retain(label + "-reviewed", {"plan": reviewed_plan, "windowToken": token})
    apply_request = {"planId": reviewed_plan["planId"],
                     "confirmationHash": reviewed_plan["confirmationHash"],
                     "idempotencyKey": label + "-apply"}
    applied = controls.call("TopologyService", "ReplicatePlacement", apply_request)["operation"]
    operation_id = applied["operationId"]
    retain(label + "-applied", {"applyRequest": apply_request, "operation": applied})
    progress = await_source_progress(token, operation_id)
    retain(label + "-source-progress", progress)
    if (not isinstance(progress, dict) or not isinstance(progress.get("receipt"), dict)
            or not progress["receipt"]
            or not isinstance(progress.get("originalValidationReceipt"), dict)):
        raise ValueError("Copy cancellation lacks the real source-progress receipt")
    validation = progress["originalValidationReceipt"]
    if (validation.get("version") != 1
            or validation.get("scope") != "intrinsic_unauthenticated_pending_copy_request"
            or validation.get("originalSha256") != progress["originalSha256"]
            or validation["request"]["original"] != progress["original"]
            or validation["request"]["control"] != "advance"
            or progress["original"]["topology"]["operation_id"] != operation_id):
        raise ValueError("Copy cancellation original observation is not the selected request")
    traces = select_copy_lifetime_traces(progress["workerLogText"], progress["captureId"],
                                        progress["originalSha256"])
    sources = [trace for trace in traces["traces"] if trace["role"] == "source_guard"]
    if not any(trace["rows"][0]["event"]["kind"] == "entry"
            and trace["rows"][-1]["event"]["kind"] != "terminal" and any(
            row["event"]["kind"] == "source_progress"
            and row["event"]["bytes"] >= 65536 and row["event"]["eof"] is False
            for row in trace["rows"]) for trace in sources):
        raise ValueError("Copy cancellation missed a real unfinished source read")
    original = progress["original"]
    target = controls.call("TopologyService", "GetPlacement", {
        "surface": surface, "name": destination_name,
    })["placement"]
    if (target["prefix"] != original["destination"]["prefix"]
            or target["resourceVersion"] != original["destination"]["resource_version"]
            or not original["topology"]["destination"]["stable_id"].endswith(
                "/placement:" + destination_name)):
        raise ValueError("Copy cancellation target differs from the selected physical original")

    def presence():
        reply = controls.call("TopologyService", "ListObjectPresence", {
            "surface": surface, "objectRef": original["path"], "pageSize": 16,
        })
        if reply.get("nextPageToken"):
            raise ValueError("Copy cancellation presence exceeded its selected placement bound")
        rows = [row for row in reply.get("presences", []) if row["placementName"] == destination_name]
        if (len(rows) != 1 or rows[0]["objectRef"] != original["path"]
                or rows[0]["state"] != "missing"):
            raise ValueError("Selected paused object is not logically missing in the actual target")
        return reply

    before_presence = presence()
    current = controls.operation(operation_id)
    operation = current["operation"]
    if operation["operationId"] != operation_id or operation["state"] != "running":
        raise ValueError("Copy cancellation missed the actual running operation")
    request = {"operationId": operation_id,
               "expectedResourceVersion": current["resourceVersion"],
               "idempotencyKey": label + "-cancel"}
    retain(label + "-cancel-request", {"current": current, "request": request})
    cancelled = controls.call("OperationService", "CancelOperation", request)
    retained_cancel = controls.wait_operation(operation_id, {"cancelled"})
    if (retained_cancel["operation"]["operationId"] != operation_id
            or retained_cancel["operation"]["state"] != "cancelled"):
        raise ValueError("Copy cancellation returned another SQL outcome")
    retain(label + "-cancel-reply", {"reply": cancelled, "current": retained_cancel})
    window = finish_window(token, label)
    retain(label + "-physical-window", window)
    after_presence = presence()
    final_operation = controls.operation(operation_id)
    if final_operation["operation"]["state"] != "cancelled":
        raise ValueError("Cancelled original changed state during its physical observation window")
    report = {"version": 1, "reviewedPlan": reviewed_plan,
              "applyRequest": apply_request, "appliedOriginal": applied,
              "operationBefore": current, "sourceTraces": traces,
              "sourceProgress": progress, "cancelRequest": request,
              "cancelReply": cancelled, "operationAfter": retained_cancel,
              "selectedPresenceBefore": before_presence, "selectedPresenceAfter": after_presence,
              "operationAfterPhysicalWindow": final_operation,
              "window": window, "remoteDrain": None, "providerSettlement": None,
              "scope": "actual SQL cancellation plus separately retained physical lifetime facts"}
    retain(label + "-cancelled", report)
    return report
