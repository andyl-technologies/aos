"""Call finite staged fault cases with a real prepared Complete original.

This adapter consumes Native's same-child pre-Complete callback. It retains raw
collector references; absent authentication/provider/SQL joins remain NULL.
Worker receipt persistence faults and a runtime fork producer are unavailable.
"""

from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time


MAX_METADATA = 64 * 1024
UNAVAILABLE = ("worker_finish_persistence", "worker_stage_terminal_persistence", "runtime_valid_fork")


def closed(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError("staged matrix fields differ")


def decimal_count(value, maximum):
    """Parses a bounded canonical count from Native's retained wire image."""
    if (not isinstance(value, str) or len(value) > len(str(maximum))
            or not re.fullmatch(r"0|[1-9][0-9]*", value)):
        raise ValueError("staged matrix reference count differs")
    count = int(value)
    if count > maximum:
        raise ValueError("staged matrix reference count exceeds its bound")
    return count


def read_reference(reference, root, maximum=MAX_METADATA, *, client_io=None):
    closed(reference, {"file", "sha256", "byteSize"})
    if not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]):
        raise ValueError("staged matrix reference digest differs")
    decimal_count(reference["byteSize"], maximum)
    if client_io is not None:
        # The selected caller owns CLIENT descriptor checks and retains their
        # actual custody receipt. Guest paths never reach controller file I/O.
        raw = client_io.read_reference(reference, root, maximum)
        if (not isinstance(raw, bytes) or len(raw) > maximum
                or str(len(raw)) != reference["byteSize"]
                or hashlib.sha256(raw).hexdigest() != reference["sha256"]):
            raise ValueError("CLIENT reference bytes differ from the original commitment")
        return raw

    root = Path(root)
    root_info = root.stat()
    if (root.resolve(strict=True) != root or not root.is_dir() or root_info.st_uid != os.getuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700):
        raise ValueError("staged reference root custody differs")
    file = Path(reference["file"])
    if not file.is_absolute():
        file = root / file
    if file.resolve(strict=True) != file or not file.is_relative_to(root):
        raise ValueError("staged matrix reference escaped its private scope")
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or before.st_size > maximum):
            raise ValueError("staged matrix reference custody differs")
        with os.fdopen(os.dup(descriptor), "rb") as source:
            raw = source.read(maximum + 1)
        after = os.fstat(descriptor)
        names = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (any(getattr(before, name) != getattr(after, name) for name in names)
                or str(len(raw)) != reference["byteSize"]
                or hashlib.sha256(raw).hexdigest() != reference["sha256"]):
            raise ValueError("staged matrix reference bytes changed")
        return raw
    finally:
        os.close(descriptor)


def prepared_complete(prepared, root, *, client_io=None):
    """Checks the actual handoff's original fields without manufacturing admission."""
    closed(prepared, {"version", "state", "method", "controlPath", "runId", "scope", "cutoffUnixMs", "clock", "status",
                      "session", "intent", "placement", "expectedResourceVersion", "sourceSha256",
                      "actorWhoami", "runtimePins", "refs"})
    if (prepared["version"] != 1 or isinstance(prepared["version"], bool)
            or prepared["state"] != "prepared_unsent" or prepared["method"] != "CompleteBatch"
            or prepared["controlPath"] != "/aos.hub.v1.DirectUploadService/CompleteBatch"
            or prepared["scope"] not in {"managed_r2", "external_s3"}
            or not re.fullmatch(r"[0-9a-f]{64}", prepared["runId"])
            or not re.fullmatch(r"[0-9a-f]{64}", prepared["sourceSha256"])
            or not isinstance(prepared["cutoffUnixMs"], int) or isinstance(prepared["cutoffUnixMs"], bool)):
        raise ValueError("prepared Complete handoff differs")
    closed(prepared["session"], {"sessionId", "logicalFingerprint"})
    closed(prepared["clock"], {"bootId", "cutoffUptimeMs"})
    if (not isinstance(prepared["clock"]["bootId"], str)
            or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", prepared["clock"]["bootId"])
            or type(prepared["clock"]["cutoffUptimeMs"]) is not int or prepared["clock"]["cutoffUptimeMs"] <= 0):
        raise ValueError("prepared original boot cutoff differs")
    required_refs = {"selectionValues", "source", "beginBody", "beginReply", "reportReply", "completeBody", "pendingReceipt"}
    closed(prepared["refs"], required_refs | ({"capabilities"} if "capabilities" in prepared["refs"] else set()))
    if prepared["intent"].get("expectedSha256") != prepared["sourceSha256"]:
        raise ValueError("prepared source identity differs")
    status = prepared["status"]
    if (not isinstance(status, dict) or status.get("state") != "creating"
            or status.get("session") != prepared["session"] or status.get("intent") != prepared["intent"]
            or status.get("placements") != [prepared["placement"]]
            or status.get("resourceVersion") != prepared["expectedResourceVersion"]):
        raise ValueError("actual Report status differs from the prepared current original")
    def handoff_reference(name, maximum=MAX_METADATA):
        original = prepared["refs"][name]
        closed(original, {"file", "sha256", "bytes"})
        decimal_count(original["bytes"], maximum)
        name = original["file"]
        if not isinstance(name, str) or Path(name).name != name or name in {".", ".."}:
            raise ValueError("Native handoff image is not an owned direct child")
        return read_reference({"file": original["file"], "sha256": original["sha256"],
                               "byteSize": original["bytes"]}, root, maximum, client_io=client_io)

    selection = json.loads(handoff_reference("selectionValues"))
    if not isinstance(selection, dict):
        raise ValueError("retained selected values differ")
    discovered = "capabilities" in selection
    if discovered == ("placement" in selection) or discovered != ("capabilities" in prepared["refs"]):
        raise ValueError("prepared capability selection mode differs")
    if discovered:
        raw_capabilities = handoff_reference("capabilities", 256 * 1024)
        selected_capabilities = selection["capabilities"]
        closed(selected_capabilities, {"file", "sha256", "byteSize"})
        if (selected_capabilities["sha256"] != hashlib.sha256(raw_capabilities).hexdigest()
                or selected_capabilities["byteSize"] != str(len(raw_capabilities))):
            raise ValueError("prepared raw capability image changed")
    elif selection["placement"] != prepared["placement"]:
        raise ValueError("retained selected placement differs")

    begin = json.loads(handoff_reference("beginBody"))
    closed(begin, {"operationId", "items"})
    if (not isinstance(begin["operationId"], str) or not re.fullmatch(r"[0-9a-f]{64}", begin["operationId"])
            or begin["items"] != [prepared["intent"]]):
        raise ValueError("prepared raw Begin changed its original intent")
    raw = handoff_reference("completeBody")
    request = json.loads(raw)
    closed(request, {"operationId", "items"})
    if not isinstance(request["items"], list) or len(request["items"]) != 1:
        raise ValueError("matrix requires one actual Complete original")
    item = request["items"][0]
    closed(item, {"session", "operationId", "expectedResourceVersion", "manifests"})
    if (item["session"] != prepared["session"]
            or item["expectedResourceVersion"] != prepared["expectedResourceVersion"]
            or not re.fullmatch(r"[0-9a-f]{64}", item["operationId"])
            or not isinstance(item["manifests"], list) or len(item["manifests"]) != 1
            or item["manifests"][0].get("placement") != prepared["placement"]):
        raise ValueError("Complete request changed its original session/placement/RV")
    for name, maximum in (("source", 8 * 1024 * 1024), ("beginReply", MAX_METADATA),
                          ("reportReply", MAX_METADATA), ("pendingReceipt", MAX_METADATA),
                          ("selectionValues", MAX_METADATA)):
        value = handoff_reference(name, maximum)
        if name == "source" and hashlib.sha256(value).hexdigest() != prepared["sourceSha256"]:
            raise ValueError("actual immutable source changed")
    return item


def _current_boot_clock():
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    uptime = Path("/proc/uptime").read_text().split()[0]
    if not re.fullmatch(r"[0-9]{1,15}\.[0-9]{1,9}", uptime):
        raise ValueError("actual client boot uptime is unavailable")
    resolution = Decimal(10) ** -len(uptime.split(".", 1)[1])
    # The proc image truncates to its printed resolution. Use its upper bound
    # so that this additional fence grants no time through that rounding.
    return boot_id, (Decimal(uptime) + resolution) * 1000


def within_original(prepared, deadline, *, client_io=None):
    if client_io is not None:
        if client_io.within_original(prepared, deadline) is not None:
            raise ValueError("CLIENT eligibility reader returned an unsupported verdict")
        return

    boot_id, uptime_ms = _current_boot_clock()
    if (boot_id != prepared["clock"]["bootId"] or uptime_ms >= prepared["clock"]["cutoffUptimeMs"]
            or time.monotonic() >= deadline or time.time() * 1000 >= prepared["cutoffUnixMs"]):
        raise RuntimeError("staged case missed its original eligibility; outcome unknown")


def provider_arm(prepared, reference, root, case, *, client_io=None):
    """Pins the response owner to the actual saved Complete original.

    The provider request remains a separately observed downstream image. This
    comparison correlates it to the original; it does not authenticate it or
    predict provider dispatch from a declared request hash.
    """
    selected = json.loads(read_reference(reference, root, client_io=client_io))
    closed(selected, {"version", "kind", "originalSha256", "originalReference", "method", "target", "host",
                      "requestSha256", "requestBytes", "rawHeadersSha256", "cutoffUnixMs", "expected"})
    expected_kind = {"source_complete_reply_lost": "source_complete",
                     "destination_complete_reply_lost": "destination_complete"}[case]
    original = prepared["refs"]["completeBody"]
    if (selected["version"] != 1 or isinstance(selected["version"], bool)
            or selected["kind"] != expected_kind or selected["method"] != "POST"
            or type(selected["cutoffUnixMs"]) is not int
            or selected["cutoffUnixMs"] > prepared["cutoffUnixMs"]
            or selected["originalSha256"] != original["sha256"]):
        raise ValueError("provider response arm selects another Complete original")
    raw = read_reference(selected["originalReference"], root, client_io=client_io)
    if (len(raw) != decimal_count(original["bytes"], MAX_METADATA) or hashlib.sha256(raw).hexdigest() != original["sha256"]):
        raise ValueError("provider response arm changed the saved Complete body")
    return selected


def continue_acknowledged_original(supervisor, selection_file, accepted_reference, private_scope_root,
                                   fresh_output, *, prepared, client_io=None,
                                   deadline_monotonic_seconds=None):
    """Calls the selected Native continuation with one retained acknowledged original.

    This precheck binds files and HTTP acknowledgement, not authentication or
    permission. The unchanged Native entry point checks the complete raw reply,
    dispatch markers and every original before advancing normal object phases.
    Its result does not invoke or prove publication Commit.
    """
    if client_io is not None:
        if supervisor is not None or deadline_monotonic_seconds is None:
            raise ValueError("CLIENT continuation requires one guest owner and its selected controller deadline")
    prepared_complete(prepared, private_scope_root, client_io=client_io)
    accepted = json.loads(read_reference(accepted_reference, private_scope_root, client_io=client_io))
    closed(accepted, {"version", "originals"})
    if (type(accepted["version"]) is not int or accepted["version"] != 1
            or not isinstance(accepted["originals"], list) or len(accepted["originals"]) != 1):
        raise ValueError("accepted continuation must select one actual original")
    original = accepted["originals"][0]
    closed(original, {"scope", "prepared", "firstResponse"})
    root = Path(private_scope_root)
    if (original["scope"] != prepared["scope"]
            or original["prepared"]["file"] != str(root / "pre-complete-prepared.json")):
        raise ValueError("accepted continuation selects another prepared original")
    if json.loads(read_reference(original["prepared"], private_scope_root, client_io=client_io)) != prepared:
        raise ValueError("accepted prepared image changed")
    prefix = prepared["refs"]["completeBody"]["file"].removesuffix("-request.json")
    if original["firstResponse"]["file"] != str(root / (prefix + "-response.json")):
        raise ValueError("accepted first-response locator changed")
    response = json.loads(read_reference(original["firstResponse"], private_scope_root, client_io=client_io))
    closed(response, {"status", "request", "reply"})
    if (type(response["status"]) is not int or response["status"] != 200
            or response["request"] != prepared["refs"]["completeBody"]):
        raise ValueError("first Complete has no same-original definitive HTTP200 acknowledgement")
    deadline = float("inf") if deadline_monotonic_seconds is None else deadline_monotonic_seconds
    within_original(prepared, deadline, client_io=client_io)
    accepted_file = Path(accepted_reference["file"])
    if not accepted_file.is_absolute():
        accepted_file = root / accepted_file
    if client_io is not None:
        return client_io.continue_acknowledged(selection_file, str(accepted_file), fresh_output)
    return supervisor.continue_acknowledged(selection_file, str(accepted_file), fresh_output)


def pre_complete_case(prepared, private_scope_root, deadline_monotonic_seconds, *,
                      case, observe, arm_provider_loss=None, scratch_sql=None, client_io=None):
    """Returns Native's two observation refs after installing one actual fault.

    This is a preparation callback, not a Complete dispatcher. Native's owned
    child issues its unchanged prepared request once after this callback returns.
    `observe` must retain actual admission/actor/current-runtime facts in private
    files; those references are not themselves an authority verdict.
    """
    if case in UNAVAILABLE:
        raise ValueError("requested subcase lacks an established runtime seam")
    if case not in {"source_complete_reply_lost", "destination_complete_reply_lost", "native_receipt_insert_refused"}:
        raise ValueError("case cannot use the prepared-Complete boundary")
    item = prepared_complete(prepared, private_scope_root, client_io=client_io)
    within_original(prepared, deadline_monotonic_seconds, client_io=client_io)
    before = observe("before", prepared)
    closed(before, {"admissionObservation", "wrapperObservation"})
    for reference in before.values():
        read_reference(reference, private_scope_root, client_io=client_io)
    if case == "native_receipt_insert_refused":
        if scratch_sql is None or arm_provider_loss is not None:
            raise ValueError("SQL case has no exclusive selected fault owner")
        selected = scratch_sql.selection
        if (selected["sessionId"] != prepared["session"]["sessionId"]
                or selected["logicalFingerprint"] != prepared["session"]["logicalFingerprint"]
                or selected["operationId"] != item["operationId"]
                or selected["expectedResourceVersion"] != prepared["expectedResourceVersion"]):
            raise ValueError("scratch SQL fault selects another prepared original")
        scratch_sql.install_fault()
    else:
        if arm_provider_loss is None or scratch_sql is not None:
            raise ValueError("provider case has no exclusive response owner")
        arm = arm_provider_loss(case, prepared, item)
        provider_arm(prepared, arm, private_scope_root, case, client_io=client_io)
    within_original(prepared, deadline_monotonic_seconds, client_io=client_io)
    return before


def run_prepared_case(driver, observe, retain, *, case, scratch_sql=None, arm_provider_loss=None,
                      continue_original=None, commit_original=None, client_io=None):
    """Calls one same-child handoff and retains failure without implicit reissue.

    `driver` is the published staged supervisor's prepared callback entry point.
    Its returned outcome is retained as a raw file, never turned into PASS here.
    Destination response loss requires known-ACK normal object progression,
    stopping at the unknown reply without publication Commit. The SQL case
    additionally requires a separate publication Commit caller. The queue's
    first acknowledgement alone
    cannot reach the intended final receipt transaction or prove publication.
    """
    if case == "source_complete_reply_lost":
        if continue_original is not None or commit_original is not None:
            raise ValueError("source response loss cannot continue or commit an unknown original")
    elif case == "destination_complete_reply_lost":
        if continue_original is None or commit_original is not None:
            raise ValueError("destination response loss requires known-ACK progression without publication Commit")
    elif case == "native_receipt_insert_refused":
        if continue_original is None or commit_original is None:
            raise ValueError("selected receipt fault requires actual known-ACK progression and publication Commit callers")
    else:
        raise ValueError("case cannot use the prepared-Complete boundary")
    attempted = False
    primary = None
    actual_prepared = None
    original_root = None
    original_deadline = None
    outcome = {"version": 1, "case": case, "driver": None, "objectProgression": None, "commit": None, "after": None,
               "cleanup": "not_required", "phaseQualification": None,
               "providerSettlement": None, "noReissueQualification": None,
               "unavailable": list(UNAVAILABLE)}

    def prepare(prepared, root, deadline):
        nonlocal attempted, actual_prepared, original_root, original_deadline
        actual_prepared = prepared
        original_root = root
        original_deadline = deadline
        attempted = scratch_sql is not None
        return pre_complete_case(prepared, root, deadline, case=case, observe=observe,
                                 arm_provider_loss=arm_provider_loss, scratch_sql=scratch_sql, client_io=client_io)

    try:
        outcome["driver"] = driver(prepare)
        if continue_original is not None:
            if actual_prepared is None:
                raise ValueError("normal progression lacks the actual prepared original")
            within_original(actual_prepared, original_deadline, client_io=client_io)
            outcome["objectProgression"] = continue_original(actual_prepared, outcome["driver"], original_root)
            if commit_original is not None:
                within_original(actual_prepared, original_deadline, client_io=client_io)
                outcome["commit"] = commit_original(actual_prepared, outcome["objectProgression"])
    except BaseException as error:
        primary = error
    finally:
        # The failing Complete/SQL attempt is the case of interest. Retain its
        # actual subsequent observations even when the driver returned no ACK.
        try:
            outcome["after"] = observe("after", actual_prepared)
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                primary.add_note("Staged after-observation failed: " + type(error).__name__)
        if attempted:
            try:
                scratch_sql.remove_fault()
                outcome["cleanup"] = "selected_trigger_removed"
            except BaseException as error:
                outcome["cleanup"] = "unknown"
                if primary is not None:
                    primary.add_note("Selected SQL fault cleanup failed: " + type(error).__name__)
                else:
                    primary = error
        try:
            retain(outcome)
        except BaseException as error:
            if primary is None:
                raise
            primary.add_note("Staged conclusion retention failed: " + type(error).__name__)
        if primary is not None:
            raise primary
    return outcome


def replay_previous_publication(exchange, previous_export_reference, private_root, current_observed_seconds):
    """Prepares a fresh authenticated Publish of an unchanged genuine export.

    The supplied adapter must be the existing shared Rust issuer prepare/verify
    path. A conflict is retained as such; this function does not forge a fork,
    retry a rejected publish, or substitute a transport error for current state.
    """
    previous_export = json.loads(read_reference(previous_export_reference, private_root))
    return exchange({"kind": "publish", "input": previous_export},
                    previous_observed=current_observed_seconds, role="publisher")


def restore_scratch(sql, snapshot, stop_native, start_native, observe_current, retain):
    """Calls selected Native lifetime controls around one exact scratch restore.

    Lifetime callbacks must own the actual selected process, and observations
    must use existing issuer/Native shared Rust verification. Their raw records
    remain separate from a qualification verdict. Remote stores are untouched.
    """
    primary = None
    record = {"version": 1, "databaseName": sql.selection["databaseName"], "snapshot": snapshot,
              "before": None, "stop": None, "restored": None, "restart": None, "after": None,
              "reconciliationQualification": None, "remoteDrain": None}
    try:
        record["before"] = observe_current("before-scratch-restore")
        record["stop"] = stop_native()
        sql.restore(snapshot)
        record["restored"] = "selected_snapshot_applied"
        record["restart"] = start_native()
        record["after"] = observe_current("after-scratch-restore")
    except BaseException as error:
        primary = error
    finally:
        # An uncertain restore/start is never followed by a second launch.
        # The selected scratch process owner retains that stopped/unknown epoch.
        try:
            retain(record)
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                primary.add_note("Scratch restore retention failed: " + type(error).__name__)
    if primary is not None:
        raise primary
    return record


def rotate_credential(controls, binding, credential, secret_version_ref, fingerprint,
                      stage_original, label):
    """Calls actual reviewed rotation and the existing validation workflow.

    New material must already be independently provisioned in private custody.
    This adapter never reads it or constructs an accepted provider/profile.
    """
    if (not re.fullmatch(r"[a-z][a-z0-9-]{0,47}", label)
            or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)
            or credential["bindingId"] != binding["stableId"]
            or str(credential["generation"]) == "0"
            or credential["purpose"] not in {"read", "list", "presign", "write", "delete"}
            or fingerprint == credential["credentialFingerprint"]
            or secret_version_ref == credential["secretVersionRef"]):
        raise ValueError("credential rotation original differs")
    rotated = controls.reviewed("BindingService", "PlanRotateBindingCredential", "RotateBindingCredential", {
        "bindingId": binding["stableId"], "purpose": credential["purpose"],
        "secretVersionRef": secret_version_ref, "credentialFingerprint": fingerprint,
        "expectedResourceVersion": binding["resourceVersion"],
        "expectedCurrentGeneration": str(credential["generation"]),
    }, label + "-rotate")["credential"]
    if (rotated["bindingId"] != binding["stableId"] or rotated["purpose"] != credential["purpose"]
            or int(rotated["generation"]) != int(credential["generation"]) + 1
            or rotated["secretVersionRef"] != secret_version_ref
            or rotated["credentialFingerprint"] != fingerprint):
        raise ValueError("rotation returned another original")
    queued = controls.reviewed("BindingService", "PlanValidateBindingCredential", "ValidateBindingCredential", {
        "bindingId": binding["stableId"], "purpose": rotated["purpose"],
        "generation": str(rotated["generation"]), "expectedResourceVersion": rotated["resourceVersion"],
    }, label + "-validate")["operation"]
    failed = controls.wait_operation(queued["operationId"], {"failed"})
    receipt = stage_original(queued["operationId"], rotated["purpose"])
    current = controls.operation(queued["operationId"])
    if current["resourceVersion"] != failed["resourceVersion"]:
        raise ValueError("unstaged rotation probe changed before staging")
    controls.retry_failed_operation(current, label + "-retry")
    completed = controls.wait_operation(queued["operationId"], {"succeeded"})
    return {"credential": rotated, "staging": receipt, "completedOperation": completed,
            "oldUnknownSettlement": None, "issuerPublication": None}
