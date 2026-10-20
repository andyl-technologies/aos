"""Supervises separate production Direct signed-closure observation scopes.

This standalone window retains private artifacts without retrying uncertain
mutations. Missing independent provider-start/authentication joins remain unknown.
It does not configure provider resources, queues, or current runtime acceptance.
"""

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time


MAX_SELECTION = 64 * 1024
SCOPES = {"managed_r2", "external_s3"}


def closed(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError("closed staged-window shape differs")
    return value


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_bytes(file, maximum):
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
            raise ValueError("private file owner differs")
        if stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1:
            raise ValueError("private file custody differs")
        if before.st_size > maximum:
            raise ValueError("private file exceeds bound")
        with os.fdopen(os.dup(descriptor), "rb") as reader:
            raw = reader.read(maximum + 1)
        after = os.fstat(descriptor)
        if (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
            before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns
        ) or len(raw) != before.st_size:
            raise ValueError("private file changed during read")
        return raw
    finally:
        os.close(descriptor)


def publication_bytes(file, maximum, validate):
    """Wait only for a validated atomic publication's temporary second link."""
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink not in {1, 2}
                or before.st_size > maximum):
            raise ValueError("private publication custody differs")
        with os.fdopen(os.dup(descriptor), "rb") as reader:
            raw = reader.read(maximum + 1)
        after = os.fstat(descriptor)
        if (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns) != (
                before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) or len(raw) != before.st_size:
            raise ValueError("private publication bytes changed")
        if before.st_nlink == 1:
            if after.st_nlink != 1 or after.st_ctime_ns != before.st_ctime_ns:
                raise ValueError("accepted publication custody changed")
        elif after.st_nlink not in {1, 2} or (after.st_nlink == 2 and after.st_ctime_ns != before.st_ctime_ns):
            raise ValueError("pending publication custody changed")
        validate(raw)
        return None if before.st_nlink == 2 else raw
    finally:
        os.close(descriptor)


def publish_private(root, name, raw):
    """Publish complete durable bytes without replacing an earlier original."""
    if Path(name).name != name or name in {".", ".."}:
        raise ValueError("publication must be a direct private child")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{name}.", suffix=".publication", dir=root)
    linked = False
    try:
        with os.fdopen(descriptor, "wb") as writer:
            writer.write(raw)
            writer.flush()
            os.fsync(writer.fileno())
        os.link(temporary, root / name, follow_symlinks=False)
        linked = True
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            # Readers cannot accept the image until its final link is durable.
            os.fsync(directory)
            os.unlink(temporary)
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        # Failed publication remains pending if the final link already exists.
        if not linked:
            os.unlink(temporary)
    return {"file": str(root / name), "sha256": digest(raw), "byteSize": str(len(raw))}


def referenced(reference, maximum, private=True):
    closed(reference, {"file", "sha256", "byteSize"})
    if private:
        raw = private_bytes(reference["file"], maximum)
    else:
        actual = Path(reference["file"]).resolve(strict=True)
        if str(actual) != reference["file"] or not str(actual).startswith("/nix/store/"):
            raise ValueError("tool must be a canonical immutable store file")
        info = actual.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o222 or not os.access(actual, os.X_OK):
            raise ValueError("selected executable custody differs")
        raw = actual.read_bytes()
        if len(raw) > maximum:
            raise ValueError("selected executable exceeds bound")
    if str(len(raw)) != reference["byteSize"] or digest(raw) != reference["sha256"]:
        raise ValueError("selected reference bytes differ")
    return raw


def child_identity(pid):
    proc = Path(f"/proc/{pid}")
    status = (proc / "status").read_text()
    uid = next(line.split()[1] for line in status.splitlines() if line.startswith("Uid:"))
    tail = (proc / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "uid": uid, "startTicks": tail[19]}


def stop_owned(child, identity, deadline=None):
    if child.poll() is not None:
        return {"status": "exited", "returnCode": child.returncode}
    if identity is None:
        # An unreaped live Popen child cannot have its PID recycled. If /proc
        # sampling failed, stop only that known child; no group/drain claim.
        child.terminate()
    else:
        if child_identity(child.pid) != identity:
            raise ValueError("owned child lifetime changed; no signal sent")
        os.killpg(child.pid, signal.SIGTERM)
    try:
        child.wait(timeout=2 if deadline is None else max(0, min(2, deadline - time.monotonic())))
    except subprocess.TimeoutExpired:
        if identity is None:
            child.kill()
        else:
            if child_identity(child.pid) != identity:
                raise ValueError("owned child lifetime changed before kill")
            os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=2 if deadline is None else max(0, min(2, deadline - time.monotonic())))
    return {"status": "stopped", "returnCode": child.returncode}


def write_private(root, name, raw):
    destination = root / name
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(os.dup(descriptor), "wb") as writer:
            writer.write(raw)
            writer.flush()
            os.fsync(writer.fileno())
    finally:
        os.close(descriptor)
    return {"file": str(destination), "sha256": digest(raw), "byteSize": str(len(raw))}


def summarize(results, selected_scopes):
    if set(results) != set(selected_scopes) or not set(results) <= SCOPES:
        raise ValueError("selected provider scope differs")
    for scope, result in results.items():
        if result["scope"] != scope or result["status"] != "incomplete":
            raise ValueError("fixture may not promote observations to qualification")
        if [item["phase"] for item in result["results"]] != ["complete", "abort"]:
            raise ValueError("closure originals differ")
        for item in result["results"]:
            if item["raceQualification"] is not None or item["cleanupSettlement"] is not None:
                raise ValueError("missing independent race/resource proof was promoted")
    return {"status": "incomplete", "scopes": sorted(results), "raceQualification": None,
            "cleanupSettlement": None, "windowsAAndC": "not_executed"}


def checked_prepared(raw, root, scope_selection):
    """Match the paused child's measured originals without asserting SQL authority."""
    prepared = closed(json.loads(raw), {"version", "state", "method", "controlPath", "runId", "scope",
                      "cutoffUnixMs", "clock", "session", "intent", "status", "placement", "expectedResourceVersion",
                      "sourceSha256", "actorWhoami", "runtimePins", "refs"})
    if type(prepared["version"]) is not int or prepared["version"] != 1:
        raise ValueError("prepared Complete version differs")
    if (prepared["state"] != "prepared_unsent" or prepared["method"] != "CompleteBatch"
            or prepared["controlPath"] != "/aos.hub.v1.DirectUploadService/CompleteBatch"):
        raise ValueError("prepared method or phase differs")
    clock = closed(prepared["clock"], {"bootId", "cutoffUptimeMs"})
    if (not isinstance(clock["bootId"], str) or type(clock["cutoffUptimeMs"]) is not int
            or clock["cutoffUptimeMs"] <= 0):
        raise ValueError("prepared original clock differs")
    discovered = "capabilities" in scope_selection
    for key in ["runId", "scope", "cutoffUnixMs"] + ([] if discovered else ["placement"]):
        if prepared[key] != scope_selection[key]:
            raise ValueError("prepared original selection differs")
    for key in ["actorWhoami", "runtimePins"]:
        if prepared[key] != scope_selection["preComplete"][key]:
            raise ValueError("prepared actor/runtime reference differs")
        referenced(prepared[key], 16384)
    status = prepared["status"]
    if (status["session"] != prepared["session"] or status["intent"] != prepared["intent"]
            or status["placements"] != [prepared["placement"]]
            or status["resourceVersion"] != prepared["expectedResourceVersion"] or status["state"] != "creating"):
        raise ValueError("prepared actual Report status differs")
    closed(prepared["refs"], {"selectionValues", "source", "beginBody", "beginReply", "reportReply", "completeBody", "pendingReceipt"}
           | ({"capabilities"} if discovered else set()))
    images = {}
    for key, reference in prepared["refs"].items():
        closed(reference, {"file", "sha256", "bytes"})
        name = reference["file"]
        if not isinstance(name, str) or Path(name).name != name or name in {".", ".."}:
            raise ValueError("prepared image must be an owned direct child")
        maximum = 8 * 1024 * 1024 if key == "source" else 256 * 1024 if key == "capabilities" else 512 * 1024
        images[key] = referenced({"file": str(root / name), "sha256": reference["sha256"],
                                 "byteSize": reference["bytes"]}, maximum)
    if discovered:
        if images["capabilities"] != referenced(scope_selection["capabilities"], 256 * 1024):
            raise ValueError("prepared raw capability image differs")
        capabilities = closed(json.loads(images["capabilities"]), {
            "target", "deploymentId", "principalId", "version", "capability", "transferMode",
            "configGeneration", "validUntil", "maximumControlBytes", "maximumBatchItems", "maximumBatchParts",
            "minimumObjectBytes", "maximumObjectBytes", "minimumPartBytes", "maximumPartBytes", "profiles"})
        if (type(capabilities["version"]) is not int or capabilities["version"] != 1
                or capabilities["capability"] != "aos.direct.multipart.v1"
                or capabilities["transferMode"] != "direct_required" or len(capabilities["profiles"]) != 1):
            raise ValueError("prepared capability original differs")
        target = scope_selection["targets"]["complete"]["target"]
        if target["kind"] == "publication_object":
            owner = {"kind": "publication", "publicationId": target["publicationId"]}
        elif target["kind"] == "cache_object":
            owner = {"kind": "cache", "cacheId": target["cacheId"]}
        else:
            raise ValueError("unsupported prepared capability owner")
        if capabilities["target"] != owner or prepared["intent"]["target"] != target:
            raise ValueError("prepared capability target differs")
        fields = {"placementId", "placementFingerprint", "placementResourceVersion", "writeSpecVersion",
                  "bindingId", "bindingResourceVersion", "bindingWriteRevision", "profileFingerprint",
                  "privatePolicyDigest", "checksumAlgorithm"}
        profile = closed(capabilities["profiles"][0], (fields - {"placementFingerprint"}) | {"providerOrigin"})
        closed(prepared["placement"], fields)
        for key in fields - {"placementFingerprint"}:
            if profile[key] != prepared["placement"][key]:
                raise ValueError("prepared capability placement differs")
        if profile["providerOrigin"] != scope_selection["providerOrigin"]:
            raise ValueError("prepared capability provider origin differs")
        # This is a public-original comparison. The external source caller must
        # still decode and validate the actual full admission using Core.
    if images["selectionValues"] != json.dumps(scope_selection, separators=(",", ":"), ensure_ascii=False).encode():
        # This compares source-selected values, not a signed protocol projection.
        if json.loads(images["selectionValues"]) != scope_selection:
            raise ValueError("prepared selected values changed")
    if (len(images["source"]) != 8 * 1024 * 1024 or digest(images["source"]) != prepared["sourceSha256"]
            or prepared["intent"]["expectedSha256"] != prepared["sourceSha256"]):
        raise ValueError("prepared source image differs")
    begin = closed(json.loads(images["beginBody"]), {"operationId", "items"})
    if begin["items"] != [prepared["intent"]]:
        raise ValueError("prepared exact Begin original differs")
    body = closed(json.loads(images["completeBody"]), {"operationId", "items"})
    if not isinstance(body["items"], list) or len(body["items"]) != 1:
        raise ValueError("prepared Complete must contain the one original item")
    item = closed(body["items"][0], {"session", "operationId", "expectedResourceVersion", "manifests"})
    if (item["session"] != prepared["session"] or item["expectedResourceVersion"] != prepared["expectedResourceVersion"]
            or len(item["manifests"]) != 1 or item["manifests"][0]["placement"] != prepared["placement"]):
        raise ValueError("prepared Complete originals differ")
    pending = closed(json.loads(images["pendingReceipt"]), {"method", "request", "cutoffUnixMs"})
    if (pending["method"] != "CompleteBatch" or pending["request"] != prepared["refs"]["completeBody"]
            or pending["cutoffUnixMs"] != prepared["cutoffUnixMs"]):
        raise ValueError("prepared pending receipt differs")
    return prepared


def continuation_record(prepared, raw, observations):
    """Retain exact guards and caller-checked observation references, not a ready flag."""
    closed(observations, {"admissionObservation", "wrapperObservation"})
    for reference in observations.values():
        referenced(reference, 65536)
    result = {"version": 1, "preparedSha256": digest(raw),
              "completeBodySha256": prepared["refs"]["completeBody"]["sha256"]}
    for key in ["runId", "scope", "session", "placement", "expectedResourceVersion", "sourceSha256", "cutoffUnixMs",
                "actorWhoami", "runtimePins"]:
        result[key] = prepared[key]
    result.update(observations)
    return result


def handoff_owner(before_complete, external_pre_complete):
    """Select one explicit owner without interpreting a continuation as readiness."""
    if type(external_pre_complete) is not bool:
        raise ValueError("external preparation owner must be explicit")
    if before_complete is not None and not callable(before_complete):
        raise ValueError("preparation callback is unavailable")
    if callable(before_complete) and external_pre_complete:
        raise ValueError("preparation must have only one selected owner")
    return callable(before_complete) or external_pre_complete


def checked_external_continuation(prepared, raw, root):
    """Check an external owner's immutable guards, not its SQL/installation claims."""
    continuation = json.loads(private_bytes(root / "pre-complete-continuation.json", MAX_SELECTION))
    if type(continuation.get("version")) is not int or continuation["version"] != 1:
        raise ValueError("external continuation version differs")
    observations = {key: continuation[key] for key in ["admissionObservation", "wrapperObservation"]}
    if continuation != continuation_record(prepared, raw, observations):
        raise ValueError("external continuation originals differ")
    return continuation


def checked_accepted(accepted, scope_selection):
    """Match the actual initial response image, without certifying its authentication."""
    closed(accepted, {"version", "prepared", "firstResponse"})
    if type(accepted["version"]) is not int or accepted["version"] != 1:
        raise ValueError("accepted-original version differs")
    raw = referenced(accepted["prepared"], MAX_SELECTION)
    root = Path(accepted["prepared"]["file"]).parent
    if (root.resolve(strict=True) != root or root.stat().st_uid != os.getuid()
            or stat.S_IMODE(root.stat().st_mode) != 0o700
            or Path(accepted["prepared"]["file"]).name != "pre-complete-prepared.json"):
        raise ValueError("accepted original directory differs")
    prepared = checked_prepared(raw, root, scope_selection)
    checked_external_continuation(prepared, raw, root)
    prefix = prepared["refs"]["completeBody"]["file"].removesuffix("-request.json")
    if accepted["firstResponse"]["file"] != str(root / f"{prefix}-response.json"):
        raise ValueError("first acknowledgement locator differs")
    response = closed(json.loads(referenced(accepted["firstResponse"], MAX_SELECTION)), {"status", "request", "reply"})
    if type(response["status"]) is not int or response["status"] != 200 or response["request"] != prepared["refs"]["completeBody"]:
        raise ValueError("initial Complete has no definitive HTTP200 acknowledgement")
    reference = closed(response["reply"], {"file", "bytes", "sha256"})
    if reference["file"] != f"{prefix}-reply.json":
        raise ValueError("initial Complete reply locator differs")
    reply = closed(json.loads(referenced({"file": str(root / reference["file"]), "byteSize": reference["bytes"],
                                         "sha256": reference["sha256"]}, 256 * 1024)),
                   {"operationId", "sessions", "grants", "errors"})
    body = json.loads(private_bytes(root / prepared["refs"]["completeBody"]["file"], MAX_SELECTION))
    if (reply["operationId"] != body["operationId"] or reply["errors"] != [] or reply["grants"] != []
            or not isinstance(reply["sessions"], list) or len(reply["sessions"]) != 1):
        raise ValueError("initial Complete acknowledgement differs")
    status = reply["sessions"][0]
    if (status["session"] != prepared["session"] or status["intent"] != prepared["intent"]
            or status["placements"] != [prepared["placement"]]
            or status["state"] not in {"completing_staging", "staged_verified"}):
        raise ValueError("initial Complete pending original differs")
    return prepared


def continue_acknowledged(selection_file, accepted_originals_file, output_directory):
    """Supervise only progression of acknowledged originals, without staging again."""
    return run(selection_file, output_directory, accepted_originals_file=accepted_originals_file)


def run(selection_file, output_directory, before_complete=None, external_pre_complete=False, accepted_originals_file=None):
    owner_selected = handoff_owner(before_complete, external_pre_complete)
    if accepted_originals_file is not None and owner_selected:
        raise ValueError("accepted progression cannot stage or choose a new preparation owner")
    accepted_raw = None
    accepted_originals = {}
    if accepted_originals_file is not None:
        accepted_raw = private_bytes(accepted_originals_file, MAX_SELECTION)
        selected = closed(json.loads(accepted_raw), {"version", "originals"})
        if (type(selected["version"]) is not int or selected["version"] != 1
                or not isinstance(selected["originals"], list) or not 1 <= len(selected["originals"]) <= 2):
            raise ValueError("accepted-original selection differs")
        for original in selected["originals"]:
            closed(original, {"scope", "prepared", "firstResponse"})
            if original["scope"] not in SCOPES or original["scope"] in accepted_originals:
                raise ValueError("accepted-original scopes differ")
            accepted_originals[original["scope"]] = {"version": 1, "prepared": original["prepared"],
                                                      "firstResponse": original["firstResponse"]}
    raw = private_bytes(selection_file, MAX_SELECTION)
    selection = closed(json.loads(raw), {"version", "node", "driver", "scopeSelections", "cutoffUnixMs"})
    if type(selection["version"]) is not int or selection["version"] != 1:
        raise ValueError("staged window version differs")
    cutoff = selection["cutoffUnixMs"]
    remaining = cutoff / 1000 - time.time() if type(cutoff) is int else -1
    if not 0 < remaining <= 180:
        raise ValueError("original staged window is unavailable")
    monotonic_cutoff = time.monotonic() + remaining
    referenced(selection["node"], 256 * 1024 * 1024, private=False)
    driver = referenced(selection["driver"], 128 * 1024)
    if not isinstance(selection["scopeSelections"], list) or not 1 <= len(selection["scopeSelections"]) <= 2:
        raise ValueError("one or two independent provider selections required")
    inputs = []
    seen = set()
    for reference in selection["scopeSelections"]:
        scope_raw = referenced(reference, MAX_SELECTION)
        scope = json.loads(scope_raw)
        if scope["scope"] not in SCOPES or scope["scope"] in seen or scope["cutoffUnixMs"] != cutoff:
            raise ValueError("provider scopes or original cutoff differ")
        seen.add(scope["scope"])
        handoff = "preComplete" in scope
        if handoff and not owner_selected and accepted_raw is None:
            raise ValueError("prepare mode requires an actual callback or explicit external owner")
        if accepted_raw is not None:
            if not handoff or scope["scope"] not in accepted_originals:
                raise ValueError("accepted progression must select retained prepared originals")
            prepared = checked_accepted(accepted_originals[scope["scope"]], scope)
            clock = prepared["clock"]
            if clock["bootId"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip():
                raise ValueError("original process boot differs")
            uptime = float(Path("/proc/uptime").read_text().split()[0])
            monotonic_cutoff = min(monotonic_cutoff, time.monotonic() + clock["cutoffUptimeMs"] / 1000 - uptime)
        inputs.append((scope["scope"], scope_raw, handoff))
    if accepted_raw is not None and set(accepted_originals) != seen:
        raise ValueError("accepted-original scope coverage differs")

    if any(handoff for _, _, handoff in inputs) and not all(handoff for _, _, handoff in inputs):
        raise ValueError("signed races and preparation require separate selected windows")
    root = Path(output_directory)
    root.mkdir(mode=0o700)
    write_private(root, "selection.json", raw)
    driver_ref = write_private(root, "driver.mjs", driver)
    if accepted_raw is not None:
        write_private(root, "accepted-originals-selection.json", accepted_raw)
    results = {}
    receipts = []
    try:
        for scope, scope_raw, handoff in inputs:
            scope_ref = write_private(root, f"{scope}-selection.json", scope_raw)
            stdout_file = root / f"{scope}-stdout.private"
            stderr_file = root / f"{scope}-stderr.private"
            if min(monotonic_cutoff - time.monotonic(), cutoff / 1000 - time.time()) <= 4:
                raise ValueError("original window has no owned-cleanup reserve")
            with open(stdout_file, "xb") as stdout, open(stderr_file, "xb") as stderr:
                os.chmod(stdout_file, 0o600)
                os.chmod(stderr_file, 0o600)
                argv = [selection["node"]["file"], driver_ref["file"], scope_ref["file"], str(root / scope)]
                if accepted_raw is not None:
                    accepted_ref = write_private(root, f"{scope}-accepted.json",
                        json.dumps(accepted_originals[scope], separators=(",", ":")).encode())
                    argv.extend(["--continue-accepted", accepted_ref["file"]])
                child = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
                identity = None
                cleanup = None
                try:
                    identity = child_identity(child.pid)
                    deadline = min(monotonic_cutoff - time.monotonic(), cutoff / 1000 - time.time()) - 4
                    if deadline <= 0:
                        raise subprocess.TimeoutExpired("original staged window", 0)
                    callback_done = False
                    prepared_file = root / scope / "pre-complete-prepared.json"
                    while child.poll() is None:
                        remaining = min(monotonic_cutoff - time.monotonic(), cutoff / 1000 - time.time()) - 4
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired("original staged window", 0)
                        if handoff and accepted_raw is None and not callback_done and prepared_file.exists():
                            prepared_raw = publication_bytes(prepared_file, MAX_SELECTION,
                                lambda value: checked_prepared(value, root / scope, json.loads(scope_raw)))
                            if prepared_raw is None:
                                time.sleep(min(0.025, remaining))
                                continue
                            prepared = checked_prepared(prepared_raw, root / scope, json.loads(scope_raw))
                            # The selected source caller owns bounded SQL/installation
                            # operations. Its deadline grants no extension to this child.
                            if external_pre_complete:
                                # The host owner reads these existing guest files and
                                # writes continuation only after its actual independent checks.
                                callback_done = True
                                continue
                            observations = before_complete(json.loads(prepared_raw), root / scope,
                                                           time.monotonic() + remaining)
                            callback_done = True
                            if (time.monotonic() >= monotonic_cutoff - 4 or time.time() >= cutoff / 1000 - 4):
                                raise ValueError("original preparation window expired")
                            if private_bytes(prepared_file, MAX_SELECTION) != prepared_raw:
                                raise ValueError("prepared originals changed during callback")
                            checked_prepared(prepared_raw, root / scope, json.loads(scope_raw))
                            continuation = continuation_record(prepared, prepared_raw, observations)
                            publish_private(root / scope, "pre-complete-continuation.json",
                                          json.dumps(continuation, separators=(",", ":"), ensure_ascii=False).encode())
                        time.sleep(min(0.025, remaining))
                    return_code = child.returncode
                    if handoff and accepted_raw is None and external_pre_complete and return_code == 2:
                        prepared_raw = private_bytes(prepared_file, MAX_SELECTION)
                        prepared = checked_prepared(prepared_raw, root / scope, json.loads(scope_raw))
                        checked_external_continuation(prepared, prepared_raw, root / scope)
                finally:
                    try:
                        cleanup = stop_owned(child, identity, monotonic_cutoff)
                    except (OSError, ValueError, subprocess.SubprocessError):
                        cleanup = {"status": "unknown"}
                        raise
                    finally:
                        receipts.append({"scope": scope, "process": identity, "cleanup": cleanup,
                                         "stdoutFile": str(stdout_file), "stderrFile": str(stderr_file)})
            if return_code != 2:
                raise ValueError("original mutation outcome unavailable; do not retry")
            result = json.loads(private_bytes(root / scope / "result.json", MAX_SELECTION))
            results[scope] = result
        if accepted_raw is not None:
            for result in results.values():
                if (result["mode"] != "accepted_original_continuation" or result["status"] != "incomplete"
                        or result["publicationCommit"] != "not_invoked" or len(result["results"]) != 1
                        or result["results"][0]["terminalState"] != "committed"
                        or result["results"][0]["raceQualification"] is not None):
                    raise ValueError("accepted original progression was promoted")
            report = {"status": "incomplete", "scopes": sorted(results), "mode": "accepted_original_continuation",
                      "publicationCommit": "not_invoked", "raceQualification": None,
                      "cleanupSettlement": None, "windowsAAndC": "not_executed"}
        elif any(handoff for _, _, handoff in inputs):
            for result in results.values():
                if (result["mode"] != "pre_complete_handoff" or result["status"] != "incomplete"
                        or len(result["results"]) != 1 or result["results"][0]["phase"] != "complete"
                        or result["results"][0]["raceQualification"] is not None):
                    raise ValueError("prepared control observation was promoted")
            report = {"status": "incomplete", "scopes": sorted(results), "mode": "pre_complete_handoff",
                      "raceQualification": None, "cleanupSettlement": None, "windowsAAndC": "not_executed"}
        else:
            report = summarize(results, seen)
        write_private(root, "summary.json", json.dumps(report, separators=(",", ":")).encode())
        return report
    finally:
        write_private(root, "supervision.json", json.dumps({"cutoffUnixMs": cutoff, "receipts": receipts},
                      separators=(",", ":")).encode())


if __name__ == "__main__":
    try:
        external = len(sys.argv) == 4 and sys.argv[3] == "--external-pre-complete"
        continuing = len(sys.argv) == 5 and sys.argv[3] == "--continue-accepted"
        if len(sys.argv) != 3 and not external and not continuing:
            raise ValueError("selection, fresh private output and optional external preparation flag required")
        if continuing:
            continue_acknowledged(sys.argv[1], sys.argv[4], sys.argv[2])
        else:
            run(sys.argv[1], sys.argv[2], external_pre_complete=external)
        print(json.dumps({"status": "incomplete", "summaryFile": str(Path(sys.argv[2]) / "summary.json")}))
        raise SystemExit(2)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError):
        print("staged window unavailable; retain private originals; do not replay mutations", file=sys.stderr)
        raise SystemExit(1)
