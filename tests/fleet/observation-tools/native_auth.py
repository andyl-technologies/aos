"""Join an unchanged observational report to selected Native ingress evidence.

The wrapper does not authenticate a MAC. It checks source-bound records of the
existing Native authentication against independently retained private bodies.
Incomplete custody or context prevents a whole authenticated-body conclusion.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys


PACKAGE_READER = runpy.run_path(str(Path(__file__).resolve(strict=True).parent / "package_context.py"))
PACKAGE = PACKAGE_READER["context"](__file__)
SOURCE = Path(PACKAGE["runtimeSource"])
MAX_BODY = 8 * 1024 * 1024
MAX_LOG = 256 * 1024 * 1024


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def closed_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("Closed selected-input schema differs")


def read_ref(reference, maximum):
    fields(reference, {"file", "sha256", "byteSize"})
    if (not Path(reference["file"]).is_absolute()
            or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])
            or not re.fullmatch(r"0|[1-9][0-9]*", reference["byteSize"])):
        raise ValueError("Private reference is noncanonical")
    raw = private_bytes(reference["file"], maximum)
    if len(raw) != int(reference["byteSize"]) or digest(raw) != reference["sha256"]:
        raise ValueError("Private reference commitment differs")
    return raw


def private_bytes(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_mode & 0o077 or before.st_size > maximum):
            raise ValueError("Private reference custody or bound differs")
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    if (len(raw) != before.st_size
            or any(getattr(before, name) != getattr(after, name) for name in
                   ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
        raise ValueError("Private reference changed")
    return raw


def source_readers(held_log=None):
    """Reuse the current public source's process/log and closed-event readers."""
    capture = runpy.run_path(str(SOURCE / "tests/fleet/_hub-storage-capture.py"))
    window = runpy.run_path(str(SOURCE / "tests/fleet/_hub-managed-storage-window.py"))
    reader = capture["observed_native_messages"]
    reader.__globals__["_closed_review_json"] = closed_json
    if held_log is not None:
        descriptor, path = held_log

        class PinnedLogOs:
            """Let the unchanged reader consume the verified, still-held inode."""

            def __getattr__(self, name):
                return getattr(os, name)

            def open(self, requested, flags):
                if str(requested) != str(path):
                    raise ValueError("Log reader selected another path")
                os.lseek(descriptor, 0, os.SEEK_SET)
                return os.dup(descriptor)

        reader.__globals__["os"] = PinnedLogOs()
    observations = window["ingress_application_observations"]
    observations.__globals__.update(observed_native_messages=reader,
                                   _closed_review_json=closed_json,
                                   native_corpus_json=lambda value: json.dumps(
                                       value, separators=(",", ":")).encode())
    return observations


def ingress_events(selected):
    log = selected["nativeLog"]
    if log is None or selected["nativeProcess"] is None:
        return [], "missing_current_native_log_or_process"
    fields(log, {"reference", "format", "provenance", "epoch"})
    epoch = log["epoch"]
    if epoch is None:
        return [], "missing_native_process_epoch_brackets"
    fields(epoch, {"beforeProcess", "afterProcess", "firstUnixMicros", "lastUnixMicros"})
    process = selected["nativeProcess"]
    for field in ("pid", "ownerUid", "startTicks", "executableSha256"):
        if (epoch["beforeProcess"][field] != process[field]
                or epoch["afterProcess"][field] != process[field]):
            raise ValueError("Native process lifetime changed in selected epoch")
    for field in ("firstUnixMicros", "lastUnixMicros"):
        if not re.fullmatch(r"0|[1-9][0-9]*", epoch[field]):
            raise ValueError("Native epoch time is noncanonical")
    if int(epoch["firstUnixMicros"]) > int(epoch["lastUnixMicros"]):
        raise ValueError("Native epoch clock brackets reversed")
    if log["format"] == "plain":
        if log["provenance"] is None:
            return [], "missing_plain_log_process_window"
        path = Path(log["reference"]["file"])
    elif log["format"] == "journal" and log["provenance"] is None:
        path = read_ref(log["reference"], MAX_LOG).decode()
    else:
        raise ValueError("Native log format/provenance differs")
    if process["executableSha256"] != selected["nativeExecutableSha256"]:
        raise ValueError("Selected Native executable differs")
    if log["format"] == "plain":
        # The path may be replaced after verification. Both passes use this
        # held inode, and the public reader independently checks its hash/EOF.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as held:
            before = os.fstat(held.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or before.st_mode & 0o077 or before.st_size > MAX_LOG):
                raise ValueError("Native log custody differs")
            raw = held.read(MAX_LOG + 1)
            if (str(len(raw)) != log["reference"]["byteSize"]
                    or digest(raw) != log["reference"]["sha256"]
                    or log["provenance"]["window"]["sha256"] != log["reference"]["sha256"]):
                raise ValueError("Native log reference/window differs")
            rows = source_readers((held.fileno(), path))(
                path, process, log["provenance"], selected["nativeSources"])
            after = os.fstat(held.fileno())
            if any(getattr(before, name) != getattr(after, name) for name in
                   ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
                raise ValueError("Held Native log changed across both reads")
    else:
        rows = source_readers()(path, process, log["provenance"], selected["nativeSources"])
    if any(not int(epoch["firstUnixMicros"]) <= int(row["completedAtUnixMicros"])
           <= int(epoch["lastUnixMicros"]) for row in rows):
        raise ValueError("Native event lies outside selected process/clock brackets")
    return rows, None


def frame_matches(frame, reference):
    return (frame["exposedSha256"] == reference["sha256"]
            and frame["exposedBytes"] == reference["byteSize"]
            and frame["eof"] and not frame["failed"] and not frame["overflow"])


def join_capture(capture, events, selected, log_missing):
    """Return source-checked authentication and separate compact-custody states."""
    identifier = capture["requestId"]
    result = {"requestIdSha256": digest(identifier.encode()),
              "sourceCheckedAuthentication": "unknown", "compactCustody": "unknown",
              "independentMacVerification": False, "checkedContexts": None,
              "sourceContractInference": None, "missing": []}
    if log_missing:
        result["missing"].append(log_missing)
        return result
    matches = [row for row in events if row["requestId"] == identifier]
    if len(matches) != 1:
        result["missing"].append("missing_or_ambiguous_exclusive_ingress_event")
        return result
    row = matches[0]
    if (row["method"] != capture["method"]
            or row["pathSha256"] != digest(capture["procedure"].encode())
            or row["phase"] != capture.get("phase") or row["status"] != capture["status"]
            or not frame_matches(row["requestConsumed"], capture["bodies"]["request"])
            or not frame_matches(row["replyOffered"], capture["bodies"]["response"])):
        result["missing"].append("native_event_transport_or_consumed_frame_mismatch")
        return result
    contexts = row["checkedContexts"]
    if (not row["envelopeAuthenticated"] or not row["bodyAuthenticated"]
            or row["stage"] != "handler_completed" or contexts is None
            or contexts["incomplete"]):
        result["missing"].append("missing_completed_source_checked_authentication")
        return result
    result["sourceCheckedAuthentication"] = "observed_native_checked_envelope_and_body"
    result["checkedContexts"] = contexts
    compact = selected["ingressCompacts"].get(identifier)
    if compact is None:
        result["missing"].append("missing_private_received_ingress_compact")
    elif digest(read_ref(compact, 16 * 1024)) != row["compactSha256"]:
        result["missing"].append("received_compact_hash_mismatch")
    else:
        result["compactCustody"] = "retained_bytes_match_native_checked_header"
    if capture["procedure"] == "/-/instance" and capture["status"] == 200:
        result["sourceContractInference"] = "current_management_handler_require_session_and_200"
    return result


def assess(selected, manifest):
    fields(selected, {"version", "runtimeCodecRevision", "sourceDigest", "nativeExecutableSha256",
                      "nativeSources", "nativeProcess", "nativeLog", "ingressCompacts",
                      "observerExecutable", "runtimeProvenance", "outputDirectory"})
    if (selected["version"] != 1
            or selected["runtimeCodecRevision"] != manifest["codecRevision"]
            or selected["sourceDigest"] != manifest["sourceDigest"]):
        raise ValueError("Selected runtime differs from manifest")
    handler = SOURCE / "crates/aos-hub/src"
    expected_sources = {
        "nativeHandlerSourceSha256": digest((handler / "server.rs").read_bytes()
                                            + (handler / "server/hybrid_observation.rs").read_bytes()),
        "checkedContextSourceSha256": digest((SOURCE / "crates/aos-hub-core/src/hybrid_ingress/observation.rs").read_bytes()),
    }
    if (selected["runtimeCodecRevision"] != PACKAGE["runtime"]["runtimeCodecRevision"]
            or selected["sourceDigest"] != PACKAGE["runtime"]["workerSourceDigest"]
            or selected["nativeExecutableSha256"] != PACKAGE["runtime"]["nativeExecutableSha256"]
            or selected["observerExecutable"] != PACKAGE["observerExecutable"]):
        raise ValueError("Selected runtime differs from installed helper")
    if selected["nativeSources"] != expected_sources:
        raise ValueError("Current compiled Native observation source differs")
    provenance = closed_json(read_ref(selected["runtimeProvenance"], 65536))
    fields(provenance, {"version", "runtimeCodecRevision", "nativeExecutableSha256",
                        "workerSourceDigest", "sourceArchiveSha256", "browserSource"})
    if (provenance["runtimeCodecRevision"] != selected["runtimeCodecRevision"]
            or provenance["workerSourceDigest"] != selected["sourceDigest"]
            or provenance["nativeExecutableSha256"] != selected["nativeExecutableSha256"]):
        raise ValueError("Runtime provenance was substituted")
    if provenance != PACKAGE["runtimeProvenance"]:
        raise ValueError("Selected six-field runtime differs from installed helper")
    events, missing = ingress_events(selected)
    rows, external = [], []
    seen = set()
    corpus = 0
    for capture in manifest["captures"]:
        if capture["requestId"] in seen:
            raise ValueError("Capture identity is duplicated")
        seen.add(capture["requestId"])
        for ref in capture["bodies"].values():
            corpus += len(read_ref(ref, MAX_BODY))
            if corpus > 512 * 1024 * 1024:
                raise ValueError("Selected corpus exceeds bound")
        if (capture.get("phase") is not None or capture.get("controlSelection") is not None
                or capture.get("storageWorkSelection") is not None):
            external.append({"requestIdSha256": digest(capture["requestId"].encode()),
                             "requirement": "existing_independent_control_storage_sql_join"})
        else:
            rows.append(join_capture(capture, events, selected, missing))
    return {"version": 1, "scope": "selected source-checked ingress events; no independent MAC verification",
            "wholeIngressContextComplete": all(not row["missing"] for row in rows),
            "captures": rows, "externalJoinRequirements": external,
            "nativeBulkBytes": None}


def observe(executable, manifest):
    """Execute the held hash-selected inode; preserve its stdout bytes exactly."""
    fields(executable, {"file", "sha256", "byteSize"})
    if executable != PACKAGE["observerExecutable"]:
        raise ValueError("Observer is not the installed selected codec")
    with PACKAGE_READER["open_installed"](executable["file"]) as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode)
                or before.st_mode & 0o222 or not before.st_mode & 0o111
                or before.st_size > 512 * 1024 * 1024):
            raise ValueError("Observer executable custody differs")
        if (hashlib.file_digest(source, "sha256").hexdigest() != executable["sha256"]
                or str(before.st_size) != executable["byteSize"]):
            raise ValueError("Observer executable pin differs")
        after = os.fstat(source.fileno())
        if any(getattr(before, name) != getattr(after, name) for name in
               ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
            raise ValueError("Observer executable changed while pinning")
        return subprocess.run(["/proc/self/fd/" + str(source.fileno()), "native-bodies", str(manifest)],
                              pass_fds=(source.fileno(),), stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=600, check=False)


def execute(selection_path, selection_hash, manifest_path):
    raw = private_bytes(selection_path, 1024 * 1024)
    if digest(raw) != selection_hash:
        raise ValueError("Static reviewed sidecar was substituted")
    selected = closed_json(raw)
    manifest_raw = private_bytes(manifest_path, 1024 * 1024)
    if len(raw) > 1024 * 1024 or len(manifest_raw) > 1024 * 1024:
        raise ValueError("Selected sidecar or manifest exceeds bound")
    assessment = assess(selected, closed_json(manifest_raw))
    result = observe(selected["observerExecutable"], manifest_path)
    if result.returncode == 0:
        report = closed_json(result.stdout)
        fields(report, {"version", "codecRevision", "selectedSourceDigest", "manifestSha256",
                        "selectedBodyBytes", "maximumSelectedBodyBytes", "maximumBodyBytes", "captures"})
        if (report["manifestSha256"] != digest(manifest_raw)
                or report["codecRevision"] != selected["runtimeCodecRevision"]
                or report["selectedSourceDigest"] != selected["sourceDigest"]):
            raise ValueError("Observer parsed a different manifest or runtime")
    assessment.update(manifestSha256=digest(manifest_raw), selectedSidecarSha256=selection_hash,
                      observerExitCode=result.returncode, reportSha256=digest(result.stdout))
    directory = Path(selected["outputDirectory"])
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory_fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Private result directory custody differs")
        descriptor = os.open(digest(manifest_raw) + ".json",
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb") as output:
            output.write(json.dumps(assessment, separators=(",", ":")).encode() + b"\n")
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(directory_fd)
    sys.stdout.buffer.write(result.stdout)
    return result.returncode if result.returncode else (0 if assessment["wholeIngressContextComplete"] else 1)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("Expected static sidecar, its pin and one manifest")
        raise SystemExit(execute(*sys.argv[1:]))
    except Exception as error:
        print("Private ingress context join refused: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
