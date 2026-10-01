"""Assess accepted-workload Native bytes from actual closed codecs and receipts.

The independently selected source-built observer parses every retained Native
body. Its source and console assets must match the installed runtime. The
assessment also requires actual authenticated Worker joins and complete provider
caller/original classification. A missing receipt or unsupported class refuses
the conclusion; injected failure windows retain their own explicit scope.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


DIRECT_NATIVE_ALLOWED_BODY_CLASSES = frozenset((
    "public_protojson_control_metadata", "issuer_control_metadata",
    "logical_control_with_optional_normalized_narinfo_or_oci_projection",
    "authenticated_instance_app_shell_html", "browser_session_token_metadata",
))

DIRECT_STORAGE_ALLOWED_BODY_CLASSES = frozenset((
    "storage_control_metadata", "storage_negative_protocol_metadata",
    "storage_selected_git_content", "storage_selected_git_tree_rows",
    "storage_exact_metadata_document", "storage_exact_metadata_document_page",
    "storage_documentation_index_projection", "storage_documentation_canonical_model",
))


def observe_direct_native_executable(native, tools, expected_sha256):
    """Bind the actual running Native process to the installed immutable binary."""
    observed = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        result = subprocess.run(['systemctl', 'show', '--property=MainPID', '--value',
            'aos-hub.service'], capture_output=True, check=True, timeout=10)
        pid = int(result.stdout)
        root = Path('/proc') / str(pid)
        before = (root / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        with (root / 'exe').open('rb') as executable:
            digest = hashlib.file_digest(executable, 'sha256').hexdigest()
        after = (root / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        if before != after or digest != selected['expectedSha256']:
            raise ValueError('running Native lifetime or installed executable differs')
        print(json.dumps({'version': 1, 'pid': pid, 'startTicks': before,
            'executableSha256': digest, 'machineRole': 'native',
            'scope': 'actual running binary; source provenance is independently selected'}))
    """, {"expectedSha256": expected_sha256}, timeout=30))
    retain_direct_flow("publication-native-executable.json", observed)
    return observed


def run_direct_native_codec_observer(selection, manifest):
    """Execute only the selected held, hashed source-built observational binary."""
    reference = selection["observerExecutable"]
    if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
            or not Path(reference["path"]).is_absolute()
            or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])):
        raise ValueError("Native codec executable selection is invalid")
    descriptor = os.open(reference["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        first = os.fstat(descriptor)
        if (not stat.S_ISREG(first.st_mode) or first.st_uid not in {0, os.geteuid()}
                or first.st_mode & 0o022 or not first.st_mode & 0o111
                or first.st_size > 512 * 1024 * 1024):
            raise ValueError("Native codec executable custody or bound refused")
        with os.fdopen(os.dup(descriptor), "rb") as source:
            actual_sha = hashlib.file_digest(source, "sha256").hexdigest()
        last = os.fstat(descriptor)
        if (actual_sha != reference["sha256"] or any(getattr(first, name) != getattr(last, name)
                for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
            raise ValueError("Native codec executable changed from the reviewed original")
        # The child inherits the held descriptor, so execution cannot select a
        # different inode through a replaced pathname after the hash check.
        try:
            result = subprocess.run(["/proc/self/fd/" + str(descriptor), str(manifest.resolve())],
                pass_fds=(descriptor,), stdin=subprocess.DEVNULL, capture_output=True,
                check=False, timeout=600)
            stdout, stderr = result.stdout, result.stderr
            exit_code, timed_out = result.returncode, False
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b"", error.stderr or b""
            exit_code, timed_out = None, True
    finally:
        os.close(descriptor)
    retain_direct_flow("native-codec-observer.stdout.json", stdout)
    retain_direct_flow("native-codec-observer.stderr", stderr)
    retain_direct_flow("native-codec-observer-execution.json", {
        "version": 1, "exitCode": exit_code, "timedOut": timed_out,
        "executableSha256": actual_sha, "manifestSha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "scope": "selected actual source-built codec; not network or authority observation",
    })
    if exit_code != 0 or len(stdout) > 16 * 1024 * 1024:
        raise RuntimeError("Native body codec refused; complete actual captures remain retained")
    return _closed_review_json(stdout)


def direct_release_storage_budget(projections, release_placements):
    """Attribute actual storage calls to retained release placement namespaces."""
    if not release_placements:
        raise ValueError("per-release storage budget lacks actual selected placement receipts")
    by_prefix = {}
    for selected in release_placements:
        if (set(selected) != {"registrySlug", "release", "sourceCommit", "placement"}
                or not re.fullmatch(r"[0-9a-f]{64}", selected["sourceCommit"])
                or not selected["placement"]["prefix"]):
            raise ValueError("per-release selected placement identity differs")
        prefix = hashlib.sha256(selected["placement"]["prefix"].encode()).hexdigest()
        if prefix in by_prefix:
            raise ValueError("per-release storage ownership is ambiguous")
        by_prefix[prefix] = selected
    releases, unassigned = {}, []
    for projection in projections:
        observed = projection["observation"]
        owner = by_prefix.get(observed["placementPrefixSha256"])
        if owner is None:
            unassigned.append(projection["requestId"])
            continue
        key = owner["registrySlug"] + "@" + owner["release"]
        row = releases.setdefault(key, {"registrySlug": owner["registrySlug"],
            "release": owner["release"], "sourceCommit": owner["sourceCommit"],
            "placementPrefixSha256": observed["placementPrefixSha256"],
            "calls": 0, "requestBytes": 0, "replyBytes": 0, "executorSourceBytes": 0,
            "operations": {}, "payloadBytesByKind": {}})
        row["calls"] += 1
        for name in ("requestBytes", "replyBytes"):
            row[name] += projection[name]
        row["executorSourceBytes"] += int(observed["executorSourceBytes"])
        operation = row["operations"].setdefault(observed["operation"], {
            "calls": 0, "maximumRequestBytes": 0, "maximumReplyBytes": 0})
        operation["calls"] += 1
        operation["maximumRequestBytes"] = max(operation["maximumRequestBytes"], projection["requestBytes"])
        operation["maximumReplyBytes"] = max(operation["maximumReplyBytes"], projection["replyBytes"])
        for kind, value in observed["payload"].items():
            row["payloadBytesByKind"][kind] = row["payloadBytesByKind"].get(kind, 0) + int(value)
    result = {"version": 1, "releases": list(releases.values()),
        "unassignedRequestIds": unassigned,
        "scope": "actual accepted business window calls attributed by independently typed original placement prefix; no division by release count, no claim of per-release-only background isolation"}
    retain_direct_flow("actual-per-release-storage-budget.json", result)
    if unassigned or len(releases) != len(release_placements):
        raise ValueError("per-release storage attribution is incomplete; actual counts retained")
    return result


def direct_storage_codec_selection(selection, source_digest):
    """Preserve the independently observed completion beside the exact original."""
    if (not isinstance(selection, dict) or set(selection) != {
            "sourceDigest", "originalPlan", "completionObservedAtUnixMillis"}
            or selection["sourceDigest"] != source_digest):
        raise ValueError("StorageWork codec selection differs from its actual source")
    completed = selection["completionObservedAtUnixMillis"]
    if not isinstance(completed, str) or not re.fullmatch(r"[1-9][0-9]{0,15}", completed):
        raise ValueError("StorageWork lacks a canonical positive proxy completion observation")
    original = selection["originalPlan"]
    return {"sourceDigest": source_digest, "completionObservedAtUnixMillis": completed,
        "originalPlan": {**original, "file": str(Path(original["file"]).resolve()),
            "byteSize": str(original["byteSize"])}}



def direct_control_codec_selection(selection, source_digest):
    """Preserve the exact independently selected original and installed audience."""
    if (not isinstance(selection, dict) or set(selection) != {
            "sourceDigest", "deploymentId", "originalRequest"}
            or selection["sourceDigest"] != source_digest
            or not isinstance(selection["deploymentId"], str)
            or not re.fullmatch(r"[a-zA-Z0-9._-]{1,128}", selection["deploymentId"])):
        raise ValueError("control codec selection differs from its actual source or audience")
    original = selection["originalRequest"]
    if (not isinstance(original, dict) or set(original) != {"file", "sha256", "byteSize"}
            or not isinstance(original["file"], str) or not Path(original["file"]).is_absolute()
            or not isinstance(original["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", original["sha256"])
            or type(original["byteSize"]) is not int or not 0 <= original["byteSize"] <= WORKER_CONTROL_REPLY_LIMIT):
        raise ValueError("control codec original descriptor differs from the captured bytes")
    return {"sourceDigest": source_digest, "deploymentId": selection["deploymentId"],
        "originalRequest": {**original, "file": str(Path(original["file"]).resolve()),
            "byteSize": str(original["byteSize"])}}


def direct_control_codec_join(item, capture, positive, source_digest):
    """Require typed original correlation beside actual protected-handler proof."""
    typed = item.get("control")
    fields = {"operation", "selectedSourceDigest", "originalRequestSha256",
        "originalRequestSemanticSha256", "deploymentIdSha256", "challengeNonceSha256",
        "originalContextSha256", "returnedProtectedMaterialBytes", "correlationValidatorSourceSha256"}
    selected = capture["controlSelection"]
    original = selected["originalRequest"]
    if (positive is None or not isinstance(typed, dict) or set(typed) != fields
            or item["class"] != "storage_control_metadata"
            or item["authentication"] != "not_checked_join_independent_authenticated_worker_receipt"
            or typed["selectedSourceDigest"] != source_digest
            or typed["originalRequestSha256"] != original["sha256"]
            or typed["originalRequestSemanticSha256"] != item["request"]["typedSemanticSha256"]
            or typed["deploymentIdSha256"] != hashlib.sha256(selected["deploymentId"].encode()).hexdigest()
            or typed["returnedProtectedMaterialBytes"] != "0"
            or positive["compiledSource"] != source_digest or positive["route"] != capture["procedure"]
            or positive["requestSha256"] != item["request"]["sha256"]
            or positive["replySha256"] != item["response"]["sha256"]
            or positive["requestBytes"] != int(item["request"]["byteSize"])
            or positive["replyBytes"] != int(item["response"]["byteSize"])
            or not positive["handlerCompletedAtUnixMillis"]):
        raise ValueError("typed control metadata lacks its exact actual authenticated-handler join")
    for name in ("originalRequestSemanticSha256", "originalContextSha256", "correlationValidatorSourceSha256"):
        if not isinstance(typed[name], str) or not re.fullmatch(r"[0-9a-f]{64}", typed[name]):
            raise ValueError("typed control correlation commitment is invalid")
    if (not isinstance(typed["operation"], str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", typed["operation"])
            or (typed["challengeNonceSha256"] is not None and (
                not isinstance(typed["challengeNonceSha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", typed["challengeNonceSha256"])))):
        raise ValueError("typed control operation or challenge commitment is invalid")
    return {"requestId": capture["requestId"], "class": item["class"],
        "requestBytes": int(item["request"]["byteSize"]),
        "replyBytes": int(item["response"]["byteSize"]), "observation": typed,
        "authenticatedHandlerReceiptSemanticSha256": positive["handlerReceiptSemanticSha256"],
        "handlerCompletedAtUnixMillis": positive["handlerCompletedAtUnixMillis"]}

def assess_direct_native_bodies(body_receipts, control_joins, provider_classification,
                               mapping, source_digest, issuer_verifier, native_executable,
                               storage_work_boundary=None, release_placements=None):
    """Require complete positive-workload type and provider evidence before zero."""
    if storage_work_boundary is None:
        raise ValueError("Native outbound StorageWork bodies remain unclassified; bulk bytes stay unknown")
    if (not isinstance(storage_work_boundary, dict)
            or storage_work_boundary["unresolvedNativeRequestIds"]
            or storage_work_boundary["receivedWithoutOriginal"]
            or len(storage_work_boundary["captures"]) != storage_work_boundary["actualNativeRequests"]
            or len(storage_work_boundary["authenticatedCompletions"]) != storage_work_boundary["actualNativeRequests"]):
        raise ValueError("actual Native outbound original/received/authenticated coverage is incomplete")
    if body_receipts["incompleteCaptures"] or control_joins["unresolvedDirectRequestIds"]:
        raise ValueError("Native accepted-workload capture or authenticated joins are incomplete")
    if (provider_classification["unresolvedReceiptIndexes"]
            or provider_classification["unknownCallers"]
            or provider_classification["nativeProviderCalls"]):
        raise ValueError("provider accepted-workload caller/original classification is incomplete")
    hashes = {
        "nativeBodies": retain_direct_flow("native-codec-capture-inputs.json", body_receipts),
        "authenticatedControls": retain_direct_flow("native-codec-authenticated-inputs.json", control_joins),
        "providerClassification": retain_direct_flow("native-codec-provider-inputs.json", provider_classification),
        "physicalOriginals": retain_direct_flow("native-codec-physical-inputs.json", mapping),
        "nativeExecutable": retain_direct_flow("native-codec-executable-inputs.json", native_executable),
        "nativeOutboundBodies": retain_direct_flow("native-codec-storage-inputs.json", storage_work_boundary),
    }
    reviewed = await_direct_review("native-capture-codecs", hashes,
        {"observerExecutable", "runtimeCodecRevision", "runtimeProvenance"})
    selection = reviewed["selection"]
    revision = selection["runtimeCodecRevision"]
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Native runtime codec revision is invalid")
    provenance = _closed_review_json(direct_selected_bytes(selection["runtimeProvenance"], 65536))
    if (not isinstance(provenance, dict) or set(provenance) != {
            "version", "runtimeCodecRevision", "nativeExecutableSha256", "workerSourceDigest",
            "sourceArchiveSha256", "browserSource"}
            or type(provenance["version"]) is not int or provenance["version"] != 1
            or provenance["runtimeCodecRevision"] != revision
            or provenance["nativeExecutableSha256"] != native_executable["executableSha256"]
            or provenance["workerSourceDigest"] != source_digest
            or not re.fullmatch(r"[0-9a-f]{64}", provenance["sourceArchiveSha256"])):
        raise ValueError("reviewed codec provenance does not match the installed runtime")
    captures = []
    for capture in [*body_receipts["bodies"], *storage_work_boundary["captures"]]:
        selected = {**capture, "phase": capture["phase"] or None,
            "responseContentType": capture["responseContentType"] or None,
            "responseContentEncoding": capture["responseContentEncoding"] or None,
            "bodies": {direction: {**body, "file": str(Path(body["file"]).resolve()),
                "byteSize": str(body["byteSize"])} for direction, body in capture["bodies"].items()}}
        if "storageWorkSelection" in selected:
            selected["storageWorkSelection"] = direct_storage_codec_selection(
                selected["storageWorkSelection"], source_digest,
            )
        if "controlSelection" in selected:
            selected["controlSelection"] = direct_control_codec_selection(
                selected["controlSelection"], source_digest,
            )
        captures.append(selected)
    selected_corpus_bytes = body_receipts["capturedCorpusBytes"] + sum(
        int(body["byteSize"]) for capture in storage_work_boundary["captures"]
        for body in capture["bodies"].values())
    if selected_corpus_bytes > NATIVE_CAPTURE_CORPUS_LIMIT or len(captures) > NATIVE_CAPTURE_COUNT_LIMIT:
        raise ValueError("combined Native inbound/outbound corpus exceeds the selected observer bounds")
    manifest = {"version": 1, "codecRevision": revision, "sourceDigest": source_digest,
        "issuerVerifier": issuer_verifier, "captures": captures}
    manifest_path = Path("external-direct-flow/native-codec-manifest-private.json")
    manifest_sha = retain_direct_flow(manifest_path.name, manifest)
    parsed = run_direct_native_codec_observer(selection, manifest_path)
    if (not isinstance(parsed, dict) or set(parsed) != {
            "version", "codecRevision", "selectedSourceDigest", "manifestSha256",
            "selectedBodyBytes", "maximumSelectedBodyBytes", "maximumBodyBytes", "captures"}
            or type(parsed["version"]) is not int or parsed["version"] != 1
            or parsed["codecRevision"] != revision or parsed["selectedSourceDigest"] != source_digest
            or parsed["manifestSha256"] != manifest_sha
            or int(parsed["selectedBodyBytes"]) != selected_corpus_bytes
            or int(parsed["maximumSelectedBodyBytes"]) != NATIVE_CAPTURE_CORPUS_LIMIT
            or int(parsed["maximumBodyBytes"]) != WORKER_CONTROL_REPLY_LIMIT
            or len(parsed["captures"]) != len(captures)):
        raise ValueError("codec observation differs from the complete selected Native corpus")
    actual = {hashlib.sha256(capture["requestId"].encode()).hexdigest(): capture for capture in captures}
    if len(actual) != len(captures):
        raise ValueError("combined Native capture request ownership is ambiguous")
    joined = {item["requestId"]: item for item in control_joins["joined"]}
    storage_joins = {item["requestId"]: item for item in storage_work_boundary["authenticatedCompletions"]}
    storage_projections, control_projections = [], []
    seen = set()
    for item in parsed["captures"]:
        identifier = item["requestIdSha256"]
        capture = actual.get(identifier)
        outbound = "storageWorkSelection" in (capture or {}) or "controlSelection" in (capture or {})
        allowed = DIRECT_STORAGE_ALLOWED_BODY_CLASSES if outbound else DIRECT_NATIVE_ALLOWED_BODY_CLASSES
        if (capture is None or identifier in seen or item["class"] not in allowed
                or item["procedure"] != capture["procedure"] or item["phase"] != capture["phase"]):
            raise ValueError("codec class or original capture ownership changed")
        seen.add(identifier)
        for direction in ("request", "response"):
            expected = capture["bodies"][direction]
            if (item[direction]["sha256"] != expected["sha256"]
                    or item[direction]["byteSize"] != expected["byteSize"]):
                raise ValueError("typed Native body differs from its actual HTTP receipt")
        if item["class"].startswith("logical_control_"):
            positive = joined.get(capture["requestId"])
            if positive is None or (positive["requestSha256"], positive["replySha256"]) != (
                    item["request"]["sha256"], item["response"]["sha256"]) or (
                    positive["publicRequestSha256"] != item["originalPublicRequestSha256"]):
                raise ValueError("typed logical body lacks its exact authenticated production join")
        if item["browserSource"] is not None and item["browserSource"] != provenance["browserSource"]:
            raise ValueError("browser template or compiled assets differ from the installed source")
        if "controlSelection" in capture:
            control_projections.append(direct_control_codec_join(item, capture,
                storage_joins.get(capture["requestId"]), source_digest))
        if "storageWorkSelection" in capture:
            positive = storage_joins.get(capture["requestId"])
            typed = item.get("storageWork")
            original = capture["storageWorkSelection"]["originalPlan"]
            if (positive is None or typed is None
                    or positive["requestSha256"] != item["request"]["sha256"]
                    or positive["replySha256"] != item["response"]["sha256"]
                    or typed["originalPlanSha256"] != original["sha256"]
                    or typed["selectedSourceDigest"] != source_digest
                    or typed["planIdSha256"] != positive["planIdSha256"]
                    or typed["operation"] != positive["operation"]
                    or int(typed["executorSourceBytes"]) != positive["executorSourceBytes"]
                    or int(typed["payload"]["returnedWholeOciObjectBytes"]) != 0
                    or int(typed["payload"]["returnedOciRangeBytes"]) != 0):
                raise ValueError("typed storage projection lacks exact production provenance or contains whole raw object bytes")
            storage_projections.append({"requestId": capture["requestId"], "class": item["class"],
                "requestBytes": int(item["request"]["byteSize"]), "replyBytes": int(item["response"]["byteSize"]),
                "observation": typed})
    if seen != set(actual):
        raise ValueError("Native codec observation omitted an actual accepted-workload request")
    release_budget = direct_release_storage_budget(storage_projections, release_placements)
    assessment = {"version": 1, "nativeBulkBytes": 0,
        "nativeClassifiedRequests": len(seen), "nativeClassifiedBodyBytes": selected_corpus_bytes,
        "nativeExecutableSha256": native_executable["executableSha256"], "runtimeCodecRevision": revision,
        "sourceDigest": source_digest, "codecReportSha256": retain_direct_flow("native-codec-classifications.json", parsed),
        "reviewSha256": reviewed["reviewSha256"], "providerClassifiedReceipts": len(provider_classification["classified"]),
        "publications": sorted({item["publicationId"] for item in mapping["originals"]}),
        "storageProjections": storage_projections, "storageControlProjections": control_projections,
        "storageControlBudget": {"calls": len(control_projections),
            "requestBytes": sum(row["requestBytes"] for row in control_projections),
            "replyBytes": sum(row["replyBytes"] for row in control_projections),
            "scope": "actual shared custody/capability/guard metadata calls; no fabricated per-release allocation"},
        "perReleaseStorageBudget": release_budget,
        "derivation": "all captured Native inbound and outbound bodies have closed supported metadata/app-shell/selected projection classes; independently matched production handler bytes and complete provider originals/callers exclude whole raw object transfer",
        "scope": "accepted A/B publication and concurrent page window only; separately retained injected-failure windows are not folded into this conclusion",
    }
    retain_direct_flow("actual-native-bulk-assessment.json", assessment)
    return assessment
