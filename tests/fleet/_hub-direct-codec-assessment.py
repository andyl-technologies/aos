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


def assess_direct_native_bodies(body_receipts, control_joins, provider_classification,
                               mapping, source_digest, issuer_verifier, native_executable):
    """Require complete positive-workload type and provider evidence before zero."""
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
    for capture in body_receipts["bodies"]:
        captures.append({**capture, "phase": capture["phase"] or None,
            "responseContentType": capture["responseContentType"] or None,
            "responseContentEncoding": capture["responseContentEncoding"] or None,
            "bodies": {direction: {**body, "file": str(Path(body["file"]).resolve()),
                "byteSize": str(body["byteSize"])} for direction, body in capture["bodies"].items()}})
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
            or int(parsed["selectedBodyBytes"]) != body_receipts["capturedCorpusBytes"]
            or int(parsed["maximumSelectedBodyBytes"]) != NATIVE_CAPTURE_CORPUS_LIMIT
            or int(parsed["maximumBodyBytes"]) != WORKER_CONTROL_REPLY_LIMIT
            or len(parsed["captures"]) != len(captures)):
        raise ValueError("codec observation differs from the complete selected Native corpus")
    actual = {hashlib.sha256(capture["requestId"].encode()).hexdigest(): capture for capture in captures}
    joined = {item["requestId"]: item for item in control_joins["joined"]}
    seen = set()
    for item in parsed["captures"]:
        identifier = item["requestIdSha256"]
        capture = actual.get(identifier)
        if (capture is None or identifier in seen or item["class"] not in DIRECT_NATIVE_ALLOWED_BODY_CLASSES
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
    if seen != set(actual):
        raise ValueError("Native codec observation omitted an actual accepted-workload request")
    assessment = {"version": 1, "nativeBulkBytes": 0,
        "nativeClassifiedRequests": len(seen), "nativeClassifiedBodyBytes": body_receipts["capturedCorpusBytes"],
        "nativeExecutableSha256": native_executable["executableSha256"], "runtimeCodecRevision": revision,
        "sourceDigest": source_digest, "codecReportSha256": retain_direct_flow("native-codec-classifications.json", parsed),
        "reviewSha256": reviewed["reviewSha256"], "providerClassifiedReceipts": len(provider_classification["classified"]),
        "publications": sorted({item["publicationId"] for item in mapping["originals"]}),
        "derivation": "every captured Native body has a closed supported metadata/app-shell class; authenticated logical joins and complete independent provider originals/callers exclude Native object transfer",
        "scope": "accepted A/B publication and concurrent page window only; separately retained injected-failure windows are not folded into this conclusion",
    }
    retain_direct_flow("actual-native-bulk-assessment.json", assessment)
    return assessment
