"""Execute the selected storage codec over the complete captured call inventory.

Successful closed decoding proves a body partition only. Actual final SQL,
actor, installed purpose and provider joins are separate obligations. Missing
joins retain unknown Native bulk bytes, including every unsupported original.
"""

import hashlib
from pathlib import Path
import re


STORAGE_CODEC_ROW_FIELDS = frozenset((
    "requestId", "sourceDigest", "requestSha256", "replySha256",
    "codecSourceSha256", "exchangeIdSha256", "originalContextSha256",
    "operation", "class", "payload",
))


def run_storage_workflow_codec_segments(selection, bundle, codec_source_digest, source_digest,
        artifact_namespace="storage-codec"):
    """Execute every bounded page with one held executable and exact membership.

    Terminal refusals remain retained. The exact serialized terminal envelope
    bound is checked before append or persistence, including its JSON framing.
    Any missing, refused or overflowing page leaves the whole selection unknown.
    """
    if (artifact_namespace != "storage-codec" and not re.fullmatch(
            r"(?:managed|external-oci)-(?:codec|outbound)-[a-z][a-z0-9-]{0,63}-[0-9a-f]{32}", artifact_namespace)):
        raise ValueError("storage codec artifact namespace differs")
    observer_prefix = "storage-codec-observer" if artifact_namespace == "storage-codec" else artifact_namespace
    outcomes, rows, terminal_bytes = [], [], 3
    executable_sha = selection["observerExecutable"]["sha256"]
    provenance_sha = selection["runtimeProvenance"]["sha256"]
    for segment in bundle["segments"]:
        label = "segment-" + str(segment["index"]).zfill(6)
        path = Path("external-direct-flow/" + artifact_namespace + "-" + label + ".json")
        encoded_manifest = native_corpus_json(segment["manifest"])
        manifest_sha = retain_direct_flow(path.name, encoded_manifest)
        outcome = {"index": segment["index"], "status": "refused",
            "manifestSha256": manifest_sha, "membershipSha256": segment["membershipSha256"],
            "executableSha256": executable_sha, "provenanceSha256": provenance_sha, "report": None}
        try:
            observed = run_direct_native_codec_observer(selection, path, label,
                artifact_prefix=observer_prefix)
            selected = segment["manifest"]["cases"]
            expected = {case["requestId"]: case for case in selected}
            if not isinstance(observed, list) or len(observed) != len(selected):
                raise ValueError("storage codec omitted a selected call")
            seen = set()
            for row in observed:
                if not isinstance(row, dict) or set(row) != STORAGE_CODEC_ROW_FIELDS:
                    raise ValueError("storage codec row shape differs")
                case = expected.get(row["requestId"])
                if (case is None or row["requestId"] in seen
                        or row["sourceDigest"] != source_digest
                        or row["codecSourceSha256"] != codec_source_digest
                        or row["requestSha256"] != case["receivedRequest"]["sha256"]
                        or row["replySha256"] != case["receivedReply"]["sha256"]):
                    raise ValueError("storage codec source, call or body substituted")
                seen.add(row["requestId"])
                for field in ("exchangeIdSha256", "originalContextSha256"):
                    if not re.fullmatch(r"[0-9a-f]{64}", row[field]):
                        raise ValueError("storage codec commitment differs")
                if (set(row["payload"]) != {"requestRawObjectBytes", "replyRawObjectBytes",
                        "selectedDataBytes", "semanticOciProjectionBytes"}
                        or any(not isinstance(value, str)
                            or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value)
                            for value in row["payload"].values())):
                    raise ValueError("storage codec payload count differs")
            outcome.update(status="success", report=observed)
        except Exception as error:
            # Exception values may include private file names or bodies.
            outcome["report"] = {"failureClass": type(error).__name__}
        encoded = native_corpus_json(outcome)
        candidate_bytes = terminal_bytes + len(encoded) + bool(outcomes)
        if (len(encoded) + 1 > NATIVE_SEGMENT_REPORT_BYTE_LIMIT
                or candidate_bytes > NATIVE_SEGMENT_REPORT_BYTE_LIMIT):
            diagnostic = {"version": 1, "complete": False,
                "overflowSegmentIndex": segment["index"], "nativeBulkBytes": None,
                "outcomeSha256": hashlib.sha256(encoded).hexdigest(),
                "outcomeBytes": len(encoded) + 1, "attemptedAggregateBytes": candidate_bytes,
                "executedSegmentCount": segment["index"] + 1,
                "unexecutedSegmentCount": len(bundle["segments"]) - segment["index"] - 1}
            body = native_corpus_json(diagnostic) + b"\n"
            if len(body) <= NATIVE_SEGMENT_DIAGNOSTIC_BYTE_LIMIT:
                retain_direct_flow(artifact_namespace + "-overflow.json", body)
            return {"version": 1, "complete": False, "observations": [], "nativeBulkBytes": None}
        retain_direct_flow(artifact_namespace + "-" + label + "-outcome.json", encoded + b"\n")
        outcomes.append(outcome)
        terminal_bytes = candidate_bytes
        if outcome["status"] == "success":
            rows.extend(outcome["report"])
    aggregate = native_corpus_json(outcomes) + b"\n"
    if len(aggregate) != terminal_bytes:
        raise ValueError("storage codec terminal representation differs")
    terminal_sha = retain_direct_flow(artifact_namespace + "-all-terminal-segments.json", aggregate)
    try:
        coverage = validate_native_segment_outputs(bundle, outcomes, executable_sha, provenance_sha)
    except ValueError:
        coverage = {"version": 1, "complete": False, "nativeBulkBytes": None}
    else:
        coverage["complete"] = True
    retain_direct_flow(artifact_namespace + "-complete-coverage.json", coverage)
    return {"version": 1, "complete": coverage["complete"], "observations": rows,
        "terminalSegmentsSha256": terminal_sha, "nativeBulkBytes": None}


def assess_selected_storage_workflow(codec_input, source_digest, native_process, final_sql):
    """Run actual selected decoders while preserving incomplete authority joins."""
    inventory_sha = retain_direct_flow("storage-codec-complete-original-inventory.json",
        codec_input["completeOriginalInventory"])
    bundle = codec_input["selectedCodecSegments"]
    result = {"version": 1, "nativeBulkBytes": None, "codecComplete": False,
        "inventorySha256": inventory_sha,
        "unresolvedNativeRequestIds": codec_input["unresolvedNativeRequestIds"],
        "finalSqlObservations": final_sql,
        "actorEvidence": None, "purposeEvidence": None, "providerPartition": None,
        "scope": "closed selected body observations; complete independent authority/provider joins required"}
    if bundle is None:
        result["reason"] = "no_supported_authenticated_storage_calls"
        retain_direct_flow("actual-storage-workflow-assessment.json", result)
        return result
    bundle_sha = retain_direct_flow("storage-codec-complete-segment-bundle.json", bundle)
    review = await_direct_review("storage-capture-codecs", {
        "completeOriginalInventory": inventory_sha, "selectedSegmentBundle": bundle_sha,
        "nativeProcess": retain_direct_flow("storage-codec-native-process.json", native_process),
    }, {"observerExecutable", "runtimeProvenance"})
    selection = review["selection"]
    provenance = _closed_review_json(direct_selected_bytes(selection["runtimeProvenance"], 65536))
    if (not isinstance(provenance, dict) or set(provenance) != {
            "version", "runtimeCodecRevision", "nativeExecutableSha256", "workerSourceDigest",
            "sourceArchiveSha256", "codecSourceSha256"}
            or type(provenance["version"]) is not int or provenance["version"] != 1
            or not re.fullmatch(r"[0-9a-f]{40}", provenance["runtimeCodecRevision"])
            or provenance["nativeExecutableSha256"] != native_process["executableSha256"]
            or provenance["workerSourceDigest"] != source_digest
            or any(not re.fullmatch(r"[0-9a-f]{64}", provenance[field])
                for field in ("sourceArchiveSha256", "codecSourceSha256"))):
        raise ValueError("storage codec provenance differs from actual installed source/process")
    decoded = run_storage_workflow_codec_segments(selection, bundle,
        provenance["codecSourceSha256"], source_digest)
    result.update(codecComplete=decoded["complete"], decoded=decoded,
        provenanceSha256=selection["runtimeProvenance"]["sha256"])
    retain_direct_flow("actual-storage-workflow-assessment.json", result)
    return result
