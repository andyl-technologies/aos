"""Measure the fresh External pair and install its independent Direct artifact."""

import hashlib
import json
import shlex


def qualify_external_oci_direct(native, worker, tools, prepared, processes, exports,
                                 artifacts, reviewer_public_key, candidate_factory, *, workflow=None, ownership=None):
    """Install the capacity-three final domain before measuring final acceptance."""
    coordinates = prepared["coordinates"]
    run = coordinates["runId"]
    label = "external-oci-" + run
    measurement_label = "eo-" + run[:8]
    identity = inspect_direct_external_deployment(worker, tools["python"], tools["hub"],
        {"bootstrap": exports["bootstrap"]}, coordinates["publicOrigin"], coordinates["controlOrigin"],
        "fleet-external-oci-" + coordinates["runId"], "external-oci-bootstrap-" + coordinates["runId"],
        coordinates["workerRoot"] + "/materials/HUB_DIRECT_UPLOAD_GUARD_KEY",
        inspection_root=coordinates["workerRoot"] + "/operator/deployment-inspection",
        retention_label="external-oci-" + coordinates["runId"])
    bulk = prepare_direct_qualification_bulk(worker, tools["python"], coordinates["workerRoot"] + "/qualification-bulk")
    metadata = prepare_direct_qualification_metadata(worker, tools["python"], coordinates["workerRoot"] + "/qualification-metadata")
    configuration = json.loads(read_direct_guest_file(worker, tools["python"], prepared["configurationFile"], 1048576))
    queues = {kind: configuration["queueProducers"]["HUB_DIRECT_VERIFY_" + kind.upper()]
        for kind in ("bulk", "metadata")}

    def measure(label):
        observed = observe_direct_installed_runtime(worker, tools, artifacts, processes["worker"], identity,
            label=label, worker_root=coordinates["workerRoot"], queue_names=queues)
        files = expose_direct_review_inputs(worker, tools, artifacts, processes["worker"], label=label)
        qualified = run_direct_prequalification(worker, tools["python"], tools["node"], tools["qualificationDriver"],
            coordinates["publicOrigin"], coordinates["workerRoot"] + "/materials/HUB_DIRECT_UPLOAD_CONFORMANCE_KEY",
            identity["identityFile"], exports["bootstrap"]["selector"], bulk, metadata,
            operator_root=coordinates["workerRoot"] + "/operator")
        digest = retain_direct_flow(label + "-prequalification.json", qualified)
        return observed, qualified, {"protectedIdentity": identity["identitySha256"],
            "installation": observed["installationSha256"], "prequalification": digest,
            "bulkConfiguration": observed["queues"]["bulk"]["sha256"],
            "metadataConfiguration": observed["queues"]["metadata"]["sha256"]}

    preflight, preflight_run, hashes = measure(measurement_label + "-preflight")
    runtime = prepare_current_runtime_profile(tools, identity, preflight, hashes, measurement_label)
    if int(runtime["runtime"]["maximumParallelProviderRequests"]) != 3:
        raise ValueError("Fresh Copy and Direct domains must share the actually selected capacity three")
    consumers = {name: json.loads(configuration["bindings"][name]) for name in (
        "HUB_EXTERNAL_OBJECT_CONSUMER", "HUB_EXTERNAL_STAGING_CONSUMER", "HUB_EXTERNAL_COPY_CONSUMER", "HUB_EXTERNAL_OCI_CONSUMER")}
    domain = consumers["HUB_EXTERNAL_COPY_CONSUMER"]["domains"][0]
    if domain["provider_concurrency"] != 3:
        raise ValueError("Fresh Copy isolate capacity changed before final Direct installation")
    domain["producer_profile_digest"] = runtime["protectedProfileDigest"]
    candidate = candidate_factory()
    raw_candidate = read_direct_guest_file(native, tools["python"], candidate["candidateFile"], 4096)
    raw_signature = read_direct_guest_file(native, tools["python"], candidate["candidateSignatureFile"], 4096)
    if hashlib.sha256(raw_candidate).hexdigest() != candidate["candidateReference"]["sha256"]:
        raise ValueError("Final OCI configuration changed the freshly prepared candidate")
    prepared = install_external_oci_consumers(worker, tools, prepared, consumers,
        configuration["serviceBindings"]["HUB_AUTHORITY_ISSUER"], "final",
        candidate_binding={"candidate": raw_candidate.decode(), "signature": raw_signature.decode().strip()})
    if workflow is not None:
        workflow.close(processes)
    processes = restart_external_oci_worker(worker, tools, prepared, processes, "external-oci-final")
    if ownership is not None:
        ownership.update(prepared=prepared, processes=processes)
    if workflow is not None:
        workflow.resume(prepared, processes, "ordinary_native")
    final_observations = observe_external_oci_pair(worker, tools, prepared, processes, "final")
    measured, qualified, hashes = measure(measurement_label + "-final")
    hashes["finalClockNamespace"] = retain_direct_flow(label + "-final-observations.json", final_observations)
    selected = await_direct_review(label + "-direct-acceptance", hashes,
        {"signedArtifact", "independentReview", "reviewerKeyId"})["selection"]
    artifact_bytes = direct_selected_bytes(selected["signedArtifact"], 65536)
    artifact = _closed_review_json(artifact_bytes)
    actual = identity["identity"]
    if (artifact["executionKind"] != "emulated_external" or artifact["reviewerKeyId"] != selected["reviewerKeyId"]
            or any(artifact[name] != actual[name] for name in
                ("deploymentId", "publicOrigin", "sourceDigest", "scriptVersion"))
            or int(artifact["evidence"]["runtime"]["maximumParallelProviderRequests"]) != 3):
        raise ValueError("Fresh Direct acceptance changed the final pair or shared provider capacity")
    review_bytes = direct_selected_bytes(selected["independentReview"], 262144)
    review_sha = retain_direct_flow(label + "-direct-review.json", review_bytes)
    artifact_sha = retain_direct_flow(label + "-direct-signed-artifact.json", artifact_bytes)
    acceptance_file = coordinates["workerRoot"] + "/direct-acceptance.json"
    worker_artifact = install_direct_guest_file(worker, tools["python"], acceptance_file, artifact_bytes)
    key = private_guest_command(worker, shlex.join([tools["reviewer"], "registry-key",
        "--deployment-id", actual["deploymentId"], "--source-digest", actual["sourceDigest"],
        "--script-version", actual["scriptVersion"]])).encode()
    key_file = coordinates["workerRoot"] + "/direct-registry-key"
    pid_file = coordinates["workerRoot"] + "/direct-acceptance-runner.pid"
    install_direct_guest_file(worker, tools["python"], key_file, key)
    install_direct_guest_file(worker, tools["python"], pid_file, str(processes["worker"]["pid"]).encode())
    installed = json.loads(private_guest_command(worker, shlex.join([tools["python"], tools["acceptanceInstaller"],
        "--socket-file", coordinates["workerRoot"] + "/control.sock", "--artifact-file", acceptance_file,
        "--registry-key-file", key_file, "--runner-pid-file", pid_file,
        "--output-directory", coordinates["workerRoot"] + "/direct-acceptance-installation"]), timeout=60))
    if installed["status"] != "installed" or installed["artifactSha256"] != hashlib.sha256(artifact_bytes).hexdigest():
        raise ValueError("Fresh actual acceptance KV readback refused")
    native_files = {"acceptanceFile": coordinates["nativeRoot"] + "/direct-acceptance.json",
        "reviewKeysFile": coordinates["nativeRoot"] + "/direct-reviewers.json",
        "guardKeyFile": prepared["nativeFiles"]["HUB_DIRECT_UPLOAD_GUARD_KEY"]}
    native_artifact = install_direct_guest_file(native, tools["python"], native_files["acceptanceFile"], artifact_bytes)
    reviewer_bytes = json.dumps({selected["reviewerKeyId"]: reviewer_public_key}, separators=(",", ":")).encode()
    native_reviewers = install_direct_guest_file(native, tools["python"], native_files["reviewKeysFile"], reviewer_bytes)
    native_review = install_direct_guest_file(native, tools["python"],
        coordinates["nativeRoot"] + "/direct-independent-review.json", review_bytes)
    guard_bytes = read_direct_guest_file(native, tools["python"], native_files["guardKeyFile"], 8192)
    direct_references = {"version": 1, "artifactSha256": artifact_sha,
        "reviewSha256": review_sha, "reviewerKeyId": selected["reviewerKeyId"],
        "workerArtifact": worker_artifact, "nativeArtifact": native_artifact,
        "nativeReviewKeys": native_reviewers, "nativeIndependentReview": native_review,
        "nativeGuardKey": {"file": native_files["guardKeyFile"],
            "sha256": hashlib.sha256(guard_bytes).hexdigest(), "byteSize": len(guard_bytes)},
        "audience": {name: actual[name] for name in
            ("deploymentId", "publicOrigin", "sourceDigest", "scriptVersion")},
        "scope": "exact installed bytes; the current Native loader verifies the triplet before helper bind"}
    return {"prepared": prepared, "processes": processes, "acceptance": native_files, "candidate": candidate,
        "evidence": {"preflight": preflight_run, "structuralRuntime": runtime,
            "finalInstallation": measured, "finalQualification": qualified,
            "finalClockNamespace": final_observations, "workerAcceptance": installed,
            "directReferences": direct_references}}
