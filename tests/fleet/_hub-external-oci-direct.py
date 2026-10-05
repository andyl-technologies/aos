"""Measure the fresh External pair and install its independent Direct artifact."""

import hashlib
import json
from pathlib import Path
import re
import shlex


def qualify_external_oci_direct(native, worker, tools, prepared, processes, exports,
                                 artifacts, reviewer_public_key, candidate_factory, *, workflow=None, ownership=None,
                                 paired_exports=None):
    """Install the capacity-three final domain before measuring final acceptance."""
    if paired_exports is not None:
        return _qualify_paired_external_oci_direct(native, worker, tools, prepared, processes,
            exports, paired_exports, artifacts, reviewer_public_key, candidate_factory,
            workflow=workflow, ownership=ownership)
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


def require_paired_copy_capacity(output, artifact, artifact_bytes, declaration, declaration_bytes,
                                 reviewer_bytes, runtime, bootstraps):
    """Bind a real source-owned projection to exact files and exported bindings.

    This reader does not verify a signature. The mandatory producer invocation
    performs the existing artifact verification at its actual current UTC; this
    join then refuses substituted output, declaration, audience or domains.
    """
    fields = {"version", "ceiling_semantics", "qualification_artifact_sha256", "declaration_sha256",
        "reviewer_public_key_sha256", "runtime_qualification_digest", "policy", "copy_configuration_version", "domains"}
    audience = {"deployment_id": artifact["deploymentId"], "source_digest": artifact["sourceDigest"],
        "script_version": artifact["scriptVersion"]}
    if (set(output) != fields or type(output["version"]) is not int or output["version"] != 1
            or output["ceiling_semantics"] != "installed_configuration"
            or type(output["copy_configuration_version"]) is not int or output["copy_configuration_version"] != 2
            or output["qualification_artifact_sha256"] != hashlib.sha256(artifact_bytes).hexdigest()
            or output["declaration_sha256"] != hashlib.sha256(declaration_bytes).hexdigest()
            or output["reviewer_public_key_sha256"] != hashlib.sha256(reviewer_bytes).hexdigest()
            or output["runtime_qualification_digest"] != runtime["runtime"]["qualificationDigest"]
            or artifact["evidence"]["runtime"] != runtime["runtime"]
            or artifact["reviewerKeyId"] != declaration["reviewer_key_id"]
            or artifact["deploymentId"] != declaration["deployment_id"]
            or artifact["publicOrigin"] != declaration["public_origin"]
            or output["policy"] != {"version": 1, **audience, "maximum_provider_requests": 3}
            or len(output["domains"]) != 2 or len(runtime["protectedProfiles"]) != 2 or len(bootstraps) != 2):
        raise ValueError("paired capacity output changes its actual acceptance or installed policy")
    for index, (domain, projected, bootstrap) in enumerate(zip(output["domains"], runtime["protectedProfiles"], bootstraps)):
        association = bootstrap["read_cohort"]["association"]
        if bootstrap["write_cohort"]["association"] != association or projected["association"] != association:
            raise ValueError("paired capacity projection changes its current Read/Write association")
        expected = {"producer_profile_digest": projected["protectedProfileDigest"],
            "binding_id": association["binding_id"], "binding_stable_id": association["binding_stable_id"],
            "binding_resource_version": association["binding_resource_version"],
            "admitted_provider_requests": (3, 5)[index]}
        if domain != expected or declaration["domains"][index] != {key: expected[key] for key in
                ("producer_profile_digest", "admitted_provider_requests")}:
            raise ValueError("paired capacity output substitutes a binding, profile or declared ceiling")
    if output["domains"][0]["binding_id"] == output["domains"][1]["binding_id"]:
        raise ValueError("paired capacity repeats an actual binding")
    match_paired_runtime_profiles(artifact["evidence"]["externalProfiles"], runtime["runtime"], bootstraps)
    return output


def _qualify_paired_external_oci_direct(native, worker, tools, prepared, processes, source_exports,
                                        destination_exports, artifacts, reviewer_public_key,
                                        candidate_factory, *, workflow, ownership):
    """Retain preflight authorization while measuring the final installed tuple.

    The signed preflight profiles remain immutable authorization inputs through
    their genuine validity. The second measurement describes the new process
    and configuration and cannot replace those profiles or mutate configuration.
    """
    coordinates = prepared["coordinates"]
    run = coordinates["runId"]
    label, measurement_label = "external-oci-" + run, "eo-" + run[:8]
    bootstraps = [source_exports["bootstrap"], destination_exports["bootstrap"]]
    identity = inspect_direct_external_deployment(worker, tools["python"], tools["hub"], source_exports,
        coordinates["publicOrigin"], coordinates["controlOrigin"], "fleet-external-oci-" + run,
        "external-oci-bootstrap-" + run, coordinates["workerRoot"] + "/materials/HUB_DIRECT_UPLOAD_GUARD_KEY",
        inspection_root=coordinates["workerRoot"] + "/operator/deployment-inspection",
        retention_label=label, additional_bootstraps=[bootstraps[1]])
    actual = identity["identity"]
    configuration = json.loads(read_direct_guest_file(worker, tools["python"], prepared["configurationFile"], 1048576))
    queues = {kind: configuration["queueProducers"]["HUB_DIRECT_VERIFY_" + kind.upper()]
        for kind in ("bulk", "metadata")}
    bulk = prepare_direct_qualification_bulk(worker, tools["python"], coordinates["workerRoot"] + "/qualification-bulk")
    metadata = prepare_direct_qualification_metadata(worker, tools["python"], coordinates["workerRoot"] + "/qualification-metadata")

    def measure(epoch):
        observed = observe_direct_installed_runtime(worker, tools, artifacts, processes["worker"], identity,
            label=epoch, worker_root=coordinates["workerRoot"], queue_names=queues)
        expose_direct_review_inputs(worker, tools, artifacts, processes["worker"], label=epoch)
        qualification = run_direct_prequalification(worker, tools["python"], tools["node"], tools["qualificationDriver"],
            coordinates["publicOrigin"], coordinates["workerRoot"] + "/materials/HUB_DIRECT_UPLOAD_CONFORMANCE_KEY",
            identity["identityFile"], bootstraps[0]["selector"], bulk, metadata,
            operator_root=coordinates["workerRoot"] + "/operator")
        hashes = {"protectedIdentity": identity["identitySha256"], "installation": observed["installationSha256"],
            "prequalification": retain_direct_flow(epoch + "-prequalification.json", qualification),
            "bulkConfiguration": observed["queues"]["bulk"]["sha256"],
            "metadataConfiguration": observed["queues"]["metadata"]["sha256"]}
        return observed, qualification, hashes

    consumers = {name: json.loads(configuration["bindings"][name]) for name in (
        "HUB_EXTERNAL_OBJECT_CONSUMER", "HUB_EXTERNAL_STAGING_CONSUMER", "HUB_EXTERNAL_COPY_CONSUMER", "HUB_EXTERNAL_OCI_CONSUMER")}
    domains = consumers["HUB_EXTERNAL_COPY_CONSUMER"]["domains"]
    if (consumers["HUB_EXTERNAL_COPY_CONSUMER"]["version"] != 1 or len(domains) != 2
            or any(domain["provider_concurrency"] != 3 for domain in domains)
            or int(configuration["bindings"]["HUB_DIRECT_QUALIFY_MAX_PROVIDER_REQUESTS"]) != 3):
        raise ValueError("paired preflight was not initially configured for the common capacity three")
    preflight, preflight_run, hashes = measure(measurement_label + "-preflight")
    runtime = prepare_current_runtime_profile(tools, identity, preflight, hashes, measurement_label,
        expected_bootstraps=bootstraps)
    if int(runtime["runtime"]["maximumParallelProviderRequests"]) != 3:
        raise ValueError("paired preflight measured a different common provider capacity")
    hashes["pairedProfiles"] = retain_direct_flow(label + "-paired-runtime-projection.json", runtime)
    selected = await_direct_review(label + "-copy-authorization", hashes,
        {"signedArtifact", "independentReview", "reviewerKeyId"})["selection"]
    artifact_bytes = direct_selected_bytes(selected["signedArtifact"], 4 * 1024 * 1024)
    artifact = _closed_review_json(artifact_bytes)
    if (artifact["executionKind"] != "emulated_external"
            or any(artifact[name] != actual[name] for name in ("deploymentId", "publicOrigin", "sourceDigest", "scriptVersion"))):
        raise ValueError("paired preflight acceptance changed its actual discovery audience")
    review_bytes = direct_selected_bytes(selected["independentReview"], 262144)
    artifact_name = label + "-copy-preflight-artifact.json"
    retain_direct_flow(artifact_name, artifact_bytes)
    reviewer_bytes = reviewer_public_key.encode()
    if re.fullmatch(rb"[0-9a-f]{64}", reviewer_bytes) is None:
        raise ValueError("paired capacity reviewer is not the independently selected public key")
    root = Path("external-direct-flow").resolve()
    key_name, declaration_name = label + "-copy-reviewer.hex", label + "-copy-declaration.json"
    retain_direct_flow(key_name, reviewer_bytes)
    declaration = {"version": 1, "deployment_id": actual["deploymentId"], "public_origin": actual["publicOrigin"],
        "reviewer_key_id": selected["reviewerKeyId"], "domains": [
            {"producer_profile_digest": item["protectedProfileDigest"], "admitted_provider_requests": ceiling}
            for item, ceiling in zip(runtime["protectedProfiles"], (3, 5))]}
    declaration_bytes = json.dumps(declaration, separators=(",", ":")).encode()
    retain_direct_flow(declaration_name, declaration_bytes)
    capacity_file = root / (label + "-copy-capacity.json")
    invocation = _run_profile_projection([tools["providerConformance"], "copy-capacity", "--artifact-file",
        str(root / artifact_name), "--reviewer-public-key-file", str(root / key_name),
        "--declaration-file", str(root / declaration_name), "--output", str(capacity_file)], label + "-copy-capacity")
    capacity_bytes = capacity_file.read_bytes()
    capacity = require_paired_copy_capacity(_closed_review_json(capacity_bytes), artifact, artifact_bytes,
        declaration, declaration_bytes, reviewer_bytes, runtime, bootstraps)
    consumers["HUB_EXTERNAL_COPY_CONSUMER"]["version"] = 2
    for index, (domain, projected) in enumerate(zip(domains, capacity["domains"])):
        if (domain["read_cohort"] != bootstraps[index]["read_cohort"]
                or domain["write_cohort"] != bootstraps[index]["write_cohort"]
                or int(domain["provider_contract"].get("maximum_copy_read_range_bytes", "0")) < 8388608):
            raise ValueError("paired Copy domain lacks its current cohort or actually admitted conditional range")
        domain["producer_profile_digest"] = projected["producer_profile_digest"]
        domain["provider_concurrency"] = projected["admitted_provider_requests"]
    consumers["HUB_PROVIDER_CAPACITY_POLICY"] = capacity["policy"]
    if tools.get("mirrorFunctionalReviewer") is not None:
        reference = runtime["protectedProfiles"][0]
        raw_profile = direct_selected_bytes({"path": reference["profileFile"],
            "sha256": reference["profileSha256"]}, 262144)
        profile = _closed_review_json(raw_profile)
        configured = json.loads(configuration["bindings"]["HUB_EXTERNAL_OBJECT_CONSUMER"])
        listing = [cohort for cohort in configured["cohorts"]
            if cohort["association"] == bootstraps[0]["read_cohort"]["association"]
            and cohort["credential"]["purpose"] == "list"]
        if len(listing) != 1:
            raise ValueError("Mirror transport lacks the independently installed source List cohort")
        domain = external_mirror_domain(profile, bootstraps[0], {
            "publication": bootstraps[0]["publication"],
            "issuer_installation": bootstraps[0]["issuer_installation"], "list_cohort": listing[0]},
            domains[0]["provider_contract"])
        consumers["HUB_EXTERNAL_MIRROR_CONSUMER"] = {"version": 1, "domains": [domain]}
    candidate = candidate_factory()
    raw_candidate = read_direct_guest_file(native, tools["python"], candidate["candidateFile"], 4096)
    raw_signature = read_direct_guest_file(native, tools["python"], candidate["candidateSignatureFile"], 4096)
    if hashlib.sha256(raw_candidate).hexdigest() != candidate["candidateReference"]["sha256"]:
        raise ValueError("paired final configuration changed its genuine OCI candidate")
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
    fixed_configuration = read_direct_guest_file(worker, tools["python"], prepared["configurationFile"], 1048576)
    acceptance, installed, direct_references = _install_paired_external_preflight(native, worker, tools, prepared, processes,
        artifact_bytes, review_bytes, selected["reviewerKeyId"], reviewer_public_key)
    final_observations = observe_external_oci_pair(worker, tools, prepared, processes, "final")
    measured, qualified, final_hashes = measure(measurement_label + "-final")
    if read_direct_guest_file(worker, tools["python"], prepared["configurationFile"], 1048576) != fixed_configuration:
        raise ValueError("paired final remeasurement changed the installed configuration")
    reverified = _run_profile_projection([tools["providerConformance"], "copy-capacity", "--artifact-file",
        str(root / artifact_name), "--reviewer-public-key-file", str(root / key_name),
        "--declaration-file", str(root / declaration_name), "--output",
        str(root / (label + "-copy-capacity-after-measurement.json"))], label + "-copy-capacity-validity")
    if _closed_review_json((root / (label + "-copy-capacity-after-measurement.json")).read_bytes()) != capacity:
        raise ValueError("paired final validity observation changed the installed authorization inputs")
    return {"prepared": prepared, "processes": processes, "acceptance": acceptance, "candidate": candidate,
        "evidence": {"preflight": preflight_run, "structuralRuntime": runtime,
            "authorization": {"artifactSha256": hashlib.sha256(artifact_bytes).hexdigest(),
                "capacity": capacity, "producerInvocation": invocation, "currentValidityInvocation": reverified,
                "semantics": "retained verified preflight acceptance; installed scheduling ceilings"},
            "finalInstallation": measured, "finalRemeasurement": qualified, "finalRemeasurementHashes": final_hashes,
            "finalClockNamespace": final_observations, "workerAcceptance": installed,
            "directReferences": direct_references,
            "scope": "final measurements are evidence only; they do not replace installed authorization profiles"}}


def _install_paired_external_preflight(native, worker, tools, prepared, processes,
                                       artifact_bytes, review_bytes, reviewer_key_id, reviewer_public_key):
    """Install exact already verified authorization bytes in both real consumers."""
    coordinates = prepared["coordinates"]
    artifact = _closed_review_json(artifact_bytes)
    artifact_sha = hashlib.sha256(artifact_bytes).hexdigest()
    acceptance_file = coordinates["workerRoot"] + "/direct-acceptance.json"
    worker_artifact = install_direct_guest_file(worker, tools["python"], acceptance_file, artifact_bytes)
    key = private_guest_command(worker, shlex.join([tools["reviewer"], "registry-key",
        "--deployment-id", artifact["deploymentId"], "--source-digest", artifact["sourceDigest"],
        "--script-version", artifact["scriptVersion"]])).encode()
    key_file, pid_file = coordinates["workerRoot"] + "/direct-registry-key", coordinates["workerRoot"] + "/direct-acceptance-runner.pid"
    install_direct_guest_file(worker, tools["python"], key_file, key)
    install_direct_guest_file(worker, tools["python"], pid_file, str(processes["worker"]["pid"]).encode())
    installed = json.loads(private_guest_command(worker, shlex.join([tools["python"], tools["acceptanceInstaller"],
        "--socket-file", coordinates["workerRoot"] + "/control.sock", "--artifact-file", acceptance_file,
        "--registry-key-file", key_file, "--runner-pid-file", pid_file,
        "--output-directory", coordinates["workerRoot"] + "/direct-acceptance-installation"]), timeout=60))
    if installed["status"] != "installed" or installed["artifactSha256"] != artifact_sha:
        raise ValueError("paired actual acceptance KV readback refused")
    native_files = {"acceptanceFile": coordinates["nativeRoot"] + "/direct-acceptance.json",
        "reviewKeysFile": coordinates["nativeRoot"] + "/direct-reviewers.json",
        "guardKeyFile": prepared["nativeFiles"]["HUB_DIRECT_UPLOAD_GUARD_KEY"]}
    native_artifact = install_direct_guest_file(native, tools["python"], native_files["acceptanceFile"], artifact_bytes)
    native_reviewers = install_direct_guest_file(native, tools["python"], native_files["reviewKeysFile"],
        json.dumps({reviewer_key_id: reviewer_public_key}, separators=(",", ":")).encode())
    native_review = install_direct_guest_file(native, tools["python"],
        coordinates["nativeRoot"] + "/direct-independent-review.json", review_bytes)
    guard_bytes = read_direct_guest_file(native, tools["python"], native_files["guardKeyFile"], 8192)
    references = {"version": 1, "artifactSha256": artifact_sha,
        "reviewSha256": hashlib.sha256(review_bytes).hexdigest(), "reviewerKeyId": reviewer_key_id,
        "workerArtifact": worker_artifact, "nativeArtifact": native_artifact,
        "nativeReviewKeys": native_reviewers, "nativeIndependentReview": native_review,
        "nativeGuardKey": {"file": native_files["guardKeyFile"], "sha256": hashlib.sha256(guard_bytes).hexdigest(),
            "byteSize": len(guard_bytes)}, "audience": {name: artifact[name] for name in
                ("deploymentId", "publicOrigin", "sourceDigest", "scriptVersion")},
        "scope": "retained verified preflight bytes; current Native loader verifies actual triplet"}
    return native_files, installed, references
