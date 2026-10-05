"""Assemble real producer inputs before an explicit independent sign checkpoint.

The reviewer reopens these bytes and live process identities on Native. The
caller selects paths and retains the unsigned candidate; it supplies no approval
flags, counters or alternate prerequisite profile.
"""

import hashlib
import json
import shlex
import time


def prepare_external_mirror_selection(native, worker, tools, prepared, processes,
                                      helper, direct, exports):
    """Capture the original serving epoch and its actually installed transport."""
    coordinates = prepared["coordinates"]
    run = coordinates["runId"]
    captured = capture_external_mirror_native(native, tools, prepared, helper)
    root = coordinates["nativeRoot"] + "/mirror-review"
    observed = observe_external_oci_pair(worker, tools, prepared, processes, "mirror-functional")

    def copy_file(name, filename, maximum=262144):
        return copy_external_mirror_review_file(native, worker, tools, root, name,
            filename, maximum)["retained"]

    configuration = json.loads(read_direct_guest_file(worker, tools["python"],
        prepared["configurationFile"], 1048576))
    configured = json.loads(configuration["bindings"]["HUB_EXTERNAL_MIRROR_CONSUMER"])
    if configured["version"] != 1 or len(configured["domains"]) != 1:
        raise ValueError("Mirror producer lacks its fixed actual transport domain")
    domain = configured["domains"][0]
    listing_raw = read_direct_guest_file(worker, tools["python"], exports["listFile"]["path"], 262144)
    if (hashlib.sha256(listing_raw).hexdigest() != exports["listFile"]["sha256"]
            or len(listing_raw) != exports["listFile"]["bytes"]
            or json.loads(listing_raw) != exports["listExport"]
            or exports["listExport"]["list_cohort"] != domain["list_cohort"]):
        raise ValueError("Mirror producer actual independent List export changed")
    list_ref = install_direct_guest_file(native, tools["python"], root + "/list-export.json", listing_raw)
    public_ref = install_direct_guest_file(native, tools["python"], root + "/reviewer.hex",
        tools["mirrorFunctionalReviewer"]["publicKey"].encode())
    manifest = captured["manifest"]
    references = direct["evidence"]["directReferences"]
    inputs = {
        "prerequisiteArtifact": mirror_review_reference(references["nativeArtifact"]),
        "prerequisiteReviewKeys": mirror_review_reference(references["nativeReviewKeys"]),
        "artifactManifest": mirror_review_reference(captured["manifestFile"]),
        "workerInstallation": copy_file("worker-installation",
            direct["evidence"]["finalInstallation"]["installationFile"]),
        "configuration": copy_file("configuration", prepared["configurationFile"]),
        "namespace": copy_file("namespace", observed["namespaceFile"]["file"]),
        "nativeObservation": mirror_review_reference(captured["nativeObservationFile"]),
        "nativeInput": mirror_review_reference(captured["nativeInput"]),
        "nativeReadiness": mirror_review_reference(captured["nativeReadiness"]),
        "listExport": mirror_review_reference(list_ref),
        "providerReport": copy_file("provider-report", coordinates["workerRoot"]
            + "/provider-observation/observations.json"),
        "nixStoreExecutable": mirror_review_reference(captured["nixStoreExecutable"]),
        "conformanceKey": copy_file("conformance-key", coordinates["workerRoot"]
            + "/materials/HUB_DIRECT_UPLOAD_CONFORMANCE_KEY", 4096),
    }
    for field, role in (("wasm", "wasm"), ("script", "script"), ("runner", "runner"),
            ("runtimeExecutable", "runtimeExecutable"), ("nativeServingExecutable", "nativeServing"),
            ("providerConformanceExecutable", "providerConformance")):
        inputs[field] = mirror_review_reference(manifest[role])
    journal = copy_external_mirror_provider_journal(native, worker, tools, root,
        coordinates["workerRoot"] + "/provider-observation/journal")
    inputs["providerJournal"] = journal["retainedDirectory"]
    clocks = [{name: copy_file("clock-" + str(index) + "-" + name, ref["file"], 65536)
        for name, ref in clock.items()} for index, clock in enumerate(observed["clocks"])]
    issued = int(private_guest_command(native, shlex.join([tools["python"], "-c",
        "import time; print(int(time.time()))"])).strip())
    remaining = int(tools["fleetCutoffMonotonic"] - time.monotonic())
    cutoff = min(issued + min(900, remaining), int(helper["readiness"]["identity"]["expiresAt"]))
    if cutoff <= issued:
        raise ValueError("Mirror purpose cannot outlive the original fixture cutoff")
    selection = {"version": 1, "reviewerKeyId": tools["mirrorFunctionalReviewer"]["keyId"],
        "reviewerPublicKey": mirror_review_reference(public_ref),
        "deploymentId": tools["deploymentId"], "publicOrigin": coordinates["publicOrigin"],
        "sourceDigest": manifest["workerSourceDigest"], "scriptVersion": manifest["workerScriptVersion"],
        "profileDigest": direct["evidence"]["structuralRuntime"]["protectedProfiles"][0]["protectedProfileDigest"],
        "upstreamBase": "https://aos.andyl.org:4778/fleet-mirror/" + run,
        "placementPrefix": ".aos-mirror-qualification/" + run + "/final",
        "maximumObjectBytes": MIRROR_SOURCE_FILE_LIMIT, "issuedAt": issued, "validUntil": cutoff,
        "inputs": inputs, "clocks": clocks}
    selected = install_direct_guest_file(native, tools["python"], root + "/selection.json",
        json.dumps(selection, separators=(",", ":")).encode())
    return {"selection": selection, "selectionFile": selected, "captured": captured,
        "clockNamespace": observed, "journal": journal, "reviewerPublicKey": public_ref}


def review_install_external_mirror(native, worker, tools, prepared, processes, helper,
                                   direct, exports):
    """Require the real candidate checkpoint before invoking the signing tool."""
    selected = prepare_external_mirror_selection(native, worker, tools, prepared,
        processes, helper, direct, exports)
    root = prepared["coordinates"]["nativeRoot"] + "/mirror-review"
    candidate = prepare_mirror_functional(native, tools, selected["selectionFile"]["file"],
        root + "/candidate.json")
    raw = read_direct_guest_file(native, tools["python"], root + "/candidate.json", 262144)
    candidate_sha = hashlib.sha256(raw).hexdigest()
    label = "external-mirror-" + prepared["coordinates"]["runId"]
    retained = retain_direct_flow(label + "-candidate.json", raw)
    review = await_direct_review(label + "-candidate-sign", {
        "candidateSha256": candidate_sha, "retainedCandidate": retained,
        "producer": retain_direct_flow(label + "-producer.json", selected),
        "prepare": retain_direct_flow(label + "-prepare.json", candidate),
    }, {"reviewedCandidateSha256", "reviewerPrivateKey"})["selection"]
    if review["reviewedCandidateSha256"] != candidate_sha:
        raise ValueError("Mirror independent review selected another unsigned candidate")
    seed = direct_selected_bytes(review["reviewerPrivateKey"], 8192)
    seed_ref = install_direct_guest_file(native, tools["python"], root + "/reviewer-seed.private", seed)
    artifact_file = root + "/artifact.json"
    signed = sign_mirror_functional(native, tools, selected["selectionFile"]["file"],
        root + "/candidate.json", candidate_sha, seed_ref["file"],
        selected["reviewerPublicKey"]["file"], artifact_file)
    installed = install_mirror_functional(native, worker, tools,
        selected["selectionFile"]["file"], artifact_file,
        prepared["coordinates"]["workerRoot"] + "/control.sock", processes["worker"])
    return {"producer": selected, "prepare": candidate, "signed": signed, "installed": installed,
        "triplet": {"artifactFile": artifact_file,
            "reviewerPublicKeyFile": selected["reviewerPublicKey"]["file"],
            "guardKeyFile": prepared["nativeFiles"]["HUB_MIRROR_GUARD_KEY"]}}
