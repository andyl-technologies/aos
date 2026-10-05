"""Keep Mirror producer observation separate from its actual serving successor.

The original helper stays alive through explicit review and installation. Only
its constructor triplet and private observation destinations change afterward;
old PID observations cannot qualify the successor lifetime.
"""

import copy
import hashlib
import json
import re


def external_mirror_successor_input(original, root, triplet):
    """Select the closed functional triplet without changing business inputs."""
    if not re.fullmatch(r"/var/lib/hybrid-native/external-oci/[0-9a-f]{32}", root):
        raise ValueError("Mirror successor leaves the selected run")
    expected = {"artifactFile", "reviewerPublicKeyFile", "guardKeyFile"}
    if (set(triplet) != expected or len(set(triplet.values())) != 3
            or any(not isinstance(path, str) or not path.startswith(root + "/")
                or any(part in {"", ".", ".."} for part in path.split("/")[1:])
                for path in triplet.values())
            or triplet["guardKeyFile"] in {original["files"]["guardKeyFile"],
                original["files"]["workKeyFile"]}
            or "mirrorFunctional" in original["files"]):
        raise ValueError("Mirror successor triplet is not an independent selected role")
    changed = copy.deepcopy(original)
    for field, suffix in (("readinessFile", "ready"), ("terminalFile", "terminal"),
            ("shutdownFile", "shutdown")):
        if original[field] != root + "/inventory-restart-" + suffix + ".json":
            raise ValueError("Mirror successor does not follow the actual inventory epoch")
        changed[field] = root + "/mirror-functional-" + suffix + ".json"
    changed["files"]["mirrorFunctional"] = dict(triplet)
    return changed


def restart_external_mirror_native(native, tools, prepared, processes, helper,
                                   triplet, workflow, artifacts, ownership):
    """Start the same selected ELF after its genuine functional constructor."""
    root = prepared["coordinates"]["nativeRoot"]
    raw = read_direct_guest_file(native, tools["python"], helper["input"]["file"], 1048576)
    if hashlib.sha256(raw).hexdigest() != helper["input"]["sha256"]:
        raise ValueError("Mirror producer original helper input changed")
    original = json.loads(raw)
    if original != helper["inputValue"]:
        raise ValueError("Mirror producer input names another actual epoch")
    successor = external_mirror_successor_input(original, root, triplet)
    input_ref = install_direct_guest_file(native, tools["python"], root + "/mirror-functional-input.json",
        json.dumps(successor, separators=(",", ":")).encode())

    workflow.close(processes)
    exited = shutdown_external_oci_helper(native, tools, prepared, helper)
    ownership["helper"] = None
    ownership["mirrorProducerExit"] = exited
    ownership["processes"] = {name: value for name, value in processes.items() if name != "native"}
    process = launch_managed_process(native, tools, root, "native-mirror-functional", [
        tools["managedCleanupNativeHelper"],
        "storage_work::external_oci::tests::fleet::actual_external_oci_fleet_origin",
        "--exact", "--ignored", "--nocapture"], {
            "AOS_EXTERNAL_OCI_FLEET_INPUT": input_ref["file"],
            "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt"})
    current_processes = {**processes, "native": process}
    ownership.update(processes=current_processes, partialHelperInput=input_ref)
    if process["executableSha256"] != helper["process"]["executableSha256"]:
        raise ValueError("Mirror successor changed the selected serving ELF")
    ready = await_external_oci_helper(native, tools, prepared, process, input_ref,
        helper["readiness"]["identity"]["candidateSha256"],
        readiness_file=successor["readinessFile"])
    if (ready["identity"]["expiresAt"] != helper["readiness"]["identity"]["expiresAt"]
            or ready["backgroundControllers"] != helper["readiness"]["backgroundControllers"]):
        raise ValueError("Mirror successor changed the original lifetime or controller choices")
    current = {"process": process, "readiness": ready, "input": input_ref,
        "inputValue": successor, "previousEpochExit": exited,
        "providerEffectsSettled": None, "remoteDrain": None}
    ownership.update(helper=current, processes=current_processes)
    codec = select_external_storage_codec(tools, artifacts, process, prepared["coordinates"]["runId"],
        "controlled_external_oci_native", epoch="mirror-functional")
    workflow.boundaries = {**workflow.boundaries, **codec}
    workflow.resume(prepared, current_processes, "controlled_external_oci_native")
    retain_direct_flow("external-mirror-" + prepared["coordinates"]["runId"] + "-successor.json", {
        "producerProcess": helper["process"], "producerInput": helper["input"],
        "producerExit": exited, "successor": current})
    return {"helper": current, "processes": current_processes}
