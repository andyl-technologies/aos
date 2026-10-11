"""Observe one real persisted OCI hash continuation across an owned restart.

The first provider range only times a confined response hold. Current SQL must
independently show the saved nonterminal offset before the Native process is
stopped. Completion requires the same generation and the immutable source hash.
"""

import hashlib
import json
import shlex
import time


def prepare_external_inventory_restart(client, s3, tools, prepared, source, helper, exports):
    """Select a real layout blob and defer the hold until its first real range."""
    selected = json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os, re, stat
        from pathlib import Path

        layout=Path(selected['layout']); root=layout/'blobs/sha256'
        if root.is_symlink() or not root.is_dir():
            raise ValueError('Inventory source layout differs')
        candidates=sorted(root.iterdir())
        if not 1<=len(candidates)<=512:
            raise ValueError('Inventory source layout exceeds its object bound')
        for path in candidates:
            before=path.lstat()
            if (not stat.S_ISREG(before.st_mode) or not re.fullmatch(r'[0-9a-f]{64}',path.name)
                    or not 0<before.st_size<=536870912):
                raise ValueError('Inventory source object custody differs')
            if before.st_size<=8388608+65536: continue
            with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
                initial=os.fstat(stream.fileno())
                first=stream.read(8388608); second=stream.read(8388608)
                digest=hashlib.sha256(); digest.update(first); digest.update(second)
                while block:=stream.read(65536): digest.update(block)
                final=os.fstat(stream.fileno())
            if (digest.hexdigest()!=path.name or any(getattr(initial,key)!=getattr(final,key)
                    for key in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))):
                raise ValueError('Inventory immutable source changed')
            print(json.dumps({'objectKey':'oci/blobs/sha256/'+path.name,
                'objectDigest':'sha256:'+path.name,'objectBytes':before.st_size,
                'firstRangeSha256':hashlib.sha256(first).hexdigest(),
                'secondRangeSha256':hashlib.sha256(second).hexdigest(),'secondRangeBytes':len(second),
                'sourceFile':str(path)}))
            break
        else: raise ValueError('Inventory source has no genuinely nonterminal large blob')
    """, {"layout": source["finalized"]["layout"]}, timeout=120))
    coordinates = prepared["coordinates"]
    association = exports["bootstrap"]["read_cohort"]["association"]
    provider_prefix = external_oci_provider_prefix("fleet-s3", association["binding_prefix"],
        coordinates["placementPrefix"])
    cutoff = helper["readiness"]["identity"]["expiresAt"]
    if type(cutoff) is not int or cutoff <= int(time.time()):
        raise ValueError("inventory hold lacks its original helper cutoff")
    arm = direct_copy_partial_command(s3, tools, tools["externalCopyPartialInstallation"], {
        "version": 1, "kind": "arm_inventory_after_first_range", "targetPrefix": provider_prefix,
        "sourceKey": provider_prefix + selected["objectKey"], "rangeStart": 8388608,
        "fixtureCutoffUnixMillis": cutoff * 1000})
    if arm != {"version": 1, "status": "armed"}:
        raise ValueError("inventory deferred first-range selector was refused")
    result = {"source": selected, "providerPrefix": provider_prefix,
        "fixtureCutoffUnixMillis": cutoff * 1000, "arm": arm,
        "scope": "actual immutable source selection; first range is timing only"}
    retain_direct_flow("external-oci-" + coordinates["runId"] + "-inventory-arm.json", result)
    return result


def run_external_inventory_restart(native, worker, s3, tools, prepared, processes,
                                   registry, candidate, helper, selection, workflow, artifacts, ownership):
    """Require persisted SQL before shutdown and a real resumed physical range."""
    run = prepared["coordinates"]["runId"]
    label = "inventory-" + run
    inventory = managed_fixture_module(tools["externalInventoryResume"], "external_inventory_" + run)
    current_processes = processes

    def read_sql(query, observation_label):
        return read_external_oci_sql(native, tools, prepared, current_processes["native"], query, observation_label)

    identity = read_sql("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
        "SELECT json_build_object('registryId',p.registry_id,'registryStableId',r.stable_id) "
        "FROM surface_placements p JOIN registries r ON r.id=p.registry_id WHERE p.id="
        + str(candidate["placementId"]) + "; COMMIT;", label + "-identity")
    if identity["value"]["registryStableId"] != registry["registry"]["stableId"]:
        raise ValueError("inventory selected another actual registry")
    expected = {**selection["source"], **identity["value"],
        "placementId": candidate["placementId"], "placementPrefix": prepared["coordinates"]["placementPrefix"],
        "providerPrefix": selection["providerPrefix"]}
    installation = tools["externalCopyPartialInstallation"]

    def state():
        return direct_copy_partial_command(s3, tools, installation, {
            "version": 1, "kind": "state_inventory", "targetPrefix": selection["providerPrefix"]})

    def current_native_time():
        return int(private_guest_command(native, shlex.join([tools["python"], "-c",
            "import time; print(int(time.time()))"])).strip())

    ceiling = selection["fixtureCutoffUnixMillis"]
    attempts = 0
    while time.time() * 1000 < ceiling:
        observed_state = state()
        if observed_state["holdUntilUnixMillis"] is not None:
            ceiling = min(ceiling, observed_state["holdUntilUnixMillis"])
        if observed_state["pendingLocalHold"] and observed_state["firstRangeReceipt"] is not None:
            partial = inventory.observe_partial_inventory(read_sql, expected,
                label + "-partial-" + str(attempts), current_native_time)
            attempts += 1
            if partial["summary"] is not None:
                # SQL collection can await guest I/O. Reopen physical state after
                # that await rather than using a stale pending response sample.
                observed_state = state()
                if (not observed_state["pendingLocalHold"] or observed_state["firstRangeReceipt"] is None
                        or observed_state["holdUntilUnixMillis"] is None
                        or time.time() * 1000 >= observed_state["holdUntilUnixMillis"]):
                    raise ValueError("inventory physical hold ended during current SQL observation")
                checkpoint = inventory.require_inventory_provider_checkpoint(observed_state, partial,
                    expected, lambda path, maximum: read_direct_guest_file(s3, tools["python"], path, maximum),
                    installation["root"])
                break
        if observed_state["terminal"] is not None:
            raise ValueError("inventory pending physical window ended before a saved checkpoint")
        time.sleep(0.1)
    else:
        retain_direct_flow(label + "-missed-window.json", {"state": state(), "attempts": attempts})
        raise RuntimeError("inventory missed its actual bounded nonterminal checkpoint window")
    retain_direct_flow(label + "-before-restart.json", checkpoint)
    def observe_restart_fence(new_processes):
        nonlocal current_processes, attempts
        current_processes = new_processes
        deadline = min(selection["fixtureCutoffUnixMillis"] / 1000, time.time() + 30)
        while time.time() < deadline:
            current = inventory.observe_partial_inventory(read_sql, expected,
                label + "-renewed-" + str(attempts), current_native_time)
            attempts += 1
            renewed = inventory.require_inventory_restart_fence(current, partial)
            if renewed is not None:
                return renewed
            time.sleep(0.1)
        retain_direct_flow(label + "-missed-renewal.json", current)
        raise RuntimeError("inventory missed its actual restarted live collector fence")

    restarted = restart_external_inventory_native(native, tools, prepared, current_processes,
        helper, workflow, artifacts, ownership, observe_restart_fence=observe_restart_fence)
    current_processes = restarted["processes"]
    completed, resumed = None, None
    renewed = restarted["helper"]["renewedCollectorFence"]
    deadline = min(selection["fixtureCutoffUnixMillis"] / 1000, time.time() + 300)
    while time.time() < deadline:
        completed = inventory.observe_completed_inventory(read_sql, expected, partial,
            label + "-completed-" + str(attempts))
        attempts += 1
        current_state = state()
        if current_state["continuationReceipts"]:
            resumed = inventory.require_inventory_resumed_range(current_state, checkpoint, expected,
                lambda path, maximum: read_direct_guest_file(s3, tools["python"], path, maximum), installation["root"],
                restarted["helper"]["launchBoundaryUnixMillis"])
        if completed["summary"] is not None and resumed is not None and renewed is not None:
            break
        time.sleep(0.5)
    else:
        retain_direct_flow(label + "-restart-incomplete.json", {"completed": completed,
            "provider": state(), "restarted": restarted})
        raise RuntimeError("inventory restart did not reach its real full source hash and resumed range")
    exchange_window = finish_managed_storage_window(native, worker, tools, workflow.prepared,
        external_capture_processes(current_processes), workflow.boundaries,
        restarted["helper"]["restartCapture"], "external-inventory-resume")
    exchange = inventory.require_inventory_restart_exchange(exchange_window,
        restarted["helper"]["process"], checkpoint, expected,
        workflow.prepared["captureSelection"]["sourceDigest"],
        workflow.boundaries["codecProvenance"]["codecSourceSha256"],
        lambda reference: direct_selected_bytes({"path": reference["file"], "sha256": reference["sha256"]}, 8388608))
    result = {"checkpoint": checkpoint, "restart": restarted, "resumedProviderRange": resumed,
        "renewedCollectorFence": renewed, "newEpochHash": exchange, "newEpochWindow": exchange_window,
        "completeInventory": completed, "sourceSelection": selection,
        "providerSettlement": None, "remoteDrain": None}
    retain_direct_flow(label + "-restart.json", result)
    return {"processes": current_processes, "helper": restarted["helper"], "evidence": result}
