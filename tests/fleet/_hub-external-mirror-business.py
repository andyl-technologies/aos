"""Call one real Full and Pull-through case inside the existing paired window.

Both destinations use the independently admitted current External binding. The
small signed source is additional functional coverage; the original large OCI,
Copy and cancellation corpus continues unchanged afterward.
"""

import json
import shlex
import time


def run_external_mirror_business(client, native, worker, tools, prepared, processes,
                                 helper, direct, exports, credentials, controls,
                                 refresh, workflow, artifacts, ownership):
    """Join public controls, reviewed purpose, actual epochs, SQL and bytes."""
    if tools["copyIsolationCase"] != "same_worker" or tools.get("mirrorFunctionalReviewer") is None:
        raise ValueError("Mirror window must run exactly once in the original same-Worker pair")
    run = prepared["coordinates"]["runId"]
    cutoff = tools["fleetCutoffMonotonic"]
    if time.monotonic() >= cutoff:
        raise ValueError("Mirror business window reached the original fixture cutoff")
    config = json.loads(read_direct_guest_file(worker, tools["python"], prepared["configurationFile"], 1048576))
    mirror_config = json.loads(config["bindings"]["HUB_EXTERNAL_MIRROR_CONSUMER"])
    if mirror_config["version"] != 1 or len(mirror_config["domains"]) != 1:
        raise ValueError("Mirror caller requires its actual single installed source domain")
    scope = require_mirror_reserved_cohorts(mirror_config["domains"][0], credentials["binding"], run)
    source = prepare_external_mirror_signed_source(client, tools, run)
    upstream = install_external_mirror_upstream(client, worker, tools, source, ownership)
    organization = {"ownerScopeKey": credentials["binding"]["ownerScopeKey"], "slug": "external-" + run}
    registries = {}
    for mode, suffix in (("full", "full"), ("pull_through", "pull-through")):
        name = "mirror-" + suffix + "-" + run[:8]
        registries[mode] = controls.create_external_registry(organization, credentials["binding"],
            name, [source["signed"]["trustKey"]], name,
            scope["reservedPlacementRoot"] + "/" + suffix, 3, True,
            mirror_run_id=run, label_prefix="external-mirror-" + run + "-" + suffix)
    installed = None
    current_processes, current_helper = processes, helper

    def install_purpose(selection, configured):
        nonlocal installed, current_processes, current_helper
        if installed is None:
            installed = review_install_external_mirror(native, worker, tools, prepared,
                current_processes, current_helper, direct, exports)
            # Verification of the original producer lifetime finishes before
            # shutdown. The successor is validated by its actual constructor.
            restarted = restart_external_mirror_native(native, tools, prepared,
                current_processes, current_helper, installed["triplet"], workflow, artifacts, ownership)
            current_processes, current_helper = restarted["processes"], restarted["helper"]
            installed["successor"] = current_helper
        actual = json.loads(read_direct_guest_file(native, tools["python"],
            installed["triplet"]["artifactFile"], 32768))
        current = int(private_guest_command(native, shlex.join([tools["python"], "-c",
            "import time; print(int(time.time()))"])).strip())
        if not actual["issuedAt"] <= current < actual["validUntil"]:
            raise ValueError("Actual Mirror functional artifact expired before its called case")
        if (actual["upstreamBase"] != selection["upstream"]
                or actual["placementPrefix"] != scope["reservedPlacementRoot"]):
            raise ValueError("Called Mirror case differs from its signed purpose")
        return {"producer": installed["producer"], "installed": installed["installed"],
            "successor": installed["successor"], "scope": "actual emulated functional purpose; no Hosted acceptance"}

    read_sql = lambda query, label: read_external_oci_sql(native, tools, prepared,
        current_processes["native"], query, label)
    cases = {}
    for mode in ("full", "pull_through"):
        selection = mirror_selection(registries[mode], source["upstream"], run, mode,
            frontier="1.0.0", source_commit=source["signed"]["sourceCommit"], binding=credentials["binding"])
        rows = source["inventory"]["objects" if mode == "full" else "pullObjects"]
        counters = {"value": 0}

        def read_visible(selected, expected, deadline):
            counters["value"] += 1
            return read_external_mirror_visible(client, tools, selected, expected, refresh,
                prepared["coordinates"]["clientRoot"] + "/mirror-reads/"
                    + ("full" if mode == "full" else "pull") + "-" + str(counters["value"]), cutoff=deadline)

        cases[mode] = run_external_mirror_case(controls, selection, rows,
            current_helper["readiness"], install_purpose=install_purpose,
            observe_effects=lambda selected, configured, ordinal: observe_mirror_effects(read_sql,
                selected, configured, "external-mirror-" + run + "-" + mode.replace("_", "-") + "-sql-" + str(ordinal)),
            read_visible=read_visible, retain=retain_direct_flow, cutoff=cutoff)
    evidence = {"version": 1, "source": source, "upstream": upstream, "reservedScope": scope,
        "registries": registries, "cases": cases, "purpose": installed,
        "nativeBulkBytes": None, "scope": "one real Full and Pull-through emulated External Mirror window"}
    retain_direct_flow("external-mirror-" + run + "-business.json", evidence)
    ownership["mirrorBusiness"] = evidence
    return {"processes": current_processes, "helper": current_helper, "evidence": evidence}
