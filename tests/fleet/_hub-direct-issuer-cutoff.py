"""Exercise SQL-reviewed denial and admission through the retained live issuer.

The readonly operator exports actual blocked and admitted SQL publications.
Only Native's publisher prepares control messages. A premature conflict is
followed by a signed unchanged head; successful reopening follows the actual
retained expiry floor. No provider drain or old unknown settlement is inferred.
"""

import hashlib
import json
from pathlib import Path
import re
import shlex
import time


def export_direct_issuer_control(worker, native, tools, authority, desired, label):
    """Export the current reviewed head and transfer its exact canonical bytes."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,47}", label):
        raise ValueError("issuer publication export label is invalid")
    selected = authority["review"]["selection"]["authority"]
    destination = "/var/lib/hybrid-worker/operator/issuer-control-" + label
    private_guest_command(worker, shlex.join([
        tools["authorityBootstrap"], "--database-url-file", "/var/lib/hybrid-worker/operator/sql.url",
        "export-publication", "--authority-id", selected["authorityId"],
        "--guard-namespace-id", selected["guardNamespaceId"],
        "--executor-identity", selected["executorIdentity"], "--output", destination,
    ]), timeout=120)
    publication = read_direct_guest_file(worker, tools["python"], destination + "/publication.json", 1048576)
    receipt = json.loads(read_direct_guest_file(worker, tools["python"],
        destination + "/publication-receipt.json", 65536))
    document = json.loads(publication)
    if (receipt["version"] != 1 or receipt["authority_id"] != selected["authorityId"]
            or receipt["publication_sha256"] != hashlib.sha256(publication).hexdigest()
            or str(receipt["generation"]) != desired["desiredGeneration"]
            or receipt["admission_digest"] != desired["digest"]
            or str(document["generation"]) != desired["desiredGeneration"]
            or document["digest"] != desired["digest"]
            or document["admission"]["state"] != receipt["state"]):
        raise ValueError("actual SQL control export differs from the reviewed API head")
    install_direct_guest_file(native, tools["python"],
        "/var/lib/hybrid-authority/control-" + label + ".json", publication)
    retain_direct_flow("issuer-sql-export-" + label + ".json", receipt)
    return {"publication": document, "receipt": receipt}


def assert_direct_issuer_published(exchange, publication):
    """Match an actual signed live head to the exact exported SQL publication."""
    journal = exchange["reply"]["current"]["journal"]
    if (journal["generation"] != str(publication["generation"])
            or journal["admission_digest"] != publication["digest"]
            or journal["state"] != publication["admission"]["state"]
            or exchange["reply"]["applied"] is None):
        raise ValueError("live issuer did not acknowledge the exact exported SQL control")


def assert_direct_issuer_cutoff_conflict(transport, prepared, observed, floor, uncertainty):
    """Exclude stale request or elapsed-floor refusals from the cutoff scenario."""
    if (transport["exitCode"] != 0 or transport["status"] != 409 or transport["stderrBytes"]
            or transport["requestSha256"] != prepared["requestSha256"]
            or not prepared["observedAtSeconds"] <= observed < prepared["observedAtSeconds"] + 30
            or observed - uncertainty >= floor):
        raise RuntimeError("premature publisher has no fresh exact TLS conflict before cutoff; no replay")


def run_direct_issuer_cutoff(native, worker, tools, helper, controls, authority):
    """Require actual denial, premature rejection and retained-floor reopening."""
    selected = authority["review"]["selection"]["authority"]
    bootstrap = authority["exported"]["bootstrap"]
    configuration_bytes = read_direct_guest_file(native, tools["python"],
        "/var/lib/hybrid-authority/configuration.json", 1048576)
    configuration = json.loads(configuration_bytes)
    uncertainty = int(configuration["clock_uncertainty"]) + int(configuration["clock_commit_latency"]) + 1
    if (int(configuration["clock_uncertainty"]) != int(bootstrap["clock_uncertainty"])
            or int(configuration["clock_commit_latency"]) < 1
            or configuration["installation"] != bootstrap["issuer_installation"]
            or configuration["policy"]["timing_profile"] != bootstrap["timing_profile"]
            or not 0 < uncertainty <= int(bootstrap["timing_profile"]["maximum_clock_uncertainty"])):
        raise ValueError("actual issuer interval configuration differs from the exported clock pins")
    before = exchange_direct_issuer(native, worker, tools, helper, bootstrap,
        {"kind": "current"}, "cutoff-before")
    get_head = lambda: controls.call("StorageAuthorityService", "GetAuthority", {
        "authorityId": selected["authorityId"],
    })
    head = get_head()
    admitted = head["desiredAdmission"]
    original_decision = admitted["decision"]
    if (original_decision["state"] != "STORAGE_AUTHORITY_DESIRED_STATE_ADMITTED"
            or admitted["desiredGeneration"] != before["reply"]["current"]["journal"]["generation"]
            or admitted["digest"] != before["reply"]["current"]["journal"]["admission_digest"]):
        raise ValueError("actual live issuer and SQL admitted predecessor differ")
    controls.authority_decision({"setAdmission": {
        "authorityId": selected["authorityId"], "guardNamespaceId": selected["guardNamespaceId"],
        "expectedGeneration": admitted["desiredGeneration"], "expectedDigest": admitted["digest"],
        "state": "STORAGE_AUTHORITY_DESIRED_STATE_BLOCKED", "associationIds": [],
    }}, admitted["desiredGeneration"], "fleet-direct-cutoff-block")
    blocked = get_head()["desiredAdmission"]
    blocked_export = export_direct_issuer_control(worker, native, tools, authority, blocked, "blocked")
    denied = exchange_direct_issuer(native, worker, tools, helper, bootstrap,
        {"kind": "publish", "input": blocked_export["publication"]}, "cutoff-denial",
        before["verified"]["observedAtSeconds"], role="publisher")
    assert_direct_issuer_published(denied, blocked_export["publication"])
    floor = int(denied["reply"]["current"]["journal"]["largest_issued_expiry"])
    # Reuse only the actual reviewed attestation and membership from the
    # predecessor. The server and export recheck their current SQL validity.
    controls.authority_decision({"setAdmission": {
        "authorityId": selected["authorityId"], "guardNamespaceId": selected["guardNamespaceId"],
        "expectedGeneration": blocked["desiredGeneration"], "expectedDigest": blocked["digest"],
        "state": "STORAGE_AUTHORITY_DESIRED_STATE_ADMITTED",
        "attestationId": original_decision["attestationId"],
        "associationIds": original_decision["associationIds"],
    }}, blocked["desiredGeneration"], "fleet-direct-cutoff-admit")
    reopened = get_head()["desiredAdmission"]
    reopened_export = export_direct_issuer_control(worker, native, tools, authority, reopened, "admitted")
    def native_now():
        return int(direct_guest_python(native, tools["python"],
            "import time\nprint(int(time.time()))", {}))
    observed = native_now()
    if observed - uncertainty >= floor:
        raise RuntimeError("actual retained expiry floor already passed; no premature conflict fabricated")
    try:
        exchange_direct_issuer(native, worker, tools, helper, bootstrap,
            {"kind": "publish", "input": reopened_export["publication"]}, "cutoff-premature",
            denied["verified"]["observedAtSeconds"], role="publisher")
    except RuntimeError:
        # A conflict is not a signed denial receipt. Independently read the
        # real signed head below before asserting that admission stayed blocked.
        transport = json.loads(Path("external-direct-flow/issuer-transport-cutoff-premature.json").read_bytes())
        preparation = json.loads(Path(
            "external-direct-flow/shared-control-issuer-prepare-cutoff-premature.json").read_bytes())
        prepared = json.loads(preparation["stdout"])
        conflict_observed = native_now()
        assert_direct_issuer_cutoff_conflict(transport, prepared, conflict_observed, floor, uncertainty)
    else:
        raise RuntimeError("publisher unexpectedly admitted before the retained cutoff; effects preserved")
    still_denied = exchange_direct_issuer(native, worker, tools, helper, bootstrap,
        {"kind": "current"}, "cutoff-conflict-head", denied["verified"]["observedAtSeconds"])
    first, second = denied["reply"]["current"]["journal"], still_denied["reply"]["current"]["journal"]
    if first != second:
        raise ValueError("actual signed issuer head changed after the premature conflict")
    deadline = time.monotonic() + 3600
    clocks = []
    while True:
        observed = native_now()
        clocks.append(observed)
        if observed - uncertainty >= floor:
            break
        if time.monotonic() > deadline:
            raise RuntimeError("actual issuer cutoff not reached; publication and old originals retained")
        time.sleep(1)
    admitted_exchange = exchange_direct_issuer(native, worker, tools, helper, bootstrap,
        {"kind": "publish", "input": reopened_export["publication"]}, "cutoff-reopened",
        still_denied["verified"]["observedAtSeconds"], role="publisher")
    assert_direct_issuer_published(admitted_exchange, reopened_export["publication"])
    result = {"version": 1, "largestIssuedExpiry": floor, "clockUncertaintySeconds": uncertainty,
        "nativeConfigurationSha256": hashlib.sha256(configuration_bytes).hexdigest(),
        "actualNativeClockObservations": clocks, "prematureConflict": transport,
        "conflictObservedNativeSeconds": conflict_observed,
        "blockedExport": blocked_export["receipt"], "admittedExport": reopened_export["receipt"],
        "blockedJournalSha256": denied["verified"]["journalSha256"],
        "admittedJournalSha256": admitted_exchange["verified"]["journalSha256"],
        "installedConsumerProfileAutomaticallyUpdated": False,
        "scope": "actual SQL export and signed live issuer cutoff; old consumer/profile remains distinct, no provider drain or unknown settlement"}
    retain_direct_flow("actual-issuer-cutoff.json", result)
    return result
