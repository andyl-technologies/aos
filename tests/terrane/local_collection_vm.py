"""Executes source-bound local repository and recovery regressions in a guest."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


PREFIX = "gc::runner::permanent_local_tests::"
CASES = [
    PREFIX + "recovery::permanent_local_collection_reconciles_with_its_original_live_session",
    PREFIX + "recovery::permanent_local_empty_pass_keeps_owner_and_reclaims_late_same_key_residue",
    PREFIX + "recovery::permanent_local_takeover_uses_current_lease_without_replacing_owner",
    PREFIX + "faults::permanent_local_foreign_hardlink_refuses_unlink",
    PREFIX + "faults::permanent_local_cancelled_waiter_before_open_retains_exclusion_through_worker_completion",
]

HINT_CASES = [
    PREFIX + "recovery::permanent_local_empty_pass_keeps_owner_and_reclaims_late_same_key_residue",
]

LOCAL_DELETE_CASES = [
    "gc::runner::tests::local_deletion::success::"
    "full_d_and_current_lease_unlink_exact_triple_and_finish_done",
]


COPIED_SHARED_CASES = [
    PREFIX + "recovery::copied_first_ownership_and_recovery_share_one_live_session",
    "gc::runner::copied_retirement_tests::"
    "gc_copied_retirement_native_pack_only_selects_new_destination_owner",
]


MISSING_TRASH_CASES = [
    "gc::runner::tests::restore::missing_trash::"
    "gc_refresh_native_missing_trash_uses_fresh_cycle_and_preserves_old_journal",
    "gc::runner::tests::restore::gc_restore_native_unknown_trash_age_restores_exact_generation",
]


PREOWNERSHIP_CASES = [
    "gc::runner::tests::restore::" + name
    for name in [
        "gc_restore_native_unknown_trash_age_restores_exact_generation",
        "gc_restore_native_preserves_fresh_live_quarantine_and_selected_values",
        "gc_restore_native_stale_and_unknown_incarnations_never_publish",
        "gc_restore_native_missing_pair_never_advertises_old_placement",
        "gc_restore_native_burn_owner_and_deleteowned_refuse",
        "gc_restore_native_metadata_only_pair_handles_imported_unknown",
        "gc_restore_native_each_handoff_rechecks_current_controls_and_pair",
        "gc_restore_native_sync_and_noop_results_never_acknowledge",
        "gc_restore_native_cancelled_worker_retains_exclusions",
        "gc_restore_native_reopen_and_fresh_cycle_make_old_trash_stale",
        "missing_trash::gc_refresh_native_missing_trash_uses_fresh_cycle_and_preserves_old_journal",
    ]
]

RESTORATION_SESSION_CASES = [
    "gc::runner::tests::restore::session::gc_restoration_native_hands_original_session_to_fresh_marking",
    "gc::runner::tests::restore::session::gc_restoration_native_expired_handoff_creates_no_checkpoint",
    "gc::runner::tests::restore::gc_restore_native_reopen_and_fresh_cycle_make_old_trash_stale",
]

STARTUP_RESTORATION_CASES = [
    "gc::runner::tests::restore::session::gc_restoration_native_hands_original_session_to_fresh_marking",
    "gc::runner::tests::restore::session::gc_restoration_native_startup_restores_required_meta_before_marking",
    "gc::runner::tests::local_deletion::success::protected_done_status_is_available_before_marking_without_resurrection",
]


COORDINATION_LOCK_CASES = [
    "store::bindings::tests::" + name for name in [
        "native_existing_locks_need_no_file_write_permission",
        "native_existing_lock_never_creates_missing_coordination",
        "native_existing_try_locks_preserve_readers_writers_and_retained_duplicates",
        "native_try_locks_reject_replaced_open_names_in_both_modes",
    ]
]


READONLY_REPOSITORY_CASES = [
    "repository::local::readonly::tests::" + name for name in [
        "native_read_only_reopen_keeps_writable_backing_and_denies_mutations",
        "native_read_only_reopen_refuses_missing_registration_without_repair",
        "native_read_only_reopen_refuses_missing_coordination_without_repair",
    ]
] + [
    "repository::local::tests::"
    "local_directory_edit_preserves_canonical_implicit_owner_on_reopen",
]


def verify_image(source, image):
    """Binds the actual retained Cargo test image to every immutable crate input."""
    identity = json.loads((image / "share/identity.json").read_text())
    assert identity["schema_version"] == 1 and identity["source"] == str(source)
    assert identity["default_features"] is False
    assert identity["requested_features"] == ["tokio", "surface-sdk"]
    assert identity["features"] == ["send", "std", "surface-sdk", "tokio"]
    assert identity["cargo_profile"] == "test"
    assert identity["profile"]["test"] is True
    assert identity["profile"]["opt_level"] == "s"
    assert identity["profile"]["debuginfo"] == 0
    assert identity["working_directory"] == "terrane/sdk/terrane-sdk"
    hashes = {
        path.relative_to(source / "crates").as_posix():
        hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((source / "crates").rglob("*"))
        if path.is_file() and path.relative_to(source / "crates").as_posix()
        != ".cargo/config.toml"
    }
    assert identity["input_sha256"] == hashes
    rows = [json.loads(line) for line in (image / "share/build.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("package_id") == identity["package_id"]
                 and row.get("target", {}).get("name") == "terrane_sdk"
                 and row.get("target", {}).get("kind") == ["lib"]
                 and row.get("profile", {}).get("test") is True
                 and row.get("executable")]
    assert len(artifacts) == 1
    assert artifacts[0]["features"] == identity["features"]
    assert artifacts[0]["profile"] == identity["profile"]
    binary = image / "libexec/terrane-native-sdk-tests"
    assert binary.read_bytes().startswith(b"\x7fELF")
    return hashlib.sha256(binary.read_bytes()).hexdigest()


def main():
    """Runs exact real native producers under an unprivileged ext4 identity."""
    assert os.getuid() == os.geteuid() == 840
    assert os.getgid() == os.getegid() == 840 and os.getgroups() == []
    status = dict(line.split(":", 1) for line in Path("/proc/self/status")
                  .read_text().splitlines() if ":" in line)
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]:
        assert int(status[name].strip(), 16) == 0, name
    assert status["NoNewPrivs"].strip() == "1"
    source = Path(os.environ["src"])
    image = Path(os.environ["TERRANE_COLLECTION_TEST_IMAGE"])
    evidence = Path(os.environ["TERRANE_COLLECTION_EVIDENCE"])
    suite = os.environ.get("TERRANE_COLLECTION_SUITE", "collection-reconciliation")
    if suite == "collection-reconciliation":
        cases = CASES
    elif suite == "maintenance-owner-hints":
        cases = HINT_CASES
    elif suite == "local-deletion-hints":
        cases = LOCAL_DELETE_CASES
    elif suite == "copied-shared-session":
        cases = COPIED_SHARED_CASES
    elif suite == "missing-trash-refresh":
        cases = MISSING_TRASH_CASES
    elif suite == "preownership-restore":
        cases = PREOWNERSHIP_CASES
    elif suite == "restoration-session":
        cases = RESTORATION_SESSION_CASES
    elif suite == "startup-restoration":
        cases = STARTUP_RESTORATION_CASES
    elif suite == "coordination-locks":
        cases = COORDINATION_LOCK_CASES
    elif suite == "readonly-repository":
        cases = READONLY_REPOSITORY_CASES
    else:
        raise ValueError("unknown native collection qualification suite")

    os.chdir(source / "crates")
    binary_hash = verify_image(source, image)
    binary = image / "bin/terrane-native-sdk-tests"
    checker = source / "tests/terrane/check_native_gate.py"
    inventory = evidence / "inventory.log"
    with inventory.open("wb") as output:
        subprocess.run([str(binary), "--list"], stdout=output, stderr=subprocess.STDOUT,
                       check=True, timeout=5)
    subprocess.run([sys.executable, str(checker), "inventory", str(inventory),
                    json.dumps(cases)], check=True, timeout=5)
    for case in cases:
        log = evidence / (case.rsplit("::", 1)[-1] + ".log")
        with log.open("wb") as output:
            completed = subprocess.run([str(binary), case, "--exact", "--test-threads=1"],
                                       stdout=output, stderr=subprocess.STDOUT, timeout=180)
        print(log.read_text(), end="", flush=True)
        completed.check_returncode()
        subprocess.run([sys.executable, str(checker), "execution", str(log),
                        json.dumps([case])], check=True, timeout=5,
                       stdout=subprocess.DEVNULL)
    assert verify_image(source, image) == binary_hash
    print("LOCAL_COLLECTION_RECONCILIATION_PROOF " + json.dumps({
        "source": str(source), "image": str(image), "cases": cases,
        "uid": os.getuid(), "capabilities": 0, "no_new_privileges": True,
        "binary_sha256": binary_hash, "configured_gc_runtime": False,
    }, sort_keys=True), flush=True)
    if suite == "collection-reconciliation":
        print("PASS original collection session reconciles actual permanent residues and retains "
              "marking; recovery lease, hardlink and cancellation controls pass", flush=True)
    elif suite == "maintenance-owner-hints":
        print("PASS actual owner discovery survives completed empty passes and reclaims late residue",
              flush=True)
    elif suite == "copied-shared-session":
        print("PASS copied first ownership and permanent recovery retain one live session; "
              "original standalone ownership still passes", flush=True)
    elif suite == "missing-trash-refresh":
        print("PASS missing Trash recovery creates a fresh exclusion and preserves old journals; "
              "original restoration still passes", flush=True)
    elif suite == "preownership-restore":
        print("PASS all eleven pre-ownership restoration and fresh-cycle recovery cases in ext4 guest",
              flush=True)
    elif suite == "startup-restoration":
        print("PASS bounded startup restores required Meta before marking; protected Done "
              "remains observable without resurrection", flush=True)
    elif suite == "coordination-locks":
        print("PASS existing read-only coordination preserves shared/exclusive exclusion, retained "
              "descriptors, missing-state refusal and original inode checks", flush=True)
    elif suite == "readonly-repository":
        print("PASS native read-only reopening preserves writable backing and selected signed reads; "
              "mutations and missing controls refuse without repair; original writable reopen passes",
              flush=True)
    elif suite == "restoration-session":
        print("PASS restoration and fresh marking retain original session poison and lease; "
              "expired handoff has no effects and original Meta restoration still passes", flush=True)
    else:
        print("PASS actual local-v1 intent discovery survives exact full-D deletion and durable Done",
              flush=True)


if __name__ == "__main__":
    main()
