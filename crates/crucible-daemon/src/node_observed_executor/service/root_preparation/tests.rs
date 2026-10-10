//! Exercises durable Root request exclusion without minting native readiness.

// crucible-lint: allow panic-shortcut -- These data-only custody assertions panic on their original failed invariant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
};
use std::sync::{Arc, Mutex, atomic::AtomicBool, mpsc};

fn request() -> RootPreparationRequest {
    RootPreparationRequest {
        format: "crucible.root-preparation-request".into(),
        version: 1,
        execution: "91919191919191919191919191919191".into(),
        selections: worker::selections().unwrap(),
        scenario: Bytes::new(Vec::new()),
        action: RootPreparationAction::DescribeHeldUart {},
    }
}

fn storage(
    directory: &std::path::Path,
) -> (Arc<dyn ImmutableBlobBackend>, Arc<dyn MutableRefBackend>) {
    (
        Arc::new(DirectoryBlobBackend::new(
            "root-model",
            directory.join("blobs"),
        )),
        Arc::new(DirectoryRefBackend::new(directory.join("refs"))),
    )
}

#[test]
fn description_is_data_only_and_exact_selection_and_empty_slot_are_mandatory() {
    let original = request();
    original.validate().unwrap();
    let mut changed = original.clone();
    changed.selections.reverse();
    assert!(changed.validate().is_err());
    changed = original.clone();
    changed.selections[1].kind = crate::node_observed_executor::InstalledNodeKind::HostClock;
    assert!(changed.validate().is_err());
    changed = original.clone();
    changed.scenario = Bytes::new(b"{}".to_vec());
    assert!(changed.validate().is_err());
    changed = original.clone();
    changed.action = RootPreparationAction::CaptureHeldUart {};
    assert!(changed.validate().is_err());
    changed = original.clone();
    changed.version = 2;
    assert!(changed.validate().is_err());
}

#[test]
fn duplicate_unknown_fields_and_forged_dynamic_recipe_are_refused_before_reservation() {
    let original = encode(&request()).unwrap();
    let mut duplicate = original.clone();
    duplicate.pop();
    duplicate.extend_from_slice(b",\"version\":1}");
    assert!(RootPreparationRequest::from_json(&duplicate).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    value["action"]["operation"] = "arbitrary_run".into();
    assert!(RootPreparationRequest::from_json(&encode(&value).unwrap()).is_err());
    value = serde_json::from_slice(&original).unwrap();
    value["authority"] = "operator-imported".into();
    assert!(RootPreparationRequest::from_json(&encode(&value).unwrap()).is_err());
}

#[test]
fn pending_original_raw_request_survives_restart_without_another_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let ledger = ledger::RootPreparationLedger::new(blobs.clone(), refs.clone()).unwrap();
    let original = request();
    let reserved = ledger.reserve(&original).unwrap();
    assert!(reserved.original_dispatch);
    let identity = ContentId::parse(&reserved.record.request).unwrap();
    assert_eq!(
        blobs
            .read(identity, None)
            .unwrap()
            .read_all(4 * 1024 * 1024)
            .unwrap(),
        encode(&original).unwrap()
    );
    assert!(ledger.retention_roots().unwrap().contains(&identity));

    let restarted = ledger::RootPreparationLedger::new(blobs, refs).unwrap();
    let retained = restarted.reserve(&original).unwrap();
    assert!(!retained.original_dispatch);
    assert_eq!(
        encode(&retained.record).unwrap(),
        encode(&reserved.record).unwrap()
    );
    assert!(
        restarted
            .complete(
                &retained,
                RootPreparationState::Unavailable {
                    reason: "model refusal".into()
                }
            )
            .is_err()
    );
    let mut changed = original.clone();
    changed.selections[0].owner = crucible_node_contract::Id::new("foreign-owner").unwrap();
    assert!(restarted.reserve(&changed).is_err());
    assert_eq!(
        encode(&restarted.state(&original.execution).unwrap()).unwrap(),
        encode(&reserved.record).unwrap()
    );
}

#[test]
fn claimed_original_without_its_route_record_never_reacquires_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let original = request();
    let claims =
        super::super::original_claim::OriginalClaims::new(blobs.clone(), refs.clone()).unwrap();
    assert_eq!(
        claims
            .reserve(
                &original.execution,
                super::super::original_claim::Route::Root,
                &encode(&original).unwrap()
            )
            .unwrap(),
        super::super::original_claim::Reservation::Original
    );
    let ledger = ledger::RootPreparationLedger::new(blobs, refs).unwrap();
    assert!(ledger.reserve(&original).is_err());
    assert!(ledger.state(&original.execution).is_err());
    assert!(!claims.retention_roots().unwrap().is_empty());
}

#[test]
fn queued_status_is_immediate_and_full_queue_preserves_original_unavailable_record() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let ledger = ledger::RootPreparationLedger::new(blobs.clone(), refs.clone()).unwrap();
    let (commands, receiver) = mpsc::sync_channel(1);
    let service = super::super::NodeObservationService {
        commands,
        stopping: Arc::new(AtomicBool::new(false)),
        roots: Arc::new(Mutex::new(Default::default())),
        retired: Arc::new(AtomicBool::new(false)),
        preparations: None,
        debug: super::super::debug::DebugLedger::new(blobs.clone(), refs.clone()).unwrap(),
        capabilities:
            super::super::capability_preparation::ledger::CapabilityPreparationLedger::new(
                blobs, refs,
            )
            .unwrap(),
        root_preparations: ledger,
    };
    let original = request();
    let first = service.submit_root_preparation(original.clone()).unwrap();
    assert!(matches!(
        first.outcome,
        RootPreparationState::AwaitingAdmission {}
    ));
    assert_eq!(
        encode(
            &service
                .root_preparation_status(&original.execution)
                .unwrap()
        )
        .unwrap(),
        encode(&first).unwrap()
    );
    assert_eq!(
        encode(&service.submit_root_preparation(original.clone()).unwrap()).unwrap(),
        encode(&first).unwrap()
    );
    let mut other = original.clone();
    other.execution = "92929292929292929292929292929292".into();
    let refused = service.submit_root_preparation(other.clone()).unwrap();
    assert!(matches!(
        refused.outcome,
        RootPreparationState::Unavailable { .. }
    ));
    assert_eq!(
        encode(&service.submit_root_preparation(other).unwrap()).unwrap(),
        encode(&refused).unwrap()
    );
    assert!(matches!(
        receiver.try_recv().unwrap(),
        super::super::Command::RootPreparation { .. }
    ));
    assert!(receiver.try_recv().is_err());
}

#[test]
fn refusal_text_preserves_utf8_within_the_original_byte_credit() {
    let original = "é".repeat(3000);
    let retained = diagnostic(&original);
    assert_eq!(retained.len(), 4096);
    assert!(original.starts_with(&retained));
    assert_eq!(
        diagnostic("short original refusal"),
        "short original refusal"
    );

    let crossing = format!("{}é", "x".repeat(4095));
    let retained = diagnostic(&crossing);
    assert_eq!(retained.len(), 4095);
    assert!(crossing.starts_with(&retained));
}

#[test]
fn first_refusal_is_readable_while_original_preactivation_owner_remains_retained() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let ledger = ledger::RootPreparationLedger::new(blobs.clone(), refs.clone()).unwrap();
    let original = request();
    let reservation = ledger.reserve(&original).unwrap();
    let mut journal = diagnostics::Journal::new(ledger.clone(), &reservation.record);
    journal.current.owner = "initial".into();
    journal.current.native_preparation_started = true;
    journal.enter("initial_coordinator_snapshot").unwrap();
    journal.first_refusal("original retained coordinator refusal");
    journal.publish().unwrap();

    let initial = ledger.diagnostic(&original.execution).unwrap();
    assert!(!initial.activation_present);
    assert!(initial.native_preparation_started);
    assert_eq!(initial.owner, "initial");
    assert_eq!(
        initial.first_refusal.as_ref().unwrap().phase,
        "initial_coordinator_snapshot"
    );

    journal.first_refusal("later cleanup refusal must not replace original");
    journal.enter("begin_retirement").unwrap();
    let restored = ledger::RootPreparationLedger::new(blobs, refs).unwrap();
    let actual = restored.diagnostic(&original.execution).unwrap();
    assert_eq!(actual.first_refusal, initial.first_refusal);
    let mut replacement = actual.clone();
    replacement.revision += 1;
    replacement.first_refusal = None;
    assert!(
        restored
            .publish_diagnostic(&replacement, Some(&actual))
            .is_err()
    );
    assert_eq!(restored.diagnostic(&original.execution).unwrap(), actual);
    assert_eq!(actual.phase, "begin_retirement");
    assert!(matches!(
        restored.state(&original.execution).unwrap().outcome,
        RootPreparationState::AwaitingAdmission {}
    ));
    assert_eq!(
        restored
            .state(&original.execution)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        reservation.record.canonical_bytes().unwrap()
    );
    assert!(!restored.reserve(&original).unwrap().original_dispatch);
    let identity = ContentId::for_bytes(
        crucible_cas::content_store::ObjectKind::Trace,
        1,
        &actual.canonical_bytes().unwrap(),
    );
    assert!(restored.retention_roots().unwrap().contains(&identity));
}

#[test]
fn diagnostic_lookup_does_not_acquire_an_unrelated_actor_custody_lock() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let ledger = ledger::RootPreparationLedger::new(blobs, refs).unwrap();
    let original = request();
    let reservation = ledger.reserve(&original).unwrap();
    let mut journal = diagnostics::Journal::new(ledger.clone(), &reservation.record);
    journal.enter("prepare_native_world").unwrap();

    let actor_custody = Arc::new(Mutex::new(journal));
    let held = actor_custody.lock().unwrap();
    let actual = ledger.diagnostic(&original.execution).unwrap();
    assert_eq!(actual.phase, "prepare_native_world");
    assert_eq!(actual.request, reservation.record.request);
    drop(held);
}

#[test]
fn diagnostic_revision_and_scope_deficits_leave_last_original_snapshot_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let ledger = ledger::RootPreparationLedger::new(blobs, refs).unwrap();
    let original = request();
    let reservation = ledger.reserve(&original).unwrap();
    let mut journal = diagnostics::Journal::new(ledger.clone(), &reservation.record);
    journal.enter("bounded_phase_1").unwrap();
    for _ in 0..1024 {
        journal.enter("bounded_phase_1").unwrap();
    }
    assert_eq!(ledger.diagnostic(&original.execution).unwrap().revision, 1);
    for revision in 2..=64 {
        journal.enter(&format!("bounded_phase_{revision}")).unwrap();
    }
    let actual = ledger.diagnostic(&original.execution).unwrap();
    assert_eq!(actual.revision, 64);
    assert!(journal.enter("exhausted_phase").is_err());
    assert_eq!(ledger.diagnostic(&original.execution).unwrap(), actual);

    let mut foreign = actual.clone();
    foreign.execution = "92929292929292929292929292929292".into();
    assert!(ledger.publish_diagnostic(&foreign, Some(&actual)).is_err());
    assert_eq!(ledger.diagnostic(&original.execution).unwrap(), actual);
    let mut excessive = actual;
    excessive.first_refusal = Some(RootFirstRefusal {
        phase: "refusal".into(),
        reason: "x".repeat(4097),
    });
    assert!(excessive.canonical_bytes().is_err());
}

#[test]
fn exhausted_diagnostics_fence_new_effects_but_leave_original_cleanup_runnable() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let ledger = ledger::RootPreparationLedger::new(blobs, refs).unwrap();
    let original = request();
    let reservation = ledger.reserve(&original).unwrap();
    let mut journal = diagnostics::Journal::new(ledger.clone(), &reservation.record);
    for revision in 1..=64 {
        journal
            .enter(&format!("original_phase_{revision}"))
            .unwrap();
    }
    let original_snapshot = ledger.diagnostic(&original.execution).unwrap();
    let mut fresh_effects = 0;
    assert!(
        worker::advance_after_checkpoint(journal.enter("new_effect"), false, || {
            fresh_effects += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(fresh_effects, 0);
    assert_eq!(
        ledger.diagnostic(&original.execution).unwrap(),
        original_snapshot
    );

    let mut original_cleanup_turns = 0;
    worker::advance_after_checkpoint(journal.enter("original_cleanup"), true, || {
        original_cleanup_turns += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(original_cleanup_turns, 1);
    assert_eq!(
        ledger.diagnostic(&original.execution).unwrap(),
        original_snapshot
    );

    journal.first_refusal("first retained cleanup refusal");
    journal.publish().unwrap();
    let failure = ledger.diagnostic(&original.execution).unwrap();
    assert_eq!(failure.revision, 65);
    assert_eq!(
        failure.first_refusal.unwrap().reason,
        "first retained cleanup refusal"
    );
    assert!(journal.enter("further_snapshot").is_err());
    assert!(matches!(
        ledger.state(&original.execution).unwrap().outcome,
        RootPreparationState::AwaitingAdmission {}
    ));
}

#[test]
fn cleanup_queue_diagnostic_rejects_excessive_original_failure_body() {
    let directory = tempfile::tempdir().unwrap();
    let (blobs, refs) = storage(directory.path());
    let ledger = ledger::RootPreparationLedger::new(blobs, refs).unwrap();
    let reservation = ledger.reserve(&request()).unwrap();
    let mut journal = diagnostics::Journal::new(ledger, &reservation.record);
    journal.current.native_cleanup =
        Some(crate::node_observed_executor::InstalledRootCleanupStatus {
            custody_present: true,
            in_flight: false,
            reclaimed: false,
            failed: true,
            first_failure: Some(
                crate::node_observed_executor::InstalledRootCleanupFailure::Refused {
                    reason: "x".repeat(2049),
                },
            ),
        });
    assert!(journal.enter("reclaim").is_err());
}

#[test]
fn root_and_debug_original_claims_exclude_each_other_before_queue_dispatch() {
    use super::super::original_claim::{OriginalClaims, Reservation, Route};

    for first in [Route::Root, Route::Debug] {
        let directory = tempfile::tempdir().unwrap();
        let (blobs, refs) = storage(directory.path());
        let claims = OriginalClaims::new(blobs.clone(), refs.clone()).unwrap();
        let original = request();
        let bytes = encode(&original).unwrap();
        assert_eq!(
            claims.reserve(&original.execution, first, &bytes).unwrap(),
            Reservation::Original
        );
        let original_roots = claims.retention_roots().unwrap();
        let other = if first == Route::Root {
            Route::Debug
        } else {
            Route::Root
        };

        assert!(claims.reserve(&original.execution, other, &bytes).is_err());
        assert_eq!(claims.retention_roots().unwrap(), original_roots);
        if first == Route::Debug {
            let root = ledger::RootPreparationLedger::new(blobs, refs).unwrap();
            assert!(root.reserve(&original).is_err());
            assert!(root.state(&original.execution).is_err());
        }
    }
}
