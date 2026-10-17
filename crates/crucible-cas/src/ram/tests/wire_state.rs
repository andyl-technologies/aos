//! Persistent source refusal, unwind disposition and unchanged wire witnesses.

use super::*;
use crucible_protocol::ram_transfer::{
    RamTransferControl, RamTransferMessage, RamTransferNodeCoordinate,
};

fn sender(
    source: &RamStore,
    root: &LeasedRamRoot,
    original: &crate::owned_decode::DecodeBudget,
) -> RamTransferSender {
    let offer = archive_offer(root, 64);
    RamTransferSender::new(
        source.clone(),
        root.clone(),
        [31; 32],
        ContentId::parse(&offer.whole_world_root).unwrap(),
        &offer.destination,
        offer.durable_placements,
        offer.limits,
        original,
    )
    .unwrap()
}

fn want(root: &LeasedRamRoot) -> RamTransferMessage {
    RamTransferMessage {
        operation: [31; 32],
        control: RamTransferControl::WantNode {
            coordinate: RamTransferNodeCoordinate::Root,
            object: root.object_id().to_string(),
        },
    }
}

#[test]
fn sender_retry_retains_the_actual_callback_cause_without_polling_or_reading() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(128),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    let operation = original.child().unwrap();
    let mut sender = sender(&store, &root, &operation);

    let first = sender
        .respond(want(&root), &mut || Err(RamStoreError::Canceled))
        .err()
        .unwrap();
    let RamStoreError::Store(StoreError::RamReadBoundary { source: first }) = first else {
        panic!("the actual source callback owns its boundary category");
    };
    assert!(matches!(
        first.first_boundary(),
        Some(RamStoreError::Canceled)
    ));
    assert!(matches!(
        first.storage_failure(),
        RamStoreError::Store(StoreError::RamBoundary { .. })
    ));
    assert_eq!(
        (
            sender.state_for_test().0,
            sender.state_for_test().1,
            sender.state_for_test().2
        ),
        (0, 0, 0)
    );

    let retry = sender
        .respond(want(&root), &mut || {
            panic!("failed operation cannot poll again")
        })
        .err()
        .unwrap();
    let RamStoreError::Store(StoreError::RamReadBoundary { source: retry }) = retry else {
        panic!("retry must return the same retained first cause");
    };
    assert_eq!(first, retry);
    assert_eq!(
        (
            sender.state_for_test().0,
            sender.state_for_test().1,
            sender.state_for_test().2
        ),
        (0, 0, 0)
    );
    drop((sender, retry, first, operation));
    original.verify_live().unwrap();
}

#[test]
fn sender_unwind_never_reconstructs_operation_slots_or_canonical_path() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(128),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    let mut sender = sender(&store, &root, &original);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = sender.respond(want(&root), &mut || {
            panic!("intentional source turn unwind")
        });
    }));
    assert!(panicked.is_err());
    let (_, _, _, state, terminal, path_closed, active_closed) = sender.state_for_test();
    assert!(!state);
    assert!(terminal);
    assert!(path_closed);
    assert!(active_closed);
    assert!(
        sender
            .respond(want(&root), &mut || panic!("unwound operation cannot poll"))
            .is_err()
    );
    assert!(sender.offer().is_err());
    original.verify_live().unwrap();
}

#[test]
fn inline_terminal_frames_match_the_existing_portable_codec() {
    for control in [
        RamTransferControl::Cancel,
        RamTransferControl::Canceled,
        RamTransferControl::Fail { code: 37 },
    ] {
        let message = RamTransferMessage {
            operation: [63; 32],
            control,
        };
        let expected = message.encode().unwrap();
        let response = RamTransferResponse::inline(message);
        let directory = tempfile::tempdir().unwrap();
        let store = store(directory.path(), RamStoreLimits::default());
        let original = fixture_original(&store);
        response
            .with_encoded(&original, |actual| {
                assert_eq!(actual, expected);
                Ok(())
            })
            .unwrap();
        let mut written = Vec::new();
        response
            .write(&mut written, &original, &mut || Ok(()))
            .unwrap();
        assert_eq!(written, expected);
    }
}

#[test]
fn checked_entry_marker_retains_canceled_and_the_same_failed_operation() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let original = fixture_original(&store);
    let operation = original.child().unwrap();
    let mut account = super::super::store_boundary::WorkAccount::new(&operation).unwrap();
    let mut polls = 0;
    let first = account
        .checked(
            &mut || {
                polls += 1;
                Err(RamStoreError::Canceled)
            },
            |_, boundary| boundary(),
        )
        .unwrap_err();
    let RamStoreError::Store(StoreError::RamReadBoundary { source: first }) = first else {
        panic!("an actual checked callback refuses as a boundary, not validation");
    };
    assert!(matches!(
        first.first_boundary(),
        Some(RamStoreError::Canceled)
    ));
    assert!(matches!(
        first.storage_failure(),
        RamStoreError::Store(StoreError::RamBoundary { .. })
    ));
    assert_eq!(polls, 1);

    let retry = account
        .checked::<()>(
            &mut || panic!("sticky operation must not poll again"),
            |_, _| panic!("sticky operation must not enter another provider"),
        )
        .unwrap_err();
    let RamStoreError::Boundary(retry) = retry else {
        panic!("same Work returns its exact retained boundary carrier");
    };
    assert_eq!(first, retry);
    assert_eq!(polls, 1);
    drop(account);
    drop((retry, first, operation));
    original.verify_live().unwrap();
}

#[test]
fn canonical_boundary_closes_only_unused_direct_marker_diagnostics() {
    for refused_poll in [2, 9] {
        let directory = tempfile::tempdir().unwrap();
        let (store, quota) = admitted_store(directory.path(), RamStoreLimits::default());
        let original = fixture_original(&store);
        let root = store
            .capture(
                topology(128),
                Scope::Exact,
                &mut patterned,
                &Retention::default(),
                &original,
                &mut || Ok(()),
            )
            .unwrap();
        let operation = original.child().unwrap();
        let response = operation.child().unwrap();
        let polls = std::cell::Cell::new(0);
        let charged_at_refusal = std::cell::Cell::new(0);
        let mut boundary = || {
            polls.set(polls.get() + 1);
            if polls.get() == refused_poll {
                charged_at_refusal.set(quota.0.usage().unwrap().1);
                Err(RamStoreError::Canceled)
            } else {
                Ok(())
            }
        };
        let mut work = Work::new(store.limits, &operation, &mut boundary).unwrap();
        let baseline = quota.0.usage().unwrap().1;

        let error = super::super::bounded_read::read_canonical(
            store.backend.as_ref(),
            root.object_id(),
            &response,
            &mut work,
        )
        .unwrap_err();
        let RamStoreError::Store(StoreError::RamReadBoundary { source }) = &error else {
            panic!("actual SQL refusal keeps the original boundary: {error:?}");
        };
        assert!(matches!(
            source.first_boundary(),
            Some(RamStoreError::Canceled)
        ));
        assert_eq!(polls.get(), refused_poll);
        assert!(charged_at_refusal.get() >= baseline + 18 * (8 << 20));
        if refused_poll == 2 {
            assert!(matches!(
                source.storage_failure(),
                RamStoreError::Store(StoreError::RamBoundary { .. })
            ));
            assert_eq!(
                quota.0.usage().unwrap().1,
                baseline,
                "the unused native diagnostic loan closes while the marker remains live"
            );
        } else {
            let RamStoreError::Store(StoreError::SqliteDiagnostic { source: diagnostic }) =
                source.storage_failure()
            else {
                panic!("a nested native scope keeps its full diagnostic owner: {source:?}");
            };
            let StoreError::SqliteScope { source: scope } = diagnostic.failure() else {
                panic!("the actual read scope must not be flattened");
            };
            assert!(matches!(
                scope.work_failure(),
                Some(StoreError::RamBoundary { .. })
            ));
            assert_eq!(
                scope.outcome(),
                crate::content_store::SqliteCommitOutcome::NotCommitted
            );
            assert!(scope.rollback_failure().is_none());
            assert!(scope.restoration_failure().is_none());
            assert!(scope.blob_close_failure().is_none());
            assert!(scope.metadata_completion_failure().is_none());
            assert!(scope.metadata_finalization_failure().is_none());
            assert!(quota.0.usage().unwrap().1 >= baseline + 18 * (8 << 20));
        }

        let retry = super::super::bounded_read::read_canonical(
            store.backend.as_ref(),
            root.object_id(),
            &response,
            &mut work,
        )
        .unwrap_err();
        let RamStoreError::Store(StoreError::RamReadBoundary { source: retry_cause }) = &retry else {
            panic!("sticky retry retains the same owning first cause");
        };
        assert_eq!(source, retry_cause);
        assert_eq!(polls.get(), refused_poll);
        drop(work);
        drop((retry, error, response, operation));
        original.verify_live().unwrap();
    }
}
