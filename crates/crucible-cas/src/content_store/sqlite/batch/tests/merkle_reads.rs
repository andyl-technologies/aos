//! Fixed-kind native Merkle reads retain current EOF and original custody.

use super::*;
use crate::content_store::{MAX_MERKLE_NODE_ENVELOPE_BYTES, MemoryBlobBackend};
use crucible_linux_resource::host_supervision::{
    HOST_OPERATION_CLASS_COUNT, HostOperationBudget, HostOperationBudgets, HostOperationClass,
    HostOperationState, HostOperationSupervisor, HostSupervisionError,
};
use std::time::Duration;

fn isolated(name: &str) -> bool {
    isolated_heap_test(&format!(
        "content_store::sqlite::batch::tests::merkle_reads::{name}"
    ))
}

// The real component GC has 256 MiB, not the older 64 MiB batch fixture. This
// separate owner uses that same finite envelope; no existing fixture is raised.
fn component_quota() -> Arc<Quota> {
    Arc::new(Quota(Arc::new(OriginalResources {
        used: AtomicU64::new(0),
        peak: AtomicU64::new(0),
        maximum: 256 << 20,
        revoked: AtomicBool::new(false),
        checks: AtomicUsize::new(0),
        starts: AtomicUsize::new(0),
        reservations: AtomicUsize::new(0),
        last_refused_bytes: AtomicU64::new(0),
        watched_loan_bytes: AtomicU64::new(0),
        watched_loan_closed: AtomicBool::new(false),
        resource_drops: AtomicUsize::new(0),
    })))
}

fn seed(backend: &SqliteBlobBackend, bytes: &[u8]) -> ContentId {
    let id = ContentId::for_bytes(ObjectKind::MerkleNode, 1, bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes))
        .expect("actual current row");
    id
}

#[test]
fn fixed_kind_refuses_before_sql_or_default_checked_dispatch() {
    if isolated("fixed_kind_refuses_before_sql_or_default_checked_dispatch") {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let quota = component_quota();
    let backend = bounded_leaf("merkle-kind", root.path(), &quota);
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let memory = MemoryBlobBackend::new("default", 1024);
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"wrong kind");
    let before = quota.0.reservations.load(Ordering::SeqCst);
    for backend in [&backend as &dyn ImmutableBlobBackend, &memory] {
        let mut calls = 0;
        let error = backend
            .read_merkle_node_with_boundary(&original, id, &mut || {
                calls += 1;
                Err(StoreError::Unauthorized)
            })
            .unwrap_err();
        assert!(matches!(error, StoreError::Corrupt { id: rejected } if rejected == id));
        assert_eq!(calls, 0, "wrong kind precedes every I/O boundary");
    }
    assert_eq!(quota.0.reservations.load(Ordering::SeqCst), before);
}

#[test]
fn complete_and_empty_native_outputs_keep_the_exact_original_until_bytes_close() {
    if isolated("complete_and_empty_native_outputs_keep_the_exact_original_until_bytes_close") {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let quota = component_quota();
    let backend = bounded_leaf("merkle-output", root.path(), &quota);
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let starts = quota.0.starts.load(Ordering::SeqCst);
    let baseline = quota.0.used.load(Ordering::SeqCst);
    for bytes in [Vec::new(), vec![37; MAX_MERKLE_NODE_ENVELOPE_BYTES]] {
        let id = seed(&backend, &bytes);
        let output = backend
            .read_merkle_node_with_boundary(&original, id, &mut || Ok(()))
            .unwrap();
        assert_eq!(&*output, bytes);
        assert!(output.original_account().same_account(&original));
        assert_eq!(
            quota.0.used.load(Ordering::SeqCst),
            baseline
                + bytes.len() as u64
                + std::mem::size_of::<crate::content_store::OwnedBlobBytes>() as u64
        );
        drop(output);
        assert_eq!(quota.0.used.load(Ordering::SeqCst), baseline);
    }
    // Seeding used the ordinary write supervisor; the checked reader did not.
    let oversized = vec![38; MAX_MERKLE_NODE_ENVELOPE_BYTES + 1];
    let id = seed(&backend, &oversized);
    let before_read = quota.0.starts.load(Ordering::SeqCst);
    let error = backend
        .read_merkle_node_with_boundary(&original, id, &mut || Ok(()))
        .unwrap_err();
    assert!(matches!(original_failure(&error), StoreError::Quota));
    drop(error);
    assert_eq!(quota.0.starts.load(Ordering::SeqCst), before_read);
    assert!(before_read >= starts);
    assert_eq!(quota.0.used.load(Ordering::SeqCst), baseline);
    assert!(quota.0.peak.load(Ordering::SeqCst) <= 256 << 20);
}

// Count the actual native primitive's callbacks. In this isolated, uncontended
// fixture four preceding checks admit the original, staging gate and lock. Its
// final native callback therefore supplies the actual closed-cursor mutation
// cut, without a production hook or replacing any I/O operation.
fn closed_native_cut(backend: &SqliteBlobBackend, original: &DecodeBudget, id: ContentId) -> usize {
    let connection = backend.read_connection.lock().unwrap();
    let _diagnostic = super::super::diagnostic::admit_for_single_record_query(
        original,
        &backend.connection,
        busy::single_record::METADATA.len(),
    )
    .unwrap();
    let mut calls = 0;
    let mut output_credit = None;
    let accepted = busy::single_record::consume_merkle(
        original,
        &connection,
        &backend.quarantined,
        &mut || {
            calls += 1;
            Ok(())
        },
        id,
        |length| {
            output_credit = Some(
                original
                    .reserve_scratch_bytes(length + std::mem::size_of::<Vec<u8>>() as u64)
                    .unwrap(),
            );
            Ok(Vec::with_capacity(length as usize))
        },
    )
    .unwrap();
    let bytes = accepted.finish(Ok).unwrap().unwrap();
    assert!(id.authenticates(&bytes));
    assert!(connection.is_autocommit());
    assert!(calls > 4);
    drop(bytes);
    drop(output_credit);
    calls + 4
}

#[test]
fn fresh_eof_rejects_foreign_growth_delete_null_and_type_after_native_body_closes() {
    if isolated("fresh_eof_rejects_foreign_growth_delete_null_and_type_after_native_body_closes") {
        return;
    }
    for (bytes, change) in [
        (b"body".as_slice(), "grow"),
        (b"body".as_slice(), "delete"),
        (b"body".as_slice(), "null"),
        (b"body".as_slice(), "text"),
        (b"".as_slice(), "grow"),
        (b"".as_slice(), "delete"),
        (b"".as_slice(), "text"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let quota = component_quota();
        let backend = bounded_leaf("merkle-current-eof", root.path(), &quota);
        backend
            .lock_connection()
            .unwrap()
            .execute_batch("PRAGMA journal_mode=WAL")
            .unwrap();
        let id = seed(&backend, bytes);
        let original = DecodeBudget::for_store(quota.clone()).unwrap();
        let cut = closed_native_cut(&backend, &original, id);
        let foreign = fixture_sqlite_connection(root.path().join(DATABASE_FILE)).unwrap();
        let baseline = quota.0.used.load(Ordering::SeqCst);
        let mut seen = 0;
        let mut mutated = false;
        let error = backend
            .read_merkle_node_with_boundary(&original, id, &mut || {
                seen += 1;
                if seen == cut {
                    match change {
                        "grow" => {
                            let mut grown = bytes.to_vec();
                            grown.push(255);
                            foreign
                                .execute(
                                    "UPDATE objects SET body=?1 WHERE id=?2",
                                    params![grown, id.encode()],
                                )
                                .unwrap();
                        }
                        "delete" => {
                            foreign
                                .execute("DELETE FROM objects WHERE id=?1", [id.encode()])
                                .unwrap();
                        }
                        "null" => {
                            // The shipped schema refuses NULL. Corrupt only this
                            // closed fixture's table, preserving the same real ID.
                            foreign
                                .execute_batch(
                                    "ALTER TABLE objects RENAME TO original_objects;
                                 CREATE TABLE objects (id TEXT PRIMARY KEY, body BLOB);
                                 INSERT INTO objects SELECT id, NULL FROM original_objects;
                                 DROP TABLE original_objects;",
                                )
                                .unwrap();
                        }
                        "text" => {
                            foreign
                                .execute(
                                    "UPDATE objects SET body=?1 WHERE id=?2",
                                    params!["t".repeat(bytes.len()), id.encode()],
                                )
                                .unwrap();
                        }
                        _ => unreachable!(),
                    }
                    mutated = true;
                }
                Ok(())
            })
            .unwrap_err();
        assert!(mutated, "the actual post-native-close cut was reached");
        if change == "text" {
            let StoreError::StreamIo { source, .. } = original_failure(&error) else {
                panic!("lost native type cause: {error:?}");
            };
            assert!(matches!(
                source
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<rusqlite::Error>()),
                Some(rusqlite::Error::InvalidColumnType(..))
            ));
        } else {
            assert!(
                matches!(original_failure(&error), StoreError::Corrupt { id: rejected } if *rejected == id),
                "{change}: {error:?}"
            );
        }
        drop(error);
        assert_eq!(quota.0.used.load(Ordering::SeqCst), baseline);
        assert!(backend.read_connection.lock().unwrap().is_autocommit());
        assert!(!backend.quarantined.load(Ordering::SeqCst));
    }
}

#[test]
fn every_native_and_fresh_eof_cut_retains_exact_original_cancellation() {
    if isolated("every_native_and_fresh_eof_cut_retains_exact_original_cancellation") {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let quota = component_quota();
    let backend = bounded_leaf("merkle-cancel", root.path(), &quota);
    let id = seed(&backend, b"whole native node");
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let mut total = 0;
    drop(
        backend
            .read_merkle_node_with_boundary(&original, id, &mut || {
                total += 1;
                Ok(())
            })
            .unwrap(),
    );
    assert!(total > closed_native_cut(&backend, &original, id));
    let baseline = quota.0.used.load(Ordering::SeqCst);
    let starts = quota.0.starts.load(Ordering::SeqCst);
    for cut in 1..=total {
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets {
                classes: [HostOperationBudget::finite(Duration::from_secs(300));
                    HOST_OPERATION_CLASS_COUNT],
            },
            Some(Duration::from_secs(300)),
        )
        .unwrap();
        let operation = supervisor.begin(HostOperationClass::Transfer).unwrap();
        let mut seen = 0;
        let error = backend
            .read_merkle_node_with_boundary(&original, id, &mut || {
                seen += 1;
                if seen == cut {
                    supervisor.cancel().unwrap();
                }
                operation
                    .wait_slice()
                    .map(|_| ())
                    .map_err(|source| StoreError::Supervision {
                        source: Box::new(source),
                    })
            })
            .unwrap_err();
        assert_eq!(seen, cut, "no later poll replaces the first cut");
        let StoreError::Supervision { source } = original_failure(&error) else {
            panic!("lost typed cut {cut}: {error:?}");
        };
        assert!(matches!(
            source.downcast_ref::<HostSupervisionError>(),
            Some(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled
            })
        ));
        drop(error);
        assert_eq!(quota.0.used.load(Ordering::SeqCst), baseline);
        assert!(!backend.quarantined.load(Ordering::SeqCst));
    }
    assert_eq!(
        quota.0.starts.load(Ordering::SeqCst),
        starts,
        "no new Read operation"
    );
}

#[test]
fn current_row_corruption_and_absence_never_reuse_an_earlier_authenticated_read() {
    if isolated("current_row_corruption_and_absence_never_reuse_an_earlier_authenticated_read") {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let quota = component_quota();
    let backend = bounded_leaf("merkle-current", root.path(), &quota);
    let id = seed(&backend, b"good");
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    drop(
        backend
            .read_merkle_node_with_boundary(&original, id, &mut || Ok(()))
            .unwrap(),
    );
    backend
        .lock_connection()
        .unwrap()
        .execute(
            "UPDATE objects SET body=?1 WHERE id=?2",
            params![b"evil".as_slice(), id.encode()],
        )
        .unwrap();
    let error = backend
        .read_merkle_node_with_boundary(&original, id, &mut || Ok(()))
        .unwrap_err();
    assert!(
        matches!(original_failure(&error), StoreError::Corrupt { id: rejected } if *rejected == id)
    );
    drop(error);
    backend
        .lock_connection()
        .unwrap()
        .execute("DELETE FROM objects WHERE id=?1", [id.encode()])
        .unwrap();
    let error = backend
        .read_merkle_node_with_boundary(&original, id, &mut || Ok(()))
        .unwrap_err();
    assert!(
        matches!(original_failure(&error), StoreError::NotFound { id: rejected } if *rejected == id)
    );
}

#[test]
fn retained_native_errors_keep_the_actual_diagnostic_bank_until_their_last_owner() {
    if isolated("retained_native_errors_keep_the_actual_diagnostic_bank_until_their_last_owner") {
        return;
    }
    for keep_first in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let quota = component_quota();
        let backend = bounded_leaf("merkle-error-credit", root.path(), &quota);
        let original = DecodeBudget::for_store(quota.clone()).unwrap();
        let bytes = b"authenticated original";
        let id = seed(&backend, bytes);
        backend
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE objects SET body = zeroblob(length(body)) WHERE id = ?1",
                [id.encode()],
            )
            .unwrap();
        let baseline = quota.0.used.load(Ordering::SeqCst);
        let first = backend
            .read_merkle_node_with_boundary(&original, id, &mut || Ok(()))
            .unwrap_err();
        assert!(
            matches!(original_failure(&first), StoreError::Corrupt { id: found } if *found == id)
        );
        let retained = quota.0.used.load(Ordering::SeqCst) - baseline;
        assert!(retained > (256 << 20) / 2);
        let first = keep_first.then_some(first);
        let reservations = quota.0.reservations.load(Ordering::SeqCst);
        let second = backend
            .read_merkle_node_with_boundary(&original, id, &mut || Ok(()))
            .unwrap_err();
        if keep_first {
            let StoreError::DecodeAdmission { source, .. } = original_failure(&second) else {
                panic!("the same finite decoded account must refuse the overlapping bank");
            };
            assert_eq!(*source, original.failure().unwrap().unwrap());
            // The decoded allowance refuses before asking the physical guard
            // for another bank. It neither grants more credit nor replaces H.
            assert_eq!(quota.0.last_refused_bytes.load(Ordering::SeqCst), 0);
            assert_eq!(quota.0.reservations.load(Ordering::SeqCst), reservations);
            assert_eq!(quota.0.used.load(Ordering::SeqCst), baseline + retained);
        } else {
            assert!(
                matches!(original_failure(&second), StoreError::Corrupt { id: found } if *found == id)
            );
            assert_eq!(quota.0.used.load(Ordering::SeqCst), baseline + retained);
        }
        eprintln!(
            "actual native diagnostic custody keep_first={keep_first} retained={retained} refused={}",
            quota.0.last_refused_bytes.load(Ordering::SeqCst)
        );
        drop(second);
        drop(first);
        assert_eq!(quota.0.used.load(Ordering::SeqCst), baseline);
    }
}
