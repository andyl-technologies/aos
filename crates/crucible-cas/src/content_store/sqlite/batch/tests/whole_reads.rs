//! Concrete whole-read borrowing, current rows and retained original controls.

use super::*;
use crucible_linux_resource::host_supervision::{
    HOST_OPERATION_CLASS_COUNT, HostOperationBudget, HostOperationBudgets, HostOperationClass,
    HostOperationState, HostOperationSupervisor, HostSupervisionError,
};
use std::time::Duration;

fn isolated(name: &str) -> bool {
    isolated_heap_test(&format!(
        "content_store::sqlite::batch::tests::whole_reads::{name}"
    ))
}

#[test]
fn whole_read_rejects_a_held_sources_grown_row_instead_of_authenticating_its_prefix() {
    if isolated("whole_read_rejects_a_held_sources_grown_row_instead_of_authenticating_its_prefix")
    {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let quota = original_quota();
    let backend = bounded_leaf("whole-current-row", root.path(), &quota);
    let bytes = b"complete body";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .expect("seed original body");
    let original = DecodeBudget::for_store(quota).expect("original account");
    let _scope = original.enter();
    let source = backend
        .read_with_boundary(&original, id, None, &mut || Ok(()))
        .expect("old admitted metadata");
    let mut grown = bytes.to_vec();
    grown.push(0xff);
    backend
        .lock_connection()
        .expect("actual current row")
        .execute(
            "UPDATE objects SET body = ?1 WHERE id = ?2",
            params![grown, id.encode()],
        )
        .expect("append beyond the source's old declared length");

    let error = source
        .read_all_with_boundary(&original, 1024, &mut || Ok(()))
        .expect_err("the complete current row must authenticate");
    assert!(
        matches!(original_failure(&error), StoreError::Corrupt { id: observed } if *observed == id)
    );
}

#[test]
fn whole_range_authenticates_hidden_bytes_and_preserves_streaming_open() {
    if isolated("whole_range_authenticates_hidden_bytes_and_preserves_streaming_open") {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let quota = original_quota();
    let backend = bounded_leaf("whole-range", root.path(), &quota);
    let mut bytes = vec![0x5a; 128 * 1024 + 7];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.clone()))
        .expect("seed");
    let original = DecodeBudget::for_store(quota.clone()).expect("original account");
    let _scope = original.enter();
    let source = backend
        .read_with_boundary(
            &original,
            id,
            Some(ByteRange {
                offset: 64 * 1024,
                length: 11,
            }),
            &mut || Ok(()),
        )
        .expect("held range");
    assert_eq!(
        source.source.checked_read_access(),
        crate::content_store::CheckedReadAccess::Whole
    );
    let starts = quota.0.starts.load(Ordering::SeqCst);
    let output = source
        .read_all_with_boundary(&original, 11, &mut || Ok(()))
        .expect("complete checked range");
    assert_eq!(&*output, &[0x5a; 11]);
    drop(output);

    let mut reader = source
        .open_with_boundary(&mut || Ok(()))
        .expect("owning stream remains available");
    let mut output = [0_u8; 11];
    assert_eq!(
        reader
            .read_with_boundary(&mut output, &mut || Ok(()))
            .expect("streamed range"),
        11
    );
    assert_eq!(output, [0x5a; 11]);
    assert_eq!(
        reader
            .read_with_boundary(&mut [0_u8; 1], &mut || Ok(()))
            .expect("authenticated stream EOF"),
        0
    );
    drop(reader);
    assert_eq!(
        quota.0.starts.load(Ordering::SeqCst),
        starts,
        "no new read supervision"
    );

    *bytes.last_mut().expect("suffix") = 0x5b;
    backend
        .lock_connection()
        .expect("actual mutation")
        .execute(
            "UPDATE objects SET body = ?1 WHERE id = ?2",
            params![bytes, id.encode()],
        )
        .expect("mutate hidden suffix");
    let error = source
        .read_all_with_boundary(&original, 11, &mut || Ok(()))
        .expect_err("hidden suffix must authenticate");
    assert!(
        matches!(original_failure(&error), StoreError::Corrupt { id: observed } if *observed == id)
    );
}

#[test]
fn every_whole_read_callback_retains_actual_original_cancellation() {
    if isolated("every_whole_read_callback_retains_actual_original_cancellation") {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let quota = original_quota();
    let backend = bounded_leaf("whole-original-cuts", root.path(), &quota);
    let bytes = vec![0x19; 64 * 1024 + 3];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.clone()))
        .expect("seed");
    let original = DecodeBudget::for_store(quota.clone()).expect("original account");
    let _scope = original.enter();
    let source = backend
        .read_with_boundary(&original, id, None, &mut || Ok(()))
        .expect("metadata");
    let mut total = 0;
    let output = source
        .read_all_with_boundary(&original, bytes.len() as u64, &mut || {
            total += 1;
            Ok(())
        })
        .expect("count actual whole-read cuts");
    assert_eq!(&*output, bytes);
    drop(output);
    assert!(total > 8, "SQL/body/EOF checks were actually exercised");
    let baseline = quota.0.used.load(Ordering::SeqCst);

    for cut in 1..=total {
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets {
                classes: [HostOperationBudget::finite(Duration::from_secs(300));
                    HOST_OPERATION_CLASS_COUNT],
            },
            Some(Duration::from_secs(300)),
        )
        .expect("one finite original operation");
        let operation = supervisor
            .begin(HostOperationClass::Transfer)
            .expect("original start");
        let mut seen = 0;
        let error = source
            .read_all_with_boundary(&original, bytes.len() as u64, &mut || {
                seen += 1;
                if seen == cut {
                    supervisor.cancel().expect("cancel the same original");
                }
                operation
                    .wait_slice()
                    .map(|_| ())
                    .map_err(|source| StoreError::Supervision {
                        source: Box::new(source),
                    })
            })
            .expect_err("every actual cut must retain the original refusal");
        assert_eq!(seen, cut);
        let StoreError::Supervision { source } = original_failure(&error) else {
            panic!("lost original typed cancellation at cut {cut}");
        };
        assert!(matches!(
            source.downcast_ref::<HostSupervisionError>(),
            Some(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled
            })
        ));
        drop(error);
        assert_eq!(
            quota.0.used.load(Ordering::SeqCst),
            baseline,
            "all per-read loans close at cut {cut}"
        );
    }
}

#[test]
fn whole_output_retains_its_source_account_after_independent_caller_and_source_close() {
    if isolated("whole_output_retains_its_source_account_after_independent_caller_and_source_close")
    {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let quota = original_quota();
    let backend = bounded_leaf("whole-external-credit", root.path(), &quota);
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"owned output");
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(b"owned output".to_vec()))
        .expect("seed");
    let original = DecodeBudget::for_store(quota.clone()).expect("source account");
    let source = backend
        .read_with_boundary(&original, id, None, &mut || Ok(()))
        .expect("held source");
    let caller_quota = original_quota();
    let caller = DecodeBudget::for_store(caller_quota.clone()).expect("independent caller account");
    let output = source
        .read_all_with_boundary(&caller, 1024, &mut || Ok(()))
        .expect("both original accounts remain live");
    assert!(output.original_account().same_account(&original));
    assert!(!output.original_account().same_account(&caller));
    drop(caller);
    drop(source);
    drop(backend);
    drop(original);
    assert_eq!(caller_quota.0.used.load(Ordering::SeqCst), 0);
    assert!(
        quota.0.used.load(Ordering::SeqCst) > 0,
        "output holds its actual original credit"
    );
    assert_eq!(&*output, b"owned output");
    drop(output);
    assert_eq!(quota.0.used.load(Ordering::SeqCst), 0);
}

#[test]
fn whole_read_rejects_an_empty_held_source_after_its_row_grows() {
    if isolated("whole_read_rejects_an_empty_held_source_after_its_row_grows") {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let quota = original_quota();
    let backend = bounded_leaf("whole-empty-current-row", root.path(), &quota);
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"");
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(Vec::new()))
        .expect("empty row");
    let original = DecodeBudget::for_store(quota).expect("original account");
    let _scope = original.enter();
    let source = backend
        .read_with_boundary(&original, id, None, &mut || Ok(()))
        .expect("empty metadata");
    backend
        .lock_connection()
        .expect("current row")
        .execute(
            "UPDATE objects SET body = ?1 WHERE id = ?2",
            params![b"appended".as_slice(), id.encode()],
        )
        .expect("append to held empty row");

    let error = source
        .read_all_with_boundary(&original, 0, &mut || Ok(()))
        .expect_err("empty cached metadata does not authenticate new bytes");
    assert!(
        matches!(original_failure(&error), StoreError::Corrupt { id: observed } if *observed == id)
    );
}

#[test]
fn whole_read_rejects_an_empty_held_source_after_its_row_is_removed() {
    if isolated("whole_read_rejects_an_empty_held_source_after_its_row_is_removed") {
        return;
    }
    let root = tempfile::tempdir().expect("catalog");
    let quota = original_quota();
    let backend = bounded_leaf("whole-empty-missing-row", root.path(), &quota);
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"");
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(Vec::new()))
        .expect("empty row");
    let original = DecodeBudget::for_store(quota).expect("original account");
    let _scope = original.enter();
    let source = backend
        .read_with_boundary(&original, id, None, &mut || Ok(()))
        .expect("empty metadata");
    backend
        .lock_connection()
        .expect("current row")
        .execute("DELETE FROM objects WHERE id = ?1", [id.encode()])
        .expect("remove held row");

    let error = source
        .read_all_with_boundary(&original, 0, &mut || Ok(()))
        .expect_err("old empty digest does not prove current row possession");
    assert!(
        matches!(original_failure(&error), StoreError::Corrupt { id: observed } if *observed == id)
    );
}

#[test]
fn owning_reader_revalidates_current_row_after_its_last_body_chunk() {
    if isolated("owning_reader_revalidates_current_row_after_its_last_body_chunk") {
        return;
    }

    for remove in [false, true] {
        let root = tempfile::tempdir().expect("catalog");
        let quota = original_quota();
        let backend = bounded_leaf("whole-terminal-current-row", root.path(), &quota);
        let bytes = b"last body";
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .expect("seed");
        let original = DecodeBudget::for_store(quota).expect("original account");
        let _scope = original.enter();
        let source = backend
            .read_with_boundary(&original, id, None, &mut || Ok(()))
            .expect("held source");
        let mut reader = source
            .open_with_boundary(&mut || Ok(()))
            .expect("same owning reader");
        let mut output = [0_u8; 9];
        assert_eq!(
            reader
                .read_with_boundary(&mut output, &mut || Ok(()))
                .expect("original full body"),
            bytes.len()
        );
        assert_eq!(&output, bytes);

        let connection = backend.lock_connection().expect("current row");
        if remove {
            connection
                .execute("DELETE FROM objects WHERE id = ?1", [id.encode()])
                .expect("remove after last body chunk");
        } else {
            let mut grown = bytes.to_vec();
            grown.push(0xff);
            connection
                .execute(
                    "UPDATE objects SET body = ?1 WHERE id = ?2",
                    params![grown, id.encode()],
                )
                .expect("append after last body chunk");
        }
        drop(connection);

        let error = reader
            .read_with_boundary(&mut [0_u8; 1], &mut || Ok(()))
            .expect_err("the digest of earlier bytes cannot prove current row possession");
        assert!(
            matches!(original_failure(&error), StoreError::Corrupt { id: observed } if *observed == id)
        );
    }
}

#[test]
fn empty_blob_projection_authenticates_a_present_row_without_erasing_native_type_errors() {
    if isolated(
        "empty_blob_projection_authenticates_a_present_row_without_erasing_native_type_errors",
    ) {
        return;
    }

    let root = tempfile::tempdir().expect("catalog");
    let quota = original_quota();
    let backend = bounded_leaf("whole-empty-live-row", root.path(), &quota);
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"");
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(b""))
        .expect("seed genuine empty BLOB");
    let original = DecodeBudget::for_store(quota).expect("original account");
    let _scope = original.enter();
    let source = backend
        .read_with_boundary(&original, id, None, &mut || Ok(()))
        .expect("empty metadata");
    let types: (String, String, i64) = backend
        .lock_connection()
        .expect("same actual connection")
        .query_row(
            "SELECT typeof(body), typeof(substr(body, 1, 0)), length(body) FROM objects WHERE id = ?1",
            [id.encode()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("actual SQLite empty projection semantics");
    assert_eq!(types, ("blob".to_owned(), "null".to_owned(), 0));
    let output = source
        .read_all_with_boundary(&original, 0, &mut || Ok(()))
        .expect("unchanged empty row authenticates");
    assert!(output.is_empty());
    drop(output);

    backend
        .lock_connection()
        .expect("actual column type mutation")
        .execute("UPDATE objects SET body = '' WHERE id = ?1", [id.encode()])
        .expect("replace BLOB by same-length TEXT");
    let error = source
        .read_all_with_boundary(&original, 0, &mut || Ok(()))
        .expect_err("non-BLOB column still retains its native type error");
    let StoreError::StreamIo { source: native, .. } = original_failure(&error) else {
        panic!("lost native column type: {error:?}");
    };
    assert!(matches!(
        native
            .get_ref()
            .and_then(|source| source.downcast_ref::<rusqlite::Error>()),
        Some(rusqlite::Error::InvalidColumnType(
            _,
            _,
            rusqlite::types::Type::Text
        ))
    ));
    drop(error);

    // The normal schema forbids NULL bodies. Replace only this fixture's
    // table to exercise a genuinely corrupt nullable row at the held EOF.
    backend
        .lock_connection()
        .expect("actual schema corruption")
        .execute_batch(
            "ALTER TABLE objects RENAME TO original_objects;
             CREATE TABLE objects (id TEXT PRIMARY KEY, body BLOB);
             INSERT INTO objects SELECT id, NULL FROM original_objects;
             DROP TABLE original_objects;",
        )
        .expect("retain the ID but corrupt its body to SQL NULL");
    let error = source
        .read_all_with_boundary(&original, 0, &mut || Ok(()))
        .expect_err("NULL body must not match the saved zero length");
    assert!(
        matches!(original_failure(&error), StoreError::Corrupt { id: observed } if *observed == id)
    );
}
