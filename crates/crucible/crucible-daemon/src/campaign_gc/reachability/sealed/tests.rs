//! Real sealed files, same-original credit and separate mutable-source controls.
//!
//! These fixtures qualify requested credit and actual file operations. They do
//! not certify native allocator/kernel overhead, deployed quota or wall speed.
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::*;
use crate::campaign_gc::reachability::batched_tests::{available_resident_bytes, counted, page};
use crate::campaign_gc::reachability::sorted_runs::SortOwner;
use crate::campaign_gc::tests::operation::ComponentGcOperation;

fn entries(count: usize) -> Vec<MarkEntry> {
    let mut entries: Vec<_> = (0..count as u64)
        .map(|ordinal| (mark_key(page(ordinal)), page(ordinal)))
        .collect();
    entries.sort_unstable_by_key(|entry| entry.0);
    entries
}

fn refused(result: Result<SealedMarks, StoreError>) -> StoreError {
    match result {
        Ok(_) => panic!("invalid input unexpectedly constructed sealed marks"),
        Err(error) => error,
    }
}

fn has_store_cause(error: &(dyn Error + 'static), matches: fn(&StoreError) -> bool) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.downcast_ref::<StoreError>().is_some_and(matches) {
            return true;
        }
        current = error.source();
    }
    false
}

#[test]
fn actual_seals_bind_length_readback_and_presence_without_writable_aliases() {
    for count in [0, 1, 65, 257] {
        let mut fixture = ComponentGcOperation::new();
        let operation = fixture.context();
        let close = ClosePurpose::<StoreError>::new(&operation).expect("prepaid final close");
        let input = entries(count);
        let marks =
            SealedMarks::from_entries(count as u64, input.iter().copied().map(Ok), &operation)
                .expect("authenticated complete copy");
        let file = marks.file.as_ref().expect("private sealed descriptor");

        assert_eq!(
            file.metadata().expect("actual length").len(),
            count as u64 * RECORD_BYTES as u64
        );
        assert!(
            fcntl_get_seals(file)
                .expect("real installed seals")
                .contains(required_seals())
        );
        assert_eq!(
            file.write_at(b"tamper", 0)
                .expect_err("write seal")
                .raw_os_error(),
            Some(1)
        );
        assert_eq!(
            file.set_len(marks.bytes + 1)
                .expect_err("grow seal")
                .raw_os_error(),
            Some(1)
        );
        if count != 0 {
            assert_eq!(
                file.set_len(0).expect_err("shrink seal").raw_os_error(),
                Some(1)
            );
        }
        for (_, id) in input {
            assert!(
                marks
                    .contains(id, operation.original(), &mut || operation.check())
                    .expect("present typed id")
            );
        }
        assert!(
            !marks
                .contains(page(10000), operation.original(), &mut || operation.check())
                .expect("absent id")
        );
        marks
            .finish(close, Ok(()), &operation, |error| error)
            .expect("real descriptor close");
    }
}

#[test]
fn wrong_count_order_duplicate_and_typed_key_refuse_before_publication() {
    let mut fixture = ComponentGcOperation::new();
    let resources = fixture.resources();
    let operation = fixture.context();
    let input = entries(3);
    let before = available_resident_bytes(resources.as_ref());
    for (count, values) in [
        (4, input.clone()),
        (2, input.clone()),
        (3, vec![input[1], input[0], input[2]]),
        (2, vec![input[0], input[0]]),
        (1, vec![(input[0].0, input[1].1)]),
    ] {
        let error = refused(SealedMarks::from_entries(
            count,
            values.into_iter().map(Ok),
            &operation,
        ));
        assert!(matches!(error, StoreError::InvalidComposition { .. }));
        assert_eq!(available_resident_bytes(resources.as_ref()), before);
        operation
            .check()
            .expect("a structural refusal does not renew or cancel the original");
    }
}

#[test]
fn actual_fallible_tail_wins_over_later_original_refusal() {
    let mut fixture = ComponentGcOperation::new();
    let source = fixture.context();
    let refuse_original = AtomicBool::new(false);
    let mut boundary = || {
        if refuse_original.load(Ordering::Relaxed) {
            Err(StoreError::Unsupported {
                capability: "late-copy-original-refusal",
            })
        } else {
            source.check()
        }
    };
    let operation =
        CampaignGcOperationContext::new(source.marks(), source.original(), &mut boundary)
            .expect("same original boundary");
    let mut ordinal = 0;
    let input = std::iter::from_fn(|| {
        ordinal += 1;
        match ordinal {
            1 => Some(Ok((mark_key(page(0)), page(0)))),
            2 => {
                refuse_original.store(true, Ordering::Relaxed);
                Some(Err(StoreError::Unsupported {
                    capability: "authentic-copy-tail-refusal",
                }))
            }
            _ => None,
        }
    });
    let error = refused(SealedMarks::from_entries(1, input, &operation));
    assert!(matches!(
        error,
        StoreError::Unsupported {
            capability: "authentic-copy-tail-refusal"
        }
    ));
}

#[test]
fn full_backing_denial_precedes_input_and_file_creation() {
    let mut fixture = ComponentGcOperation::new();
    let resources = fixture.resources();
    let operation = fixture.context();
    let available = available_resident_bytes(resources.as_ref());
    let hold = operation
        .reserve_bytes(available - 16 * 1024)
        .expect("hold this same bank");
    let visited = AtomicBool::new(false);
    let input = std::iter::once_with(|| {
        visited.store(true, Ordering::Relaxed);
        Ok((mark_key(page(0)), page(0)))
    });
    let error = refused(SealedMarks::from_entries(4096, input, &operation));
    assert!(matches!(error, StoreError::Quota));
    assert!(!visited.load(Ordering::Relaxed));
    drop(hold);
    assert_eq!(available_resident_bytes(resources.as_ref()), available);
}

#[test]
fn sealed_production_copy_survives_late_source_deletion_without_sql_lookup() {
    let mut fixture = ComponentGcOperation::new();
    let path = fixture.scratch_path().join("objects.sqlite3");
    let source = fixture.context();
    let backend = counted(source.marks());
    let mut boundary = || source.check();
    let operation =
        CampaignGcOperationContext::new(backend.clone(), source.original(), &mut boundary)
            .expect("same accounted SQL namespace");
    let close = ClosePurpose::<StoreError>::new(&operation).expect("prepaid final close");
    let mut marks = Reachability::with_operation(&operation).expect("mark owner");
    let mut sorter = SortOwner::new(&operation).expect("bounded sorter");
    for ordinal in (0..257).rev() {
        sorter
            .insert(page(ordinal))
            .expect("authenticated mark entry");
    }
    sorter
        .finish_sealed(&mut marks)
        .expect("complete authenticated source and seals");
    let reads = backend.reads.load(Ordering::Relaxed);
    let connection = crucible_store::content_store::fixture_sqlite_heap()
        .expect("same actual fixture SQLite heap")
        .open_connection(&path, rusqlite::OpenFlags::default())
        .expect("independent source writer");
    assert!(
        connection
            .execute("DELETE FROM objects", [])
            .expect("actual late source mutation")
            > 0
    );

    assert_eq!(marks.len(), 257);
    for ordinal in 0..257 {
        assert!(
            marks
                .contains_with_boundary(&page(ordinal), &mut || operation.check())
                .expect("separate immutable copy")
        );
    }
    assert!(
        !marks
            .contains_with_boundary(&page(10000), &mut || operation.check())
            .expect("immutable absence")
    );
    assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
    marks
        .finish(close, Ok(()), &operation, |error| error)
        .expect("explicit native close");
}

#[test]
fn cancellation_precedes_search_and_clean_close_refunds_actual_credit() {
    let mut fixture = ComponentGcOperation::new();
    let resources = fixture.resources();
    let operation = fixture.context();
    let before = available_resident_bytes(resources.as_ref());
    let close = ClosePurpose::<StoreError>::new(&operation).expect("prepaid close");
    let marks = SealedMarks::from_entries(1, [Ok((mark_key(page(0)), page(0)))], &operation)
        .expect("actual sealed marks");
    let calls = AtomicUsize::new(0);
    let error = marks
        .contains(page(0), operation.original(), &mut || {
            calls.fetch_add(1, Ordering::Relaxed);
            Err(StoreError::Unsupported {
                capability: "actual-search-cancellation",
            })
        })
        .expect_err("saved boundary refuses before read");
    assert!(matches!(
        error,
        StoreError::Unsupported {
            capability: "actual-search-cancellation"
        }
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let error = marks
        .finish(close, Err::<(), _>(error), &operation, |error| error)
        .expect_err("initiating cause survives close");
    assert!(matches!(
        error,
        StoreError::Unsupported {
            capability: "actual-search-cancellation"
        }
    ));
    assert_eq!(available_resident_bytes(resources.as_ref()), before);
}

#[test]
fn reported_native_close_failure_keeps_first_cause_and_quarantines_credit() {
    let mut fixture = ComponentGcOperation::new();
    let resources = fixture.resources();
    let operation = fixture.context();
    let before = available_resident_bytes(resources.as_ref());
    let close = ClosePurpose::<StoreError>::new(&operation).expect("prepaid exact failure frame");
    let marks = SealedMarks::from_entries(1, [Ok((mark_key(page(0)), page(0)))], &operation)
        .expect("actual sealed marks");
    let held = available_resident_bytes(resources.as_ref());
    let error = marks
        .finish_with(
            close,
            Err::<(), _>(StoreError::Unsupported {
                capability: "initiating-mark-work-refusal",
            }),
            &operation,
            |error| error,
            |file| {
                // The native descriptor really closes. Fault injection models its
                // reported uncertainty without creating or leaking a fake file.
                close_file(file)?;
                Err(rustix::io::Errno::IO)
            },
        )
        .expect_err("reported close failure must own its physical reservation");
    assert!(has_store_cause(&error, |error| matches!(
        error,
        StoreError::Unsupported {
            capability: "initiating-mark-work-refusal"
        }
    )));
    let retained = match &error {
        StoreError::StreamIo { source, .. } => source
            .get_ref()
            .and_then(|error| error.downcast_ref::<CloseFailure<StoreError>>())
            .expect("actual owning close frame"),
        other => panic!("expected owning close frame, got {other:?}"),
    };
    assert_eq!(retained.close, Some(rustix::io::Errno::IO));
    assert!(retained.post.is_none());
    assert!(retained._owner.file.is_none());
    assert!(retained._owner.close_uncertain);
    assert_eq!(available_resident_bytes(resources.as_ref()), held);
    drop(error);
    assert!(available_resident_bytes(resources.as_ref()) < before);
}

#[test]
fn preseal_source_storage_failure_never_publishes_a_partial_copy() {
    let mut fixture = ComponentGcOperation::new();
    let path = fixture.scratch_path().join("objects.sqlite3");
    let source = fixture.context();
    let backend = counted(source.marks());
    let armed = AtomicBool::new(false);
    let changed = AtomicBool::new(false);
    let read_floor = AtomicUsize::new(usize::MAX);
    let connection = crucible_store::content_store::fixture_sqlite_heap()
        .expect("same fixture native heap")
        .open_connection(&path, rusqlite::OpenFlags::default())
        .expect("source writer");
    let mut boundary = || {
        if armed.load(Ordering::Relaxed)
            && backend.reads.load(Ordering::Relaxed) as usize > read_floor.load(Ordering::Relaxed)
            && !changed.swap(true, Ordering::Relaxed)
        {
            connection
                .execute("DELETE FROM objects", [])
                .map_err(|source| {
                    io_error("fault-inject source deletion", io::Error::other(source))
                })?;
        }
        source.check()
    };
    let operation =
        CampaignGcOperationContext::new(backend.clone(), source.original(), &mut boundary)
            .expect("same original deletion edge");
    let mut marks = Reachability::with_operation(&operation).expect("mutable prior root");
    let prior = marks.root;
    let mut sorter = SortOwner::new(&operation).expect("bounded sorter");
    for ordinal in 0..128 {
        sorter
            .insert(page(ordinal))
            .expect("real published run pages");
    }
    read_floor.store(
        backend.reads.load(Ordering::Relaxed) as usize,
        Ordering::Relaxed,
    );
    armed.store(true, Ordering::Relaxed);
    let error = sorter
        .finish_sealed(&mut marks)
        .expect_err("current source deletion refuses seal");
    assert!(changed.load(Ordering::Relaxed));
    assert!(has_store_cause(&error, |error| matches!(
        error,
        StoreError::NotFound { .. }
            | StoreError::Corrupt { .. }
            | StoreError::InvalidSourceLength { .. }
    )));
    assert!(marks.sealed.is_none());
    assert_eq!(marks.root, prior);
}

#[test]
fn typed_id_on_hit_is_checked_even_in_an_immutable_faulted_copy() {
    let mut fixture = ComponentGcOperation::new();
    let operation = fixture.context();
    let close = ClosePurpose::<StoreError>::new(&operation).expect("prepaid close");
    let requested = page(0);
    let other = page(1);
    let mut marks =
        SealedMarks::from_entries(1, [Ok((mark_key(requested), requested))], &operation)
            .expect("real original admission and descriptor");

    // This private fault bypasses the constructor's canonical relation, not
    // its resource account. Close the actual old file before replacing it;
    // the existing one-FD/full-record loan continues to cover the same extent.
    close_file(marks.file.take().expect("actual original file")).expect("real old close");
    operation.check().expect("same original before replacement");
    let mut file = File::from(
        memfd_create(
            "crucible-gc-id-fault",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .expect("actual replacement memfd"),
    );
    let mut record = [0_u8; RECORD_BYTES];
    record[..32].copy_from_slice(&mark_key(requested).as_bytes());
    other.with_encoded_text(|text| {
        record[32] = text.len() as u8;
        record[33..33 + text.len()].copy_from_slice(text);
    });
    file.write_all(&record).expect("real faulted bytes");
    fcntl_add_seals(&file, required_seals()).expect("real immutable faulted bytes");
    marks.file = Some(file);
    operation
        .check()
        .expect("same original after replacement publication");

    let error = marks
        .contains(requested, operation.original(), &mut || operation.check())
        .expect_err("matching scalar key is insufficient typed membership");
    assert!(matches!(error, StoreError::InvalidComposition { .. }));
    marks
        .finish(close, Err::<(), _>(error), &operation, |error| error)
        .expect_err("actual first corruption retained through cleanup");
}

#[test]
fn real_close_precedes_original_post_refusal_and_keeps_its_owner() {
    let mut fixture = ComponentGcOperation::new();
    let resources = fixture.resources();
    let source = fixture.context();
    let closed = AtomicBool::new(false);
    let mut boundary = || {
        if closed.load(Ordering::Relaxed) {
            Err(StoreError::Unsupported {
                capability: "original-postclose-refusal",
            })
        } else {
            source.check()
        }
    };
    let operation =
        CampaignGcOperationContext::new(source.marks(), source.original(), &mut boundary)
            .expect("same original postclose boundary");
    let before = available_resident_bytes(resources.as_ref());
    let close = ClosePurpose::<StoreError>::new(&operation).expect("prepaid returned frame");
    let marks = SealedMarks::from_entries(1, [Ok((mark_key(page(0)), page(0)))], &operation)
        .expect("actual sealed marks");
    let held = available_resident_bytes(resources.as_ref());
    let error = marks
        .finish_with(
            close,
            Ok(()),
            &operation,
            |error| error,
            |file| {
                close_file(file)?;
                closed.store(true, Ordering::Relaxed);
                Ok(())
            },
        )
        .expect_err("original postclose failure is retained");
    assert!(closed.load(Ordering::Relaxed));
    assert!(has_store_cause(&error, |error| matches!(
        error,
        StoreError::Unsupported {
            capability: "original-postclose-refusal"
        }
    )));
    assert_eq!(available_resident_bytes(resources.as_ref()), held);
    drop(error);
    assert_eq!(available_resident_bytes(resources.as_ref()), before);
}

#[test]
fn descriptor_denial_refuses_before_input_without_borrowing_another_bank() {
    let mut fixture = ComponentGcOperation::new();
    let resources = fixture.resources();
    let operation = fixture.context();
    let mut available = 0;
    let mut denied = 129;
    while denied - available > 1 {
        let candidate = available + (denied - available) / 2;
        match resources.reserve_resources(candidate, 0) {
            Ok(loan) => {
                drop(loan);
                available = candidate;
            }
            Err(StoreError::Quota) => denied = candidate,
            Err(error) => panic!("same original descriptor probe: {error:?}"),
        }
    }
    assert!(available > 0);
    let hold = resources
        .reserve_resources(available, 0)
        .expect("retain all remaining original descriptors");
    let entered = AtomicBool::new(false);
    let input = std::iter::once_with(|| {
        entered.store(true, Ordering::Relaxed);
        Ok((mark_key(page(0)), page(0)))
    });
    let error = refused(SealedMarks::from_entries(1, input, &operation));
    assert!(matches!(error, StoreError::Quota));
    assert!(!entered.load(Ordering::Relaxed));
    drop(hold);
    let close = ClosePurpose::<StoreError>::new(&operation).expect("existing final frame");
    let next = SealedMarks::from_entries(0, std::iter::empty(), &operation)
        .expect("same original permits later admission after the fixture loan closes");
    next.finish(close, Ok(()), &operation, |error| error)
        .expect("actual clean native close");
}

#[test]
fn checked_read_partial_and_interrupted_attempts_observe_original_cancellation() {
    for interrupted in [false, true] {
        let mut fixture = ComponentGcOperation::new();
        let supervisor = fixture.supervision();
        let operation = fixture.context();
        let close = ClosePurpose::<StoreError>::new(&operation).expect("prepaid close");
        let marks = SealedMarks::from_entries(1, [Ok((mark_key(page(0)), page(0)))], &operation)
            .expect("actual sealed source");
        let file = marks.file.as_ref().expect("owned sealed descriptor");
        let calls = AtomicUsize::new(0);
        let mut output = [0_u8; RECORD_BYTES];

        let error = read_exact_at_checked(
            &mut output,
            0,
            &mut || operation.check(),
            "injected sealed read",
            |bytes, offset| {
                calls.fetch_add(1, Ordering::Relaxed);
                let result = if interrupted {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    file.read_at(&mut bytes[..1], offset)
                };
                supervisor
                    .cancel()
                    .expect("cancel same original after attempt");
                result
            },
        )
        .expect_err("post-attempt original cut prevents another syscall");

        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "interrupted={interrupted}"
        );
        assert!(operation.check().is_err());
        assert!(matches!(error, StoreError::Supervision { .. }));
        let _error = marks
            .finish(close, Err::<(), _>(error), &operation, |error| error)
            .expect_err("actual cleanup retains the initiating cancellation");
    }
}

#[test]
fn checked_write_partial_and_interrupted_attempts_observe_original_cancellation() {
    for interrupted in [false, true] {
        let mut fixture = ComponentGcOperation::new();
        let supervisor = fixture.supervision();
        let operation = fixture.context();
        let credit = operation
            .reserve_resources(1, 4096)
            .expect("prepaid test descriptor");
        let mut file = File::from(
            memfd_create("checked-mark-write", MemfdFlags::CLOEXEC).expect("actual write target"),
        );
        let calls = AtomicUsize::new(0);

        let error = write_all_checked(b"two bytes", &mut || operation.check(), |bytes| {
            calls.fetch_add(1, Ordering::Relaxed);
            let result = if interrupted {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                file.write(&bytes[..1])
            };
            supervisor
                .cancel()
                .expect("cancel same original after attempt");
            result
        })
        .expect_err("post-attempt original cut prevents another syscall");

        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "interrupted={interrupted}"
        );
        assert!(operation.check().is_err());
        assert!(matches!(error, StoreError::Supervision { .. }));
        close_file(file).expect("physical test descriptor closes before credit");
        drop(credit);
    }
}

#[test]
fn checked_io_advances_only_actual_partial_bytes_and_retries_interrupted_attempts() {
    let mut fixture = ComponentGcOperation::new();
    let operation = fixture.context();
    let credit = operation
        .reserve_resources(1, 4096)
        .expect("prepaid test descriptor");
    let mut file = File::from(
        memfd_create("checked-mark-progress", MemfdFlags::CLOEXEC).expect("actual target"),
    );
    let mut writes = 0;
    write_all_checked(b"abcdef", &mut || operation.check(), |bytes| {
        writes += 1;
        if writes == 2 {
            Err(io::ErrorKind::Interrupted.into())
        } else {
            file.write(&bytes[..bytes.len().min(2)])
        }
    })
    .expect("same original accepts the complete partial write");

    let mut output = [0_u8; 6];
    let mut offsets = Vec::new();
    read_exact_at_checked(
        &mut output,
        0,
        &mut || operation.check(),
        "partial mark read",
        |bytes, offset| {
            offsets.push(offset);
            if offsets.len() == 2 {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                let length = bytes.len().min(2);
                file.read_at(&mut bytes[..length], offset)
            }
        },
    )
    .expect("same original accepts the complete partial read");

    assert_eq!(writes, 4);
    assert_eq!(offsets, [0, 2, 2, 4]);
    assert_eq!(&output, b"abcdef");
    close_file(file).expect("physical descriptor closes before credit");
    drop(credit);
}

#[test]
fn checked_io_keeps_hard_io_first_without_a_success_only_postcut() {
    for reading in [false, true] {
        let mut fixture = ComponentGcOperation::new();
        let supervisor = fixture.supervision();
        let operation = fixture.context();
        let cuts = AtomicUsize::new(0);
        let mut check = || {
            cuts.fetch_add(1, Ordering::Relaxed);
            operation.check()
        };

        let error = if reading {
            read_exact_at_checked(
                &mut [0_u8; 1],
                0,
                &mut check,
                "first mark read IO",
                |_, _| {
                    supervisor
                        .cancel()
                        .expect("independent original cancellation");
                    Err(io::Error::from_raw_os_error(5))
                },
            )
        } else {
            write_all_checked(b"x", &mut check, |_| {
                supervisor
                    .cancel()
                    .expect("independent original cancellation");
                Err(io::Error::from_raw_os_error(5))
            })
        }
        .expect_err("first hard IO refusal survives the later cancellation");

        match error {
            StoreError::StreamIo { source, .. } => assert_eq!(source.raw_os_error(), Some(5)),
            other => panic!("expected first actual IO category: {other}"),
        }
        assert_eq!(cuts.load(Ordering::Relaxed), 1);
        assert!(operation.check().is_err());
    }
}

#[test]
fn checked_io_keeps_zero_progress_first_after_original_cancellation() {
    for reading in [false, true] {
        let mut fixture = ComponentGcOperation::new();
        let supervisor = fixture.supervision();
        let operation = fixture.context();
        let cuts = AtomicUsize::new(0);
        let mut check = || {
            cuts.fetch_add(1, Ordering::Relaxed);
            operation.check()
        };

        let error = if reading {
            read_exact_at_checked(
                &mut [0_u8; 1],
                0,
                &mut check,
                "zero-progress mark read",
                |_, _| {
                    supervisor.cancel().expect("cancel same original");
                    Ok(0)
                },
            )
        } else {
            write_all_checked(b"x", &mut check, |_| {
                supervisor.cancel().expect("cancel same original");
                Ok(0)
            })
        }
        .expect_err("zero progress preserves the initiating IO category");

        let expected = if reading {
            io::ErrorKind::UnexpectedEof
        } else {
            io::ErrorKind::WriteZero
        };
        match error {
            StoreError::StreamIo { source, .. } => assert_eq!(source.kind(), expected),
            other => panic!("expected zero-progress IO category: {other}"),
        }
        assert_eq!(cuts.load(Ordering::Relaxed), 1);
        assert!(operation.check().is_err());
    }
}
