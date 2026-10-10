//! Actual admitted SQLite run mutation, canonical roots and same-bank custody.
//!
//! These component accounts test requested credit and authenticated storage.
//! They do not certify allocator rounding, installed quotas or runtime speed.
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicBool, Ordering};

use crucible_cas::content_store::{BlobHandle, ObjectKind, OwnedBlobBytes};

use super::super::batched_tests::{available_resident_bytes, counted, page};
use super::*;
use crate::campaign_gc::tests::operation::ComponentGcOperation;

#[test]
fn bounded_runs_preserve_empty_point_and_sorted_canonical_roots() {
    for count in [0, 1, 128, PAGE, PAGE + 1, 2 * PAGE + 3] {
        let mut fixture = ComponentGcOperation::new();
        let operation = fixture.context();
        let mut marks = Reachability::with_operation(&operation).unwrap();
        let mut sorter = SortOwner::new(&operation).unwrap();
        for index in (0..count as u64).rev() {
            sorter.insert(page(index)).unwrap();
        }
        // Duplicates cross both collection and merge boundaries.
        for index in 0..count.min(17) as u64 {
            sorter.insert(page(index)).unwrap();
        }
        sorter.finish(&mut marks).unwrap();

        let account = mark_account(operation.original()).unwrap();
        let _scope = account.enter();
        let _entries_credit = operation.reserve_array::<MarkEntry>(count).unwrap();
        let mut entries: Vec<_> = (0..count as u64)
            .map(|index| (mark_key(page(index)), page(index)))
            .collect();
        entries.sort_unstable_by_key(|entry| entry.0);
        let canonical = marks
            .map
            .build_from_sorted(entries.iter().copied())
            .unwrap();
        assert_eq!(marks.root, canonical, "complete canonical root for {count}");
        assert_eq!(marks.len(), count as u64);
        if count <= 128 {
            let mut point = marks.map.empty().unwrap();
            for (key, id) in &entries {
                point = marks.map.insert(point.content_id(), *key, *id).unwrap();
            }
            assert_eq!(marks.root, point, "independent point traversal for {count}");
        }
        for index in [0, count.saturating_sub(1)] {
            assert_eq!(marks.contains(&page(index as u64)).unwrap(), count != 0);
        }
        assert!(!marks.contains(&page(count as u64 + 1)).unwrap());
    }
}

#[test]
fn failed_run_publication_retains_page_heads_and_original_mark_root() {
    let mut fixture = ComponentGcOperation::new();
    let source_operation = fixture.context();
    let backend = counted(source_operation.marks());
    let mut boundary = || source_operation.check();
    let operation = CampaignGcOperationContext::new(
        backend.clone(),
        source_operation.original(),
        &mut boundary,
    )
    .unwrap();
    let marks = Reachability::with_operation(&operation).unwrap();
    let prior = marks.root;
    let mut sorter = SortOwner::new(&operation).unwrap();
    for index in 0..(3 * PAGE) as u64 {
        sorter.insert(page(index)).unwrap();
    }
    let accepted = sorter.levels;
    for index in (3 * PAGE) as u64..(4 * PAGE - 1) as u64 {
        sorter.insert(page(index)).unwrap();
    }
    // Accept the new page and the first two-page merge, then refuse the
    // final carry after its real publication. Both old ranks must survive.
    let before_carry = backend.publications.load(Ordering::Relaxed);
    backend
        .refuse_on_publication
        .store(before_carry + 3, Ordering::Relaxed);

    let error = sorter.insert(page((4 * PAGE - 1) as u64)).unwrap_err();
    assert_eq!(
        backend.publications.load(Ordering::Relaxed),
        before_carry + 3
    );
    assert!(matches!(
        error.original_failure(),
        StoreError::Unsupported {
            capability: "actual-mark-publication-then-refusal"
        }
    ));
    assert_eq!(marks.root, prior);
    assert_eq!(sorter.page.len(), PAGE);
    assert!(
        sorter
            .levels
            .iter()
            .zip(accepted)
            .all(|(actual, expected)| {
                actual.map(|run| run.node) == expected.map(|run| run.node)
            })
    );
    assert!(backend.objects.load(Ordering::Relaxed) > 0);
    let before = backend.publications.load(Ordering::Relaxed);
    assert!(matches!(
        sorter.insert(page(999_999)),
        Err(StoreError::Unsupported {
            capability: "failed-GC-run-owner"
        })
    ));
    assert_eq!(sorter.page.len(), PAGE);
    assert_eq!(backend.publications.load(Ordering::Relaxed), before);
    operation.original().verify_live().unwrap();
}

#[test]
fn run_cursor_requires_current_right_page_and_never_turns_refusal_into_eof() {
    for remove in [false, true] {
        let mut fixture = ComponentGcOperation::new();
        let path = fixture.scratch_path().join("objects.sqlite3");
        let source_operation = fixture.context();
        let backend = counted(source_operation.marks());
        let mut boundary = || source_operation.check();
        let operation = CampaignGcOperationContext::new(
            backend.clone(),
            source_operation.original(),
            &mut boundary,
        )
        .unwrap();
        let _input_credit = operation.reserve_array::<MarkEntry>(PAGE + 1).unwrap();
        let mut entries: Vec<_> = (0..=PAGE as u64)
            .map(|index| (mark_key(page(index)), page(index)))
            .collect();
        entries.sort_unstable_by_key(|entry| entry.0);
        let mut writer = RunWriter::new(backend.as_ref(), &operation).unwrap();
        for entry in &entries {
            writer.push(*entry).unwrap();
        }
        let run = writer.finish().unwrap().unwrap();
        let source = backend
            .read_with_boundary(operation.original(), run.id, None, &mut || {
                operation.check()
            })
            .unwrap();
        let bytes = source
            .read_all_with_boundary(operation.original(), format::MAX_PAGE_BYTES, &mut || {
                operation.check()
            })
            .unwrap();
        let right = match format::decode(run.id, &bytes).unwrap() {
            format::Record::Branch {
                children: [_, right],
                ..
            } => right,
            _ => panic!("two-page run must retain a branch"),
        };
        drop(bytes);
        drop(source);
        let mut cursor = Cursor::new(run, backend.as_ref(), &operation).unwrap();
        for expected in &entries[..PAGE] {
            assert_eq!(cursor.next_entry().unwrap(), Some(*expected));
        }

        let connection = crucible_cas::content_store::fixture_sqlite_heap()
            .unwrap()
            .open_connection(&path, rusqlite::OpenFlags::default())
            .unwrap();
        let sql = if remove {
            "DELETE FROM objects WHERE id = ?1"
        } else {
            "UPDATE objects SET body = substr(body, 1, length(body) - 1) WHERE id = ?1"
        };
        assert_eq!(connection.execute(sql, [right.id.encode()]).unwrap(), 1);
        let error = cursor.next_entry().unwrap_err();
        assert!(
            matches!(error.original_failure(),
                StoreError::NotFound { id } | StoreError::Corrupt { id }
                if *id == right.id
            ) || matches!(
                error.original_failure(),
                StoreError::InvalidSourceLength { .. }
            )
        );
        assert_eq!(cursor.observed, PAGE as u64);
        assert!(!cursor.complete);
        let reads = backend.reads.load(Ordering::Relaxed);
        assert!(matches!(
            cursor.next_entry(),
            Err(StoreError::Unsupported {
                capability: "failed-GC-run-cursor"
            })
        ));
        assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
        let mut refused = Cursor::new(run, backend.as_ref(), &operation).unwrap();
        backend.refuse_read.store(true, Ordering::Relaxed);
        assert!(matches!(
            refused.next_entry(),
            Err(StoreError::Unsupported {
                capability: "actual-run-read-refusal"
            })
        ));
        let reads = backend.reads.load(Ordering::Relaxed);
        assert!(refused.next_entry().is_err());
        assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
        assert_eq!(refused.observed, 0);
    }
}

#[test]
fn complete_run_tail_and_fallible_builder_tail_keep_initiating_cause() {
    let mut fixture = ComponentGcOperation::new();
    let source_operation = fixture.context();
    let refuse = AtomicBool::new(false);
    let mut boundary = || {
        if refuse.load(Ordering::Relaxed) {
            Err(StoreError::Unsupported {
                capability: "GC-tail-original-refusal",
            })
        } else {
            source_operation.check()
        }
    };
    let operation = CampaignGcOperationContext::new(
        source_operation.marks(),
        source_operation.original(),
        &mut boundary,
    )
    .unwrap();
    let backend = operation.marks();
    let mut writer = RunWriter::new(backend.as_ref(), &operation).unwrap();
    let entry = (mark_key(page(0)), page(0));
    writer.push(entry).unwrap();
    let run = writer.finish().unwrap().unwrap();
    let mut cursor = Cursor::new(run, backend.as_ref(), &operation).unwrap();
    assert_eq!(cursor.next_entry().unwrap(), Some(entry));
    refuse.store(true, Ordering::Relaxed);
    assert!(matches!(
        cursor.next_entry(),
        Err(StoreError::Unsupported {
            capability: "GC-tail-original-refusal"
        })
    ));
    assert!(!cursor.complete);
    refuse.store(false, Ordering::Relaxed);
    assert!(cursor.next_entry().is_err());

    let marks = Reachability::with_operation(&operation).unwrap();
    let account = mark_account(operation.original()).unwrap();
    let input = [
        Ok(entry),
        Err(StoreError::Unsupported {
            capability: "authenticated-input-tail-failure",
        }),
    ];
    assert!(matches!(
        marks
            .map
            .build_from_sorted_with_boundary(input, &account, &mut || operation.check(),),
        Err(crucible_campaign::CampaignStoreError::Store(
            StoreError::Unsupported {
                capability: "authenticated-input-tail-failure"
            }
        ))
    ));
    assert_eq!(marks.len(), 0);
}

#[test]
fn closed_run_grammar_rejects_typed_collision_header_tail_and_all_byte_changes() {
    let mut fixture = ComponentGcOperation::new();
    let operation = fixture.context();
    let mut entries = [(mark_key(page(0)), page(0)), (mark_key(page(1)), page(1))];
    entries.sort_unstable_by_key(|entry| entry.0);
    let (node, bytes) =
        format::leaf(&entries, operation.original(), &mut || operation.check()).unwrap();
    assert!(format::decode(node.id, &bytes).is_ok());
    for position in 0..bytes.len() {
        let mut changed = bytes.to_vec();
        changed[position] ^= 1;
        assert!(format::decode(node.id, &changed).is_err());
    }
    for length in 0..bytes.len() {
        let id = ContentId::for_bytes(ObjectKind::Projection, 1, &bytes[..length]);
        assert!(format::decode(id, &bytes[..length]).is_err());
    }
    // Authenticate each malformed body itself: the grammar, rather than only
    // an old digest mismatch, must reject these specific invalid commitments.
    for position in [8, 9, 17, 18, 19, 83, 115] {
        let mut changed = bytes.to_vec();
        changed[position] ^= 0xff;
        let id = ContentId::for_bytes(ObjectKind::Projection, 1, &changed);
        assert!(
            format::decode(id, &changed).is_err(),
            "authenticated invalid field {position}"
        );
    }
    let mut sorter = SortOwner::new(&operation).unwrap();
    sorter
        .page
        .extend([entries[0], (entries[0].0, entries[1].1)]);
    assert!(matches!(
        sorter.flush(),
        Err(StoreError::InvalidComposition {
            reason: "GC typed mark key collision"
        })
    ));
    assert_eq!(sorter.page.len(), 2);
}

#[test]
fn same_original_control_and_owned_source_loans_survive_aliases_and_unwind() {
    let mut fixture = ComponentGcOperation::new();
    let resources = fixture.resources();
    let operation = fixture.context();
    let before = available_resident_bytes(resources.as_ref());
    let extent =
        (std::mem::size_of::<SortOwner<'_, '_>>() + PAGE * std::mem::size_of::<MarkEntry>()) as u64;
    let sorter = SortOwner::new(&operation).unwrap();
    assert_eq!(
        before - available_resident_bytes(resources.as_ref()),
        extent
    );
    assert_eq!(sorter.page.capacity(), PAGE);
    drop(sorter);
    assert_eq!(available_resident_bytes(resources.as_ref()), before);
    let pressure = resources.reserve_resources(0, before - extent + 1).unwrap();
    assert!(matches!(SortOwner::new(&operation), Err(StoreError::Quota)));
    drop(pressure);
    assert_eq!(available_resident_bytes(resources.as_ref()), before);

    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _sorter = SortOwner::new(&operation).unwrap();
        panic!("control loan unwind");
    }));
    assert!(unwound.is_err());
    assert_eq!(available_resident_bytes(resources.as_ref()), before);

    let bytes = OwnedBlobBytes::write_with_boundary(
        operation.original(),
        4,
        &mut || operation.check(),
        |output| {
            output.copy_from_slice(b"paid");
            Ok(4)
        },
    )
    .unwrap();
    let source = BlobHandle::from_owned_bytes(bytes).unwrap();
    let alias = source.clone();
    let held = available_resident_bytes(resources.as_ref());
    assert!(held < before);
    drop(source);
    assert_eq!(available_resident_bytes(resources.as_ref()), held);
    assert!(alias.open().is_err());
    let output = alias
        .read_all_with_boundary(operation.original(), 4, &mut || operation.check())
        .unwrap();
    assert_eq!(&*output, b"paid");
    drop(output);
    assert_eq!(available_resident_bytes(resources.as_ref()), held);
    drop(alias);
    assert_eq!(available_resident_bytes(resources.as_ref()), before);
    let writer_unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _bytes = OwnedBlobBytes::write_with_boundary(
            operation.original(),
            4,
            &mut || operation.check(),
            |_| {
                panic!("admitted fixed writer unwind");
            },
        );
    }));
    assert!(writer_unwound.is_err());
    assert_eq!(available_resident_bytes(resources.as_ref()), before);
    eprintln!(
        "actual component types: sorter={} cursor={} writer={} publication={} node_ref={} entry={} owned_bytes={} blob_handle={}",
        std::mem::size_of::<SortOwner<'_, '_>>(),
        std::mem::size_of::<Cursor<'_, '_>>(),
        std::mem::size_of::<RunWriter<'_, '_>>(),
        std::mem::size_of::<publication::Publication<'_, '_>>(),
        std::mem::size_of::<NodeRef>(),
        std::mem::size_of::<MarkEntry>(),
        std::mem::size_of::<OwnedBlobBytes>(),
        std::mem::size_of::<BlobHandle>(),
    );
    assert!(
        OwnedBlobBytes::write_with_boundary(
            operation.original(),
            4,
            &mut || operation.check(),
            |_| Ok(3),
        )
        .is_err()
    );
    assert_eq!(available_resident_bytes(resources.as_ref()), before);
}
