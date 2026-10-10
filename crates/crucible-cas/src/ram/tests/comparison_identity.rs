//! Same-store comparison reuse and adversarial realization checks.

use super::*;
use crate::ram::codec::{TreeNode, TreeRef};
use crate::ram::difference::{DifferenceAccess, ExistingDifference};

fn compare(
    store: &RamStore,
    before: TreeRef,
    after: TreeRef,
    original: &crate::owned_decode::DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
) -> Result<(u64, u64), RamStoreError> {
    let mut work = Work::new(store.limits, original, boundary)?;
    let mut changed = 0;
    let mut visitor = |_: &str, _: u64| panic!("equal logical digests have no changed page");
    let mut access = ExistingDifference {
        backend: store.backend.as_ref(),
        work: &mut work,
        visitor: &mut visitor,
    };
    crate::ram::difference::walk(&mut access, "main", before, after, 0, &mut changed)?;
    assert_eq!(changed, 0);
    Ok((work.visits, work.io_bytes))
}

#[test]
fn same_id_comparison_authenticates_one_actual_object() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    let reference = root.regions[0];

    let mut read_polls = 0;
    let mut read_boundary = || {
        read_polls += 1;
        Ok(())
    };
    let mut work = Work::new(store.limits, &original, &mut read_boundary).unwrap();
    let mut visitor = |_: &str, _: u64| panic!("an actual record read cannot visit");
    let expected = ExistingDifference {
        backend: store.backend.as_ref(),
        work: &mut work,
        visitor: &mut visitor,
    }
    .node(reference)
    .unwrap();
    assert!(matches!(expected, TreeNode::Leaf { .. }));
    let expected_counts = (work.visits, work.io_bytes);
    drop(work);

    let mut compare_polls = 0;
    let counts = compare(&store, reference, reference, &original, &mut || {
        compare_polls += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(counts, expected_counts);
    assert_eq!(counts.0, 1);
    assert_eq!(compare_polls, read_polls);
    eprintln!("one_actual_read_polls={read_polls} same_id_comparison_polls={compare_polls}");
}

#[test]
fn same_id_comparison_checks_second_reference_geometry_and_height_priority() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    let reference = root.regions[0];

    for (after, expected) in [
        (
            TreeRef {
                digest: NodeDigest::from_bytes([42; 32]),
                ..reference
            },
            "tree reference geometry",
        ),
        (
            TreeRef {
                height: 1,
                ..reference
            },
            "tree reference geometry",
        ),
        (
            TreeRef {
                pages: 0,
                ..reference
            },
            "tree reference geometry",
        ),
        (
            TreeRef {
                height: 53,
                ..reference
            },
            "tree schema or height",
        ),
    ] {
        let error = compare(&store, reference, after, &original, &mut || Ok(())).unwrap_err();
        assert!(matches!(error, RamStoreError::Invalid(reason) if reason == expected));
    }
}

#[test]
fn different_id_comparison_authenticates_second_realization_for_equal_digest() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    let reference = root.regions[0];
    let missing = ContentId::for_bytes(ObjectKind::RamTree, 1, b"missing realization");
    let after = TreeRef {
        id: missing,
        ..reference
    };

    let error = compare(&store, reference, after, &original, &mut || Ok(())).unwrap_err();
    let RamStoreError::Store(error) = error else {
        panic!("actual lookup retains its owning storage error");
    };
    assert!(error.confirmed_absence(missing));
}

#[test]
fn same_id_comparison_still_detects_corrupt_physical_realization() {
    let directory = tempfile::tempdir().unwrap();
    let (store, quota) = admitted_store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    let reference = root.regions[0];

    // The fault injector uses the same authored namespace bank and existing
    // native SQLite heap ceiling before opening its extra fixture connection.
    let fault_credit = quota.0.reserve(1, 8 << 20).unwrap();
    let connection = crate::content_store::fixture_sqlite_heap()
        .unwrap()
        .open_connection(
            directory.path().join("objects.sqlite3"),
            rusqlite::OpenFlags::default(),
        )
        .unwrap();
    let changed = reference
        .id
        .with_encoded_text(|id| {
            let text = std::str::from_utf8(id).unwrap();
            connection.execute(
                "UPDATE objects SET body = zeroblob(length(body)) WHERE id = ?1",
                [text],
            )
        })
        .unwrap();
    assert_eq!(changed, 1);
    drop(connection);
    drop(fault_credit);

    let error = compare(&store, reference, reference, &original, &mut || Ok(())).unwrap_err();
    let RamStoreError::Store(error) = error else {
        panic!("physical corruption retains its owning storage error");
    };
    assert!(matches!(error.original_failure(), StoreError::Corrupt { id } if *id == reference.id));
}

#[test]
fn same_id_comparison_never_accepts_callback_poisoned_original() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    let reference = root.regions[0];
    let mut successful_polls = 0;
    compare(&store, reference, reference, &original, &mut || {
        successful_polls += 1;
        Ok(())
    })
    .unwrap();

    for poison_at in 1..=successful_polls {
        let operation = original.child().unwrap();
        let mut polls = 0;
        let mut first_refusal = None;
        let result = compare(&store, reference, reference, &operation, &mut || {
            polls += 1;
            if polls == poison_at {
                first_refusal = Some(operation.charge_bytes(u64::MAX).unwrap_err());
            }
            Ok(())
        });
        assert!(
            result.is_err(),
            "accepted original poisoned at callback {poison_at} of {successful_polls}"
        );
        assert_eq!(polls, poison_at, "no callback follows original refusal");
        let Err(RamStoreError::Store(error)) = &result else {
            panic!("the original admission refusal retains its typed storage cause");
        };
        let StoreError::DecodeAdmission { source, .. } = error.original_failure() else {
            panic!("the original refusal remains an admission failure");
        };
        assert_eq!(Some(source), first_refusal.as_ref());
        drop(result);
        drop(first_refusal);
        drop(operation);
        original.verify_live().unwrap();
    }
}
