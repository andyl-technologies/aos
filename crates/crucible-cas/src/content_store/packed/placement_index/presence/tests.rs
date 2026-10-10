//! Real finite arena, original-loan and callback cuts for group presence reuse.
//!
//! Fixture construction uses the existing4MiB/eight-FD component account; its
//! surrounding test allocations confer no mounted quota or native entitlement.

use super::*;
use crate::content_store::packed::placement_tests::{
    Fixture, FixtureError, object, published_two_leaf_index, value,
};
use std::os::unix::fs::FileExt;

fn arena_path(fixture: &Fixture, snapshot: &IndexSnapshot) -> PathBuf {
    let name = index_io::arena_name(snapshot.header.arena.expect("real two-leaf arena"));
    fixture
        .backend
        .admin
        .join(std::str::from_utf8(&name).expect("fixed ASCII arena name"))
}

#[test]
fn group_presence_reuses_actual_paid_page_after_new_page_loans_are_denied()
-> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    {
        let snapshot = published_two_leaf_index(&fixture)?;
        let before = fixture.usage()?;
        let mut scratch = None;
        assert_eq!(
            snapshot.find_for_group(
                &fixture.backend,
                object(0),
                &fixture.original,
                &mut scratch,
                &mut || Ok(())
            )?,
            Some(value(0).entry()?),
        );
        let retained = fixture.usage()?;
        assert_eq!(retained.0, before.0, "no descriptor survives a lookup");
        assert_eq!(
            retained.1 - before.1,
            wire::PAGE_BYTES as u64 + std::mem::size_of::<PresenceScratch<'_, '_>>() as u64
        );

        fixture.refuse_page_reservations();
        assert_eq!(
            snapshot.find_for_group(
                &fixture.backend,
                object(64),
                &fixture.original,
                &mut scratch,
                &mut || Ok(())
            )?,
            Some(value(64).entry()?),
        );
        assert_eq!(fixture.usage()?, retained);
        drop(scratch);
        assert_eq!(fixture.usage()?, before);
    }
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}

#[test]
fn group_presence_reopens_replaced_arena_before_reusing_storage() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let snapshot = published_two_leaf_index(&fixture)?;
    let mut scratch = None;
    snapshot.find_for_group(
        &fixture.backend,
        object(0),
        &fixture.original,
        &mut scratch,
        &mut || Ok(()),
    )?;
    let retained = fixture.usage()?;
    let path = arena_path(&fixture, &snapshot);
    let previous = path.with_extension("previous-test-arena");
    fs::rename(&path, &previous)?;
    fs::write(&path, [])?;

    let error = snapshot
        .find_for_group(
            &fixture.backend,
            object(0),
            &fixture.original,
            &mut scratch,
            &mut || Ok(()),
        )
        .expect_err("fresh path observes the truncated replacement");
    assert!(matches!(error, StoreError::Incompatible));
    assert_eq!(fixture.usage()?, retained);
    fs::remove_file(&path)?;
    fs::rename(previous, path)?;
    assert_eq!(
        snapshot.find_for_group(
            &fixture.backend,
            object(0),
            &fixture.original,
            &mut scratch,
            &mut || Ok(())
        )?,
        Some(value(0).entry()?)
    );
    Ok(())
}

#[test]
fn group_presence_freshly_authenticates_mutated_page_bytes() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let snapshot = published_two_leaf_index(&fixture)?;
    let mut scratch = None;
    snapshot.find_for_group(
        &fixture.backend,
        object(0),
        &fixture.original,
        &mut scratch,
        &mut || Ok(()),
    )?;
    let retained = fixture.usage()?;
    let root = PageReference::decode(snapshot.body())?;
    let file = fs::OpenOptions::new()
        .write(true)
        .open(arena_path(&fixture, &snapshot))?;
    file.write_all_at(&[0xff], root.offset)?;
    drop(file);

    let error = snapshot
        .find_for_group(
            &fixture.backend,
            object(0),
            &fixture.original,
            &mut scratch,
            &mut || Ok(()),
        )
        .expect_err("retained storage never substitutes for fresh bytes");
    assert!(matches!(error, StoreError::Incompatible));
    assert_eq!(fixture.usage()?, retained);
    Ok(())
}

#[test]
fn group_presence_callback_cancellation_keeps_storage_and_first_refusal() -> Result<(), FixtureError>
{
    let fixture = Fixture::new()?;
    let snapshot = published_two_leaf_index(&fixture)?;
    let mut scratch = None;
    snapshot.find_for_group(
        &fixture.backend,
        object(0),
        &fixture.original,
        &mut scratch,
        &mut || Ok(()),
    )?;
    let retained = fixture.usage()?;
    let mut cuts = 0;
    let error = snapshot
        .find_for_group(
            &fixture.backend,
            object(64),
            &fixture.original,
            &mut scratch,
            &mut || {
                cuts += 1;
                Err(StoreError::Unauthorized)
            },
        )
        .expect_err("same callback cancels before fresh IO");
    assert!(matches!(error, StoreError::Unauthorized));
    assert_eq!(cuts, 1);
    assert_eq!(fixture.usage()?, retained);
    assert!(scratch.is_some());
    Ok(())
}

#[test]
fn group_presence_retained_page_does_not_renew_revoked_original() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let snapshot = published_two_leaf_index(&fixture)?;
    let mut scratch = None;
    snapshot.find_for_group(
        &fixture.backend,
        object(0),
        &fixture.original,
        &mut scratch,
        &mut || Ok(()),
    )?;
    let retained = fixture.usage()?;
    fixture.close_original();

    let error = snapshot
        .find_for_group(
            &fixture.backend,
            object(64),
            &fixture.original,
            &mut scratch,
            &mut || Ok(()),
        )
        .expect_err("saved owner is actually revoked");
    assert!(matches!(error, StoreError::DecodeAdmission { .. }));
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert_eq!(fixture.usage()?, retained);
    assert!(scratch.is_some());
    Ok(())
}

#[test]
fn group_presence_refuses_inline_snapshot_or_original_substitution() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let snapshot = published_two_leaf_index(&fixture)?;
    let mut scratch = None;
    snapshot.find_for_group(
        &fixture.backend,
        object(0),
        &fixture.original,
        &mut scratch,
        &mut || Ok(()),
    )?;
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut || Ok(()),
    };
    let inline = EncodedIndex::empty_under(&fixture.backend, [42; 32], &mut operation)?.snapshot();
    let retained = fixture.usage()?;

    let error = inline
        .find_for_group(
            &fixture.backend,
            object(0),
            &fixture.original,
            &mut scratch,
            &mut || Ok(()),
        )
        .expect_err("inline lookup cannot silently bypass the saved snapshot binding");
    assert!(matches!(error, StoreError::Incompatible));
    assert_eq!(fixture.usage()?, retained);

    let other = Fixture::new()?;
    let other_baseline = other.usage()?;
    let error = snapshot
        .find_for_group(
            &fixture.backend,
            object(0),
            &other.original,
            &mut scratch,
            &mut || Ok(()),
        )
        .expect_err("another fixture account cannot borrow retained storage");
    assert!(matches!(error, StoreError::Incompatible));
    assert_eq!(other.usage()?, other_baseline);
    assert_eq!(fixture.usage()?, retained);
    assert!(scratch.is_some());
    drop(scratch);
    Ok(())
}
