//! Real retained-reader authentication and same-original lookup storage controls.
//!
//! Arena bytes and resource loans use the existing finite placement fixture;
//! fixture construction is not native allocator or deployed quota evidence.

use super::*;
use crate::content_store::packed::index_format::PageReference;
use crate::content_store::packed::placement_tests::{
    Fixture, FixtureError, object, published_two_leaf_index, value,
};
use std::os::unix::fs::FileExt;

#[test]
fn validation_lookup_reuses_paid_buffers_without_new_page_admission() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    {
        let snapshot = published_two_leaf_index(&fixture)?;
        let mut operation = Operation {
            original: Some(&fixture.original),
            boundary: &mut || Ok(()),
        };
        let reader = snapshot.reader(&fixture.backend, &mut operation)?;
        let before = fixture.usage()?;
        let mut lookup = ValidationLookup::new(&operation)?;
        assert_eq!(
            lookup.find(&reader, Key::object(object(0)), &mut operation)?,
            Some(value(0))
        );
        let retained = fixture.usage()?;
        assert_eq!(retained.0, before.0);
        assert_eq!(
            retained.1 - before.1,
            (2 * wire::PAGE_BYTES + std::mem::size_of::<Option<ValidationLookup>>()) as u64
        );

        fixture.refuse_page_reservations();
        assert_eq!(
            lookup.find(&reader, Key::object(object(64)), &mut operation)?,
            Some(value(64))
        );
        assert_eq!(lookup.root.identical_reads, 1);
        assert_eq!(fixture.usage()?, retained);
        drop(lookup);
        assert_eq!(fixture.usage()?, before);
    }
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}

#[test]
fn validation_lookup_rereads_mutated_root_despite_retained_layout() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let snapshot = published_two_leaf_index(&fixture)?;
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut || Ok(()),
    };
    let reader = snapshot.reader(&fixture.backend, &mut operation)?;
    let mut lookup = ValidationLookup::new(&operation)?;
    lookup.find(&reader, Key::object(object(0)), &mut operation)?;
    let retained = fixture.usage()?;
    let reference = PageReference::decode(snapshot.body())?;
    let name = index_io::arena_name(snapshot.header.arena.expect("real arena"));
    let path = fixture
        .backend
        .admin
        .join(std::str::from_utf8(&name).expect("ASCII arena name"));
    let writer = fs::OpenOptions::new().write(true).open(path)?;
    writer.write_all_at(&[0xff], reference.offset)?;
    drop(writer);

    let error = lookup
        .find(&reader, Key::object(object(0)), &mut operation)
        .expect_err("cached layout cannot replace the actual fresh root bytes");
    assert!(matches!(error, StoreError::Incompatible));
    assert_eq!(lookup.root.identical_reads, 0);
    assert_eq!(fixture.usage()?, retained);
    Ok(())
}

#[test]
fn validation_lookup_refuses_revoked_original_without_refunding_live_storage()
-> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let snapshot = published_two_leaf_index(&fixture)?;
    let mut operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut || Ok(()),
    };
    let reader = snapshot.reader(&fixture.backend, &mut operation)?;
    let mut lookup = ValidationLookup::new(&operation)?;
    lookup.find(&reader, Key::object(object(0)), &mut operation)?;
    let retained = fixture.usage()?;
    fixture.close_original();

    let error = lookup
        .find(&reader, Key::object(object(64)), &mut operation)
        .expect_err("retained storage never renews its actual original owner");
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert_eq!(fixture.usage()?, retained);
    Ok(())
}

#[test]
fn validation_lookup_page_admission_failure_refunds_prepaid_control() -> Result<(), FixtureError> {
    let fixture = Fixture::new()?;
    let baseline = fixture.usage()?;
    fixture.refuse_page_reservations();
    let operation = Operation {
        original: Some(&fixture.original),
        boundary: &mut || Ok(()),
    };

    let error = match ValidationLookup::new(&operation) {
        Ok(_) => panic!("denied page cannot create a lookup owner"),
        Err(error) => error,
    };
    assert!(matches!(error.original_failure(), StoreError::Quota));
    assert_eq!(fixture.usage()?, baseline);
    Ok(())
}
