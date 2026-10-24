//! Checks actual owner capacities and refusal boundaries without native peers.

use super::*;
use crucible_node_format::{Phase, Position, U64, canonical};

#[test]
fn equal_short_values_keep_independent_spare_capacity() -> Result<(), OperationFailure> {
    let mut first = String::with_capacity(768 * 1024);
    first.push('x');
    let mut second = String::with_capacity(4096);
    second.push('x');
    let values = Vec::<Id>::with_capacity(31);
    let expected = first.capacity() + second.capacity() + values.capacity() * size_of::<Id>();
    let mut counter = Counter::new(expected);

    counter.charge(&first)?;
    counter.charge(&second)?;
    counter.charge(&values)?;

    assert_eq!(first, second);
    assert_eq!(counter.finish().known_requested_bytes(), expected);
    let mut short = Counter::new(expected - 1);
    short.charge(&first)?;
    short.charge(&second)?;
    assert!(short.charge(&values).is_err());
    Ok(())
}

#[test]
fn actual_rc_aliases_share_only_the_same_backing() -> Result<(), OperationFailure> {
    let mut text = String::with_capacity(8192);
    text.push('x');
    let first = Rc::new(text);
    let alias = Rc::clone(&first);
    let second = Rc::new(first.as_ref().clone());
    let mut counter = Counter::new(usize::MAX);

    assert!(counter.rc(&first)?);
    counter.charge(first.as_ref())?;
    let before = counter.bytes;
    assert!(!counter.rc(&alias)?);
    assert_eq!(counter.bytes, before);
    assert!(counter.rc(&second)?);
    counter.charge(second.as_ref())?;
    assert!(counter.bytes > before);
    assert_eq!(first, second);
    assert!(counter.shared(Rc::as_ptr(&first).cast(), 1).is_err());
    Ok(())
}

#[test]
fn shared_bank_exhaustion_keeps_the_original_count() -> Result<(), OperationFailure> {
    let owners: Vec<_> = (0..=SHARED_LIMIT).map(|_| Rc::new(())).collect();
    let mut counter = Counter::new(usize::MAX);
    for owner in &owners[..SHARED_LIMIT] {
        assert!(counter.rc(owner)?);
    }
    let before = counter.bytes;

    assert!(counter.rc(&owners[SHARED_LIMIT]).is_err());
    assert_eq!(counter.bytes, before);
    assert_eq!(counter.used, SHARED_LIMIT);
    Ok(())
}

#[test]
fn empty_tree_and_nested_json_spare_banks_are_retained() -> Result<(), OperationFailure> {
    let mut values = crucible_node_format::Extensions::new();
    let mut empty = Counter::new(usize::MAX);
    empty.extensions(&values)?;
    let root = empty.bytes;
    assert!(root > 0);
    let mut text = String::with_capacity(32 * 1024);
    text.push('x');
    let spare = text.capacity();
    values.insert("actual".to_owned(), serde_json::Value::String(text));
    let mut counter = Counter::new(usize::MAX);

    counter.extensions(&values)?;
    let total = counter.bytes;
    assert!(total >= root + spare);
    let mut exact = Counter::new(total);
    exact.extensions(&values)?;
    let mut short = Counter::new(total - 1);
    assert!(short.extensions(&values).is_err());
    Ok(())
}

#[test]
fn repeated_activation_roots_use_full_ceiling_before_dedup() -> Result<(), OperationFailure> {
    use crate::node_contract::{ActivationRecord, WorldActivation};

    // Private field construction is data-only. No runtime, prepared node or
    // installed Source accepts or executes these authored metadata fixtures.
    let reference =
        canonical::content_ref(b"world", "application/octet-stream").map_err(unknown)?;
    let active = WorldActivation {
        authority: Rc::new(()),
        record: ActivationRecord {
            generation: U64::new(1),
            activation_id: Id::new("world").map_err(unknown)?,
            world_binding_hash: reference.hash,
            owners: Vec::new(),
            boundary: Position::new(U64::new(1), U64::new(1), Phase::Publication),
        },
        nodes: Rc::from(Vec::new()),
        preparation: None,
    };
    let same = active.clone();
    let first = active
        .retained_requested_storage_data(usize::MAX)
        .map_err(unknown)?;
    let second = same
        .retained_requested_storage_data(usize::MAX)
        .map_err(unknown)?;
    let shared = first.shared_allocations().try_fold(0usize, |sum, owner| {
        sum.checked_add(owner.requested_bytes())
            .ok_or_else(exhausted)
    })?;
    let total = first.independent_bytes() + second.independent_bytes() + shared;
    let mut counter = Counter::new(total);

    common::activation(&active, &mut counter)?;
    common::activation(&same, &mut counter)?;
    assert_eq!(counter.bytes, total);
    let mut short = Counter::new(total - 1);
    common::activation(&active, &mut short)?;
    assert!(common::activation(&same, &mut short).is_err());
    Ok(())
}

#[test]
fn unknown_owners_never_complete_an_equal_numeric_row() {
    let flags = [
        CnpRetainedStorageUnknowns {
            supervisor_slot: true,
            ..Default::default()
        },
        CnpRetainedStorageUnknowns {
            executable_lease_worker: true,
            ..Default::default()
        },
        CnpRetainedStorageUnknowns {
            child_process_backing: true,
            ..Default::default()
        },
        CnpRetainedStorageUnknowns {
            child_streams: true,
            ..Default::default()
        },
        CnpRetainedStorageUnknowns {
            extension_callback: true,
            ..Default::default()
        },
        CnpRetainedStorageUnknowns {
            installed_source_owners: true,
            ..Default::default()
        },
    ];
    for unknowns in flags {
        let report = CnpRetainedStorageReport {
            known_requested_bytes: 123,
            unknowns,
            std_child_layout: false,
        };
        assert_eq!(report.known_requested_bytes(), 123);
        assert!(report.complete_requested_bytes().is_err());
    }
}

#[test]
fn foreign_origin_refuses_before_owned_metadata() {
    let mut origin = StorageOrigin::current();
    origin.process = origin.process.wrapping_add(1);
    assert!(origin.check().is_err());
}
