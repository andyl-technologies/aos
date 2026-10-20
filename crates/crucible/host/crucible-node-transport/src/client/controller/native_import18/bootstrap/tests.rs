//! Exercises actual typed input correspondence and retained backing DATA.
//!
//! These controls create no Controller, opaque recipe, Initial result or witness.

use super::*;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;

fn request_data() -> PacketNativeImport18BootstrapRequest {
    PacketNativeImport18BootstrapRequest {
        schema: NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA.into(),
        recipe_identity: Bytes::new(vec![7; 32]),
        initial_funding: PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(1),
            maximum_simultaneous_transient_bytes: U64::new(2),
            declared_counter_scratch_bytes: U64::new(3),
        },
    }
}

#[test]
fn typed_identity_binds_id_schema_recipe_and_each_initial_axis() {
    let request = request_data();
    let first = Id::new("bootstrap-first").unwrap();
    let second = Id::new("bootstrap-second").unwrap();
    let exact = storage::input_identity_data(&first, &request).unwrap();
    assert_ne!(
        exact,
        storage::input_identity_data(&second, &request).unwrap()
    );

    let mut changed = request_data();
    changed.schema.push('x');
    assert_ne!(
        exact,
        storage::input_identity_data(&first, &changed).unwrap()
    );
    changed = request_data();
    changed.recipe_identity = Bytes::new(vec![8; 32]);
    assert_ne!(
        exact,
        storage::input_identity_data(&first, &changed).unwrap()
    );

    for axis in 0..3 {
        let mut changed = request_data();
        match axis {
            0 => changed.initial_funding.retained_requested_bytes = U64::new(4),
            1 => changed.initial_funding.maximum_simultaneous_transient_bytes = U64::new(4),
            _ => changed.initial_funding.declared_counter_scratch_bytes = U64::new(4),
        }
        assert_ne!(
            exact,
            storage::input_identity_data(&first, &changed).unwrap()
        );
    }
}

#[test]
fn correspondence_compares_full_initial_row_without_reissuing_it() {
    let request = request_data();
    let initial = request.initial_funding;
    assert!(storage::request_matches_initial_data(
        &request, &[7; 32], &initial
    ));
    assert!(!storage::request_matches_initial_data(
        &request, &[8; 32], &initial
    ));
    let mut changed = initial;
    changed.declared_counter_scratch_bytes = U64::new(4);
    assert!(!storage::request_matches_initial_data(
        &request, &[7; 32], &changed
    ));
}

#[test]
fn invalid_typed_partial_counts_actual_spare_string_and_digest_backing() {
    let mut request = request_data();
    request.schema.reserve_exact(1024);
    let mut digest = Vec::with_capacity(4096);
    digest.extend_from_slice(&[9; 5]);
    request.recipe_identity = Bytes::new(digest);
    assert!(request.validate_data().is_err());

    let mut observer = MetadataObserver::new();
    storage::observe_request_data(&request, &mut observer).unwrap();
    let actual = requested_metadata_backing_storage_data(&observer.finish()).unwrap();
    assert!(actual >= request.schema.capacity() + request.recipe_identity.allocation_capacity());
}

#[test]
fn constructor_axes_refuse_checked_overflow() {
    assert_eq!(storage::checked_sum_data(&[1, 2, 3]).unwrap(), 6);
    assert!(storage::checked_sum_data(&[usize::MAX, 1]).is_err());
}
