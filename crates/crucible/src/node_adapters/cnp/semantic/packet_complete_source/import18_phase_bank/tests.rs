//! Exercises actual failed partial backing without constructing a phase witness.

use super::*;
use crucible_node_contract::Bytes;
use crucible_node_provider::bodies::BeginKind;

#[test]
fn bootstrap_partial_keeps_invalid_typed_bytes_and_independent_encoded_bank() {
    let mut partial = BootstrapPartials::new_data();
    let mut digest = Vec::with_capacity(113);
    digest.push(7);
    let mut schema = String::with_capacity(97);
    schema.push_str("failed-bootstrap-schema");
    partial.request = Some(PacketNativeImport18BootstrapRequest {
        schema,
        recipe_identity: Bytes::new(digest),
        initial_funding: PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(1),
            maximum_simultaneous_transient_bytes: U64::new(2),
            declared_counter_scratch_bytes: U64::new(3),
        },
    });
    partial.encoded = Vec::with_capacity(131);
    partial.failed = true;

    let request = partial.request.as_ref().unwrap();
    assert!(request.validate_data().is_err());
    let actual = partial.retained_backing_data(usize::MAX).unwrap();
    assert!(
        actual
            >= request.schema.capacity()
                + request.recipe_identity.allocation_capacity()
                + partial.encoded.capacity()
    );
    assert_eq!(partial.retained_backing_data(actual).unwrap(), actual);
    assert!(partial.retained_backing_data(actual - 1).is_err());
    assert!(partial.failed);
    assert!(!partial.assigned);
    assert!(partial.receipt.is_none());
}

#[test]
fn literal_attempt_header_is_not_double_counted_beside_independent_bytes() {
    let mut partial = PhasePartials::new_data();
    partial.normalized[0].attempt = Some(LiteralValue18TokenAttempt::new());
    partial.normalized[0].encoded = Vec::with_capacity(73);
    partial.normalized[3].encoded = Vec::with_capacity(109);
    partial.started = true;
    partial.failed = true;

    let expected =
        partial.normalized[0].encoded.capacity() + partial.normalized[3].encoded.capacity();
    assert_eq!(partial.retained_backing_data(expected).unwrap(), expected);
    assert!(partial.retained_backing_data(expected - 1).is_err());
    let view = history::phase_history(&partial);
    assert!(view.normalized[0].attempt.is_some());
    assert!(view.normalized[0].literal.is_none());
    assert!(view.normalized[1].attempt.is_none());
    assert!(view.failed);
    assert!(!view.verified);
}

#[test]
fn source_begin_and_request_id_remain_independent_failed_partial_owners() {
    let mut partial = PhasePartials::new_data();
    partial.request_id = Some(Id::new("phase18/actual-partial-request").unwrap());
    partial.baseline = Some(BeginRequest {
        kind: BeginKind::PrepareRestore,
        binding_hash: crucible_node_contract::canonical::hash(
            "phase18.failed-partial.data",
            b"retained Begin",
        )
        .unwrap(),
        owner_generation: U64::new(1),
        activation_id: crucible_node_provider::envelope::Nullable(None),
        world_generation: U64::new(1),
        arguments: Default::default(),
        extensions: Default::default(),
    });
    partial.failed = true;
    let actual = partial.retained_backing_data(usize::MAX).unwrap();
    assert!(actual >= partial.request_id.as_ref().unwrap().allocated_capacity() + 32);
    assert_eq!(partial.retained_backing_data(actual).unwrap(), actual);
    assert!(partial.retained_backing_data(actual - 1).is_err());
    assert!(!partial.assigned);
    assert!(!partial.sealed);
}
