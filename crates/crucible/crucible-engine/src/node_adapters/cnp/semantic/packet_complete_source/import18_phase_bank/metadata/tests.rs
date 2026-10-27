//! Checks failed partial geometry independently of native and phase witnesses.

use super::super::super::tests::{coordinator, installation, producer, storage_selection};
use super::*;
use crucible_node_format::{Bytes, canonical::hash};
use crucible_node_transport::{bodies::BeginKind, envelope::Nullable};

fn source() -> PacketCompleteSemanticSource {
    let coordinator = coordinator();
    PacketCompleteSemanticSource::new_producer_for_collecting_world(
        installation(&coordinator, 0),
        producer(),
        coordinator,
        storage_selection(),
    )
    .unwrap()
}

#[test]
fn unentered_source_has_no_invented_bank_and_busy_or_foreign_owners_refuse() {
    let mut source = source();
    assert_eq!(
        source
            .native_import18_phase_bank_capacity_data(None)
            .unwrap(),
        RetainedProtocolMetadataFacts::default()
    );
    let borrowed = source.native_import18_phase_bank.borrow_mut();
    assert!(
        source
            .native_import18_phase_bank_capacity_data(None)
            .is_err()
    );
    drop(borrowed);

    source.process = source.process.wrapping_add(1);
    assert!(
        source
            .native_import18_phase_bank_capacity_data(None)
            .is_err()
    );
    assert!(source.native_import18_phase_bank.borrow().is_none());
}

#[test]
fn invalid_bootstrap_partial_keeps_actual_spare_capacities_and_old_byte_cost() {
    let mut partial = BootstrapPartials::new_data();
    let mut schema = String::with_capacity(97);
    schema.push_str("invalid-partial-schema");
    let mut digest = Vec::with_capacity(113);
    digest.push(7);
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
    partial.literal_attempt = Some(LiteralValue18TokenAttempt::new());
    partial.failed = true;

    let mut census = PhaseCapacityCensus::new(None);
    census.bootstrap(&partial).unwrap();
    let facts = census.facts;
    let request = partial.request.as_ref().unwrap();
    let old_bytes = partial.retained_backing_data(usize::MAX).unwrap();

    assert!(request.validate_data().is_err());
    assert_eq!(facts.string_capacity_bytes, request.schema.capacity());
    assert_eq!(
        facts.vector_capacity_bytes,
        partial.encoded.capacity() + request.recipe_identity.allocation_capacity()
    );
    assert_eq!(facts.vector_banks, 4);
    assert_eq!(facts.string_banks, 1);
    assert_eq!(facts.capacity_records, 5);
    assert_eq!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &facts, old_bytes,
        ),
        Ok(old_bytes)
    );
    assert!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &facts,
            old_bytes - 1,
        )
        .is_err()
    );
    assert!(partial.failed);
    assert!(!partial.assigned);
    assert!(partial.receipt.is_none());
}

#[test]
fn independent_phase_inputs_keep_actual_empty_tree_layout_and_failed_prefix() {
    let mut partial = PhasePartials::new_data();
    partial.request_id = Some(Id::new("phase18/original-capacity").unwrap());
    partial.baseline = Some(BeginRequest {
        kind: BeginKind::PrepareRestore,
        binding_hash: hash("phase18.capacity.data", b"independent Begin").unwrap(),
        owner_generation: U64::new(1),
        activation_id: Nullable(None),
        world_generation: U64::new(1),
        arguments: Default::default(),
        extensions: Default::default(),
    });
    partial.normalized[0].attempt = Some(LiteralValue18TokenAttempt::new());
    partial.normalized[0].encoded = Vec::with_capacity(73);
    partial.normalized[3].encoded = Vec::with_capacity(109);
    partial.failed = true;

    let mut census = PhaseCapacityCensus::new(None);
    census.phase(&partial).unwrap();
    let expected = OriginalNativeImport18Assignment::source_input_retained_metadata_data(
        partial.request_id.as_ref(),
        partial.baseline.as_ref(),
        None,
        None,
        None,
    )
    .unwrap();
    let actual = census.facts;
    let old_bytes = partial.retained_backing_data(usize::MAX).unwrap();

    assert_eq!(actual.tree_containers, expected.tree_containers);
    assert_eq!(
        actual.maximum_tree_key_value_bytes,
        expected.maximum_tree_key_value_bytes
    );
    assert_eq!(
        actual.maximum_tree_entry_alignment,
        expected.maximum_tree_entry_alignment
    );
    assert_eq!(actual.capacity_records, expected.capacity_records + 7);
    assert_eq!(actual.vector_banks, expected.vector_banks + 7);
    assert_eq!(
        actual.vector_capacity_bytes,
        expected.vector_capacity_bytes
            + partial.normalized[0].encoded.capacity()
            + partial.normalized[3].encoded.capacity()
    );
    assert_eq!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &actual, old_bytes,
        ),
        Ok(old_bytes)
    );
    assert!(partial.failed);
    assert!(!partial.verified);
}
