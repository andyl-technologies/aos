//! Checks original derivation field geometry without fabricating a sealed Job.
//!
//! A local field-walk specimen is ordinary DATA. Positive Source/job/mechanism
//! association still requires the real supervised route and original deployment.

use super::*;
use crucible_node_format::ExtensionSelection;

fn empty_state() -> NativeImport18DerivationState {
    NativeImport18DerivationState {
        source: 0,
        process: std::process::id(),
        thread: std::thread::current().id(),
        attempt: None,
        private_launch: None,
        original_launch: None,
        registration: None,
        receipt: None,
        host_reference: None,
        private_seed: None,
        private_birth_started: false,
        source_bank: Vec::new(),
        registration_bank: Vec::new(),
        job: None,
        banks: None,
        stage: DerivationStage::Failed,
    }
}

#[test]
fn failed_derivation_fields_keep_spare_banks_and_original_input_capacities() {
    let text = |capacity, value: &str| {
        let mut text = String::with_capacity(capacity);
        text.push_str(value);
        text
    };
    let mut state = empty_state();
    state.private_launch = Some(Id::new(text(101, "retained-private-launch")).unwrap());
    state.registration = Some(PacketCompleteAckHostRegistrationPlan {
        connection_id: Id::new(text(113, "retained-connection")).unwrap(),
        features: Vec::with_capacity(3),
        extensions: Vec::with_capacity(2),
        envelope_extensions: Vec::with_capacity(5),
    });
    state.private_seed = Some(birth::OriginalImport18PrivateSeed::empty());
    state.host_reference = Some([7; 32]);
    state.private_birth_started = true;
    state.source_bank = Vec::with_capacity(31);
    state.source_bank.extend_from_slice(b"source");
    state.registration_bank = Vec::with_capacity(47);
    state.banks = Some([0..6, 0..0]);
    let source_pointer = state.source_bank.as_ptr();
    let registration_pointer = state.registration_bank.as_ptr();
    let expected_vectors = 3 * size_of::<Id>()
        + 2 * size_of::<ExtensionSelection>()
        + 5 * size_of::<String>()
        + 31
        + 47;
    let mut census = OriginalOwnerCapacityMetadataData::new(7, None);

    state.record_known_capacity_data(&mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 7);
    assert_eq!(facts.string_banks, 2);
    assert_eq!(facts.string_capacity_bytes, 101 + 113);
    assert_eq!(facts.vector_banks, 5);
    assert_eq!(facts.vector_capacity_bytes, expected_vectors);
    assert_eq!(facts.shared_backing_views, 0);
    assert!(facts.observed_nodes > facts.capacity_records);
    let bytes = 101 + 113 + expected_vectors;
    assert_eq!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &facts, bytes,
        ),
        Ok(bytes)
    );
    assert_eq!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &facts,
            bytes - 1,
        ),
        Err(RuntimeError::ResourceLimit)
    );

    let mut short = OriginalOwnerCapacityMetadataData::new(6, None);
    assert_eq!(
        state.record_known_capacity_data(&mut short),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(short.finish().capacity_records, 6);
    assert_eq!(state.source_bank.as_ptr(), source_pointer);
    assert_eq!(state.registration_bank.as_ptr(), registration_pointer);
    assert!(state.private_birth_started && state.stage == DerivationStage::Failed);
}

#[test]
fn empty_derivation_fields_count_fixed_work_and_zero_capacity_vector_rows() {
    let state = empty_state();
    let mut census = OriginalOwnerCapacityMetadataData::new(2, None);

    state.record_known_capacity_data(&mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 2);
    assert_eq!(facts.vector_capacity_bytes, 0);
    assert_eq!(facts.observed_nodes, 16);
    assert!(!state.private_birth_started);
}

#[test]
fn aggregate_child_observer_passes_only_remaining_rows_and_retains_originals() {
    let mut prefix = String::with_capacity(17);
    prefix.push_str("prefix");
    let mut values = Vec::with_capacity(5);
    values.extend_from_slice(&[1u8, 2]);
    let mut suffix = String::with_capacity(31);
    suffix.push_str("suffix");
    let original_values = values.as_ptr();
    let mut census = OriginalOwnerCapacityMetadataData::new(3, None);
    census.observe(&prefix).unwrap();

    census
        .observe_component_capacity_data(|remaining, bank| {
            assert_eq!(remaining, 2);
            assert!(bank.is_none());
            let mut child = OriginalOwnerCapacityMetadataData::new(remaining, bank);
            child.observe(&values)?;
            child.observe(&suffix)?;
            Ok(child.finish())
        })
        .unwrap();
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 3);
    assert_eq!(facts.string_capacity_bytes, 17 + 31);
    assert_eq!(facts.vector_capacity_bytes, 5 * size_of::<u8>());
    assert!(facts.observed_nodes > facts.capacity_records);
    let mut short = OriginalOwnerCapacityMetadataData::new(2, None);
    short.observe(&prefix).unwrap();
    assert_eq!(
        short.observe_component_capacity_data(|remaining, bank| {
            assert_eq!(remaining, 1);
            let mut child = OriginalOwnerCapacityMetadataData::new(remaining, bank);
            child.observe(&values)?;
            child.observe(&suffix)?;
            Ok(child.finish())
        }),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(short.finish().capacity_records, 1);
    assert_eq!(values.as_ptr(), original_values);
    assert_eq!(values, [1, 2]);
}

#[test]
fn source_derivation_absence_is_data_and_unassociated_fields_refuse() {
    use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;

    for reactive in [false, true] {
        let coordinator = fixture::coordinator();
        let mut source = if reactive {
            PacketCompleteSemanticSource::new_reactive_for_collecting_world(
                fixture::installation(&coordinator, 1),
                fixture::reactive(&coordinator, 1),
                coordinator,
                fixture::storage_selection(),
            )
            .unwrap()
        } else {
            PacketCompleteSemanticSource::new_producer_for_collecting_world(
                fixture::installation(&coordinator, 0),
                fixture::producer(),
                coordinator,
                fixture::storage_selection(),
            )
            .unwrap()
        };
        let facts = source
            .native_import18_derivation_known_capacity_data(0, None)
            .unwrap();
        assert_eq!(facts.capacity_records, 0);
        assert_eq!(facts.observed_nodes, 1);
        assert_eq!(source.isolated_derivation_known_backing_data(0), Ok(0));

        let mut unassociated = empty_state();
        unassociated.source = &source as *const _ as usize;
        source.native_import18_derivation = Some(unassociated);
        assert_eq!(
            source.native_import18_derivation_known_capacity_data(2, None),
            Err(RuntimeError::ForeignAuthority)
        );
        assert!(source.native_import18_derivation.is_some());
        assert!(!source.ack_birth_attempted);
    }
}
