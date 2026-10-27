//! Checks real pre-Child Source DATA without constructing native authority.

use super::super::tests::{coordinator, installation, producer, reactive, storage_selection};
use super::*;

fn source(member: usize) -> PacketCompleteSemanticSource {
    let coordinator = coordinator();
    let installation = installation(&coordinator, member);
    if member == 0 {
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            installation,
            producer(),
            coordinator,
            storage_selection(),
        )
        .unwrap()
    } else {
        let definition = reactive(&coordinator, member);
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            installation,
            definition,
            coordinator,
            storage_selection(),
        )
        .unwrap()
    }
}

#[test]
fn all_actual_source_roles_compose_at_exact_rows_and_refuse_one_short() {
    for member in 0..3 {
        let source = Rc::new(source(member));
        let references = Rc::strong_count(&source);
        let facts = source
            .original_prechild_capacity_data(usize::MAX, None)
            .unwrap();
        let legacy = source
            .original_complete_code_retained_storage_precredit_data(usize::MAX)
            .unwrap();
        let bytes =
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                &facts,
                usize::MAX,
            )
            .unwrap();

        assert!(facts.capacity_records > 2);
        assert!(facts.observed_nodes >= 43);
        // One aggregate tree/shared alignment bound can conservatively exceed
        // independently priced components; it must not lose their owners.
        assert!(bytes >= legacy, "member {member}: {bytes} < {legacy}");
        assert_eq!(
            source
                .original_prechild_capacity_data(facts.capacity_records, None)
                .unwrap(),
            facts
        );
        assert!(matches!(
            source.original_prechild_capacity_data(facts.capacity_records - 1, None),
            Err(RuntimeError::ResourceLimit)
        ));
        assert_eq!(
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                &facts, bytes
            )
            .unwrap(),
            bytes
        );
        assert!(
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                &facts,
                bytes - 1
            )
            .is_err()
        );
        assert_eq!(
            source
                .original_prechild_capacity_data(usize::MAX, None)
                .unwrap(),
            facts
        );
        assert_eq!(Rc::strong_count(&source), references);
        assert!(!source.complete_bytes_launch_reserved.get());
        assert!(!source.ack_birth_attempted);
    }
}

#[test]
fn retained_partial_input_banks_keep_spare_capacity_and_original_pointers() {
    let before = Rc::new(source(0))
        .original_prechild_capacity_data(usize::MAX, None)
        .unwrap();
    let mut source = source(0);
    let mut bytes = Vec::with_capacity(127);
    bytes.extend_from_slice(b"partial");
    source.ack_birth_input_banks = Some((bytes, Vec::with_capacity(73)));
    let source = Rc::new(source);
    let (first, second) = source.ack_birth_input_banks.as_ref().unwrap();
    let pointers = (first.as_ptr(), second.as_ptr());

    let after = source
        .original_prechild_capacity_data(usize::MAX, None)
        .unwrap();

    assert_eq!(after.capacity_records, before.capacity_records + 2);
    assert_eq!(after.vector_banks, before.vector_banks + 2);
    assert_eq!(
        after.vector_capacity_bytes,
        before.vector_capacity_bytes + 200
    );
    assert_eq!(after.observed_nodes, before.observed_nodes + 9);
    let (first, second) = source.ack_birth_input_banks.as_ref().unwrap();
    assert_eq!((first.as_ptr(), second.as_ptr()), pointers);
    assert_eq!(first, b"partial");
    assert!(second.is_empty());
}

#[test]
fn busy_source_field_refuses_without_erasing_original_owners() {
    let source = Rc::new(source(1));
    let before = source
        .original_prechild_capacity_data(usize::MAX, None)
        .unwrap();
    let slot = source.capture_banks.borrow_mut();

    assert!(matches!(
        source.original_prechild_capacity_data(usize::MAX, None),
        Err(RuntimeError::OwnerBusy)
    ));
    assert!(slot.is_none());
    drop(slot);
    assert_eq!(
        source
            .original_prechild_capacity_data(usize::MAX, None)
            .unwrap(),
        before
    );
}

#[test]
fn repeated_source_views_keep_both_capacity_populations_without_alias_discount() {
    let source = Rc::new(source(2));
    let alias = Rc::clone(&source);
    let references = Rc::strong_count(&source);
    let once = source
        .original_prechild_capacity_data(usize::MAX, None)
        .unwrap();
    let mut census = OriginalOwnerCapacityMetadataData::new(once.capacity_records * 2, None);

    for view in [&source, &alias] {
        census
            .observe_component_capacity_data(|remaining, bank| {
                view.original_prechild_capacity_data(remaining, bank)
            })
            .unwrap();
    }
    let twice = census.finish();

    assert_eq!(twice.capacity_records, once.capacity_records * 2);
    assert_eq!(twice.shared_backing_views, once.shared_backing_views * 2);
    assert_eq!(twice.vector_capacity_bytes, once.vector_capacity_bytes * 2);
    assert_eq!(twice.observed_nodes, once.observed_nodes * 2);
    assert_eq!(Rc::strong_count(&source), references);
}
