//! Pins every refactored public definition to its original complete bytes.
//!
//! Expected fixtures come from the unchanged current source macros, separately
//! from the shared borrowed rosters. They grant no native or schema authority.

#[test]
fn borrowed_contract_rosters_preserve_all_eight_original_canonical_definitions() {
    assert_eq!(
        crate::reference_packet::continuation_contracts::complete_ingress_contract()
            .unwrap()
            .as_slice(),
        include_bytes!("schemas_current/complete_ingress_contract.json")
    );
    assert_eq!(
        crate::reference_packet::service::ack_emitter::native_canonical_blob_ack_contract()
            .unwrap()
            .as_slice(),
        include_bytes!("schemas_current/native_canonical_blob_ack_contract.json")
    );
    assert_eq!(
        crate::reference_packet::service::confirmation::native_after_confirmation_contract()
            .unwrap()
            .as_slice(),
        include_bytes!("schemas_current/native_after_confirmation_contract.json")
    );
    assert_eq!(
        crate::reference_packet::service::complete_restore::complete_restore_contract()
            .unwrap()
            .as_slice(),
        include_bytes!("schemas_current/complete_restore_contract.json")
    );
    assert_eq!(crate::reference_packet::service::complete_restore::transfer::complete_restore_transfer_contract().unwrap().as_slice(),
        include_bytes!("schemas_current/complete_restore_transfer_contract.json"));
    assert_eq!(
        crate::reference_packet::service::complete_restore::native_restored_record_contract()
            .unwrap()
            .as_slice(),
        include_bytes!("schemas_current/native_restored_record_contract.json")
    );
    assert_eq!(crate::reference_packet::service::complete_restore::input_emitter::canonical_restore_inputs_contract().unwrap().as_slice(),
        include_bytes!("schemas_current/canonical_restore_inputs_contract.json"));
    assert_eq!(
        crate::reference_packet::service::capture_allocation::capture_allocation_contract()
            .unwrap()
            .as_slice(),
        include_bytes!("schemas_current/capture_allocation_contract.json")
    );
}
