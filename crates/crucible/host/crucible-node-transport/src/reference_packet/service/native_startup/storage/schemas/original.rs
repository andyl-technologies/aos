//! Counts the same compiled definitions used by actual native policy constructors.
//!
//! Shared borrowed field rosters avoid constructing a temporary schema merely
//! to discover its allocation demand. Static included JSON uses the fixed raw
//! occurrence scanner. Definition references have their own owned child terms.

use super::*;
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;

pub(super) struct InitialSchemaStorage {
    pub(super) transient: usize,
    pub(super) retained_reference_children: usize,
}

pub(super) fn project(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<InitialSchemaStorage, ProviderError> {
    let mut phase = 0usize;
    let mut references = 1usize;
    let mut add = |data: OriginalSerializationStorageData| -> Result<(), ProviderError> {
        phase = sum(&[phase, data.requested_total()?], maximum)?;
        Ok(())
    };
    add(
        crate::reference_packet::continuation_contracts::complete_ingress_contract_storage_data(
            maximum,
        )?,
    )?;
    if launch.confirmation_selection.is_some() {
        add(
            crate::reference_packet::service::confirmation::native_after_confirmation_contract_storage_data(
                maximum,
            )?,
        )?;
        references = references.checked_add(1).ok_or_else(refused)?;
    }
    if launch.ack_emitter_selection.is_some() {
        add(
            crate::reference_packet::service::ack_emitter::native_canonical_blob_ack_contract_storage_data(
                maximum,
            )?,
        )?;
        references = references.checked_add(1).ok_or_else(refused)?;
    }
    if launch.complete_restore_selection.is_some() {
        add(
            crate::reference_packet::service::complete_restore::complete_restore_contract_storage_data(maximum)?,
        )?;
        references = references.checked_add(3).ok_or_else(refused)?;
    }
    if launch.complete_restore_selection==Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) {
        add(crate::reference_packet::service::complete_restore::transfer::complete_restore_transfer_contract_storage_data(maximum)?)?;
        add(crate::reference_packet::service::complete_restore::native_restored_record_contract_storage_data(maximum)?)?;
        references=references.checked_add(7).ok_or_else(refused)?;
    }
    if launch.restore_input_emitter_selection.is_some() {
        add(crate::reference_packet::service::complete_restore::input_emitter::canonical_restore_inputs_contract_storage_data(maximum)?)?;
        references = references.checked_add(1).ok_or_else(refused)?;
    }
    if launch.capture_allocation_selection.is_some() {
        add(
            crate::reference_packet::service::capture_allocation::capture_allocation_contract_storage_data(
                maximum,
            )?,
        )?;
        references = references.checked_add(2).ok_or_else(refused)?;
    }
    if launch.fresh_restore_allocation_selection.is_some() {
        // NativePolicy18 creates the same five exact definitions and compares
        // them in both immutable provider/binding rosters. The static publisher
        // schema counter is admitted before these owning helpers can run.
        phase = sum(
            &[
                phase,
                crate::reference_packet::service::report_startup::original_fresh_schema_generation_storage_data(
                )?,
            ],
            maximum,
        )?;
        references = references.checked_add(5).ok_or_else(refused)?;
    }

    let admission = decode_value(
        crucible_source_birth_data::profile::reference_packet::service::ack_emitter::NATIVE_CANONICAL_ACK_ADMISSION_CONTRACT_DATA,
        maximum,
    )?;
    // Hash construction may retain the generated reference while a verification
    // reference is built. Each independent HashRef owns all three real Strings.
    let reference_children =
        "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len();
    let retained = references
        .checked_mul(reference_children)
        .ok_or_else(refused)?;
    let temporary = reference_children.checked_mul(2).ok_or_else(refused)?;
    Ok(InitialSchemaStorage {
        transient: sum(
            &[phase, admission, temporary, size_of::<blake3::Hasher>()],
            maximum,
        )?,
        retained_reference_children: retained,
    })
}
