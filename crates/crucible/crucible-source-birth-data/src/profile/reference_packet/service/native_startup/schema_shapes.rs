//! Counts the same compiled definitions used by actual native policy constructors.
//!
//! Shared borrowed field rosters avoid constructing a temporary schema merely
//! to discover its allocation demand. Static included JSON uses the fixed raw
//! occurrence scanner. Definition references have their own owned child terms.

use crate::ProviderError;
use crate::profile::reference_packet::service::PacketNative5LaunchValidationFields as Fields;
use crate::profile::serialization_storage::OriginalSerializationStorageData;
use crate::selected_decode::selected_value_decode_storage_data as decode_value;
use std::mem::size_of;

/// Shares the original compiled borrowed contract quote entry points.
pub mod contracts;
/// Shares the original fixed schema literal-generation population.
pub mod literal_generation;

/// Reports original schema phase and independent retained reference children.
///
/// This is checked arithmetic DATA, never installation or admission authority.
pub struct InitialSchemaStorage {
    /// Counts the complete selected schema generation phase.
    pub transient: usize,
    /// Counts independently retained schema-reference string children.
    pub retained_reference_children: usize,
}

/// Executes the original selected schema schedule over actual borrowed Fields.
///
/// # Errors
/// Preserves each original serializer, selected decode and baseline-storage refusal.
pub fn project(launch: &Fields<'_>, maximum: usize) -> Result<InitialSchemaStorage, ProviderError> {
    let mut phase = 0usize;
    let mut references = 1usize;
    let mut add = |data: OriginalSerializationStorageData| -> Result<(), ProviderError> {
        phase = sum(&[phase, data.requested_total()?], maximum)?;
        Ok(())
    };
    add(contracts::complete_ingress_contract_storage_data(maximum)?)?;
    if launch.confirmation_selection.is_some() {
        add(contracts::native_after_confirmation_contract_storage_data(
            maximum,
        )?)?;
        references = references.checked_add(1).ok_or_else(refused)?;
    }
    if launch.ack_emitter_selection.is_some() {
        add(contracts::native_canonical_blob_ack_contract_storage_data(
            maximum,
        )?)?;
        references = references.checked_add(1).ok_or_else(refused)?;
    }
    if launch.complete_restore_selection.is_some() {
        add(contracts::complete_restore_contract_storage_data(maximum)?)?;
        references = references.checked_add(3).ok_or_else(refused)?;
    }
    if launch.complete_restore_selection==Some(crate::profile::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) {
        add(contracts::complete_restore_transfer_contract_storage_data(maximum)?)?;
        add(contracts::native_restored_record_contract_storage_data(maximum)?)?;
        references=references.checked_add(7).ok_or_else(refused)?;
    }
    if launch.restore_input_emitter_selection.is_some() {
        add(contracts::canonical_restore_inputs_contract_storage_data(
            maximum,
        )?)?;
        references = references.checked_add(1).ok_or_else(refused)?;
    }
    if launch.capture_allocation_selection.is_some() {
        add(contracts::capture_allocation_contract_storage_data(
            maximum,
        )?)?;
        references = references.checked_add(2).ok_or_else(refused)?;
    }
    if launch.fresh_restore_allocation_selection.is_some() {
        // NativePolicy18 creates the same five exact definitions and compares
        // them in both immutable provider/binding rosters. The static publisher
        // schema counter is admitted before these owning helpers can run.
        phase = sum(
            &[phase, literal_generation::fresh_requested_data()?],
            maximum,
        )?;
        references = references.checked_add(5).ok_or_else(refused)?;
    }

    let admission = decode_value(
        crate::profile::reference_packet::service::ack_emitter::NATIVE_CANONICAL_ACK_ADMISSION_CONTRACT_DATA,
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

fn sum(values: &[usize], maximum: usize) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, bytes| {
        total
            .checked_add(*bytes)
            .filter(|total| *total <= maximum)
            .ok_or_else(refused)
    })
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("native baseline requested storage")
}
