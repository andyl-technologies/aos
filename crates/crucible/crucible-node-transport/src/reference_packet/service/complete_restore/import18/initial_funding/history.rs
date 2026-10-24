//! Borrows the complete initial result for failed-owner history and census.
//!
//! Every field is fixed inline DATA. This view has no deserializer and cannot
//! reconstruct an opaque initial result, memory admission or bootstrap owner.

use super::*;
use crate::retained_metadata::MetadataObserver;

/// Borrows every fixed initial operand, including failed or mismatched attempts.
///
/// This DATA contains no key, native handle, constructor or phase permission.
/// Its source owner remains borrowed throughout observation or serialization.
#[derive(Clone, Copy, Serialize)]
pub struct PacketNativeImport18InitialFundingHistoryData<'a> {
    /// The independently produced initial retained/transient/scratch row.
    pub row: &'a PacketNativeStartupAllocationRow,
    /// The exact initial result's recipe commitment.
    pub recipe_identity: &'a [u8; 32],
    /// The exact original Source lease commitment.
    pub lease_identity: &'a [u8; 32],
    /// The exact selected public launch commitment.
    pub selected_launch_identity: &'a [u8; 32],
    /// The commitment to the actual private Birth identifier.
    pub private_launch_identity: &'a [u8; 32],
    /// The original mapping nonce; this is not a private key.
    pub nonce: &'a [u8; 32],
    /// The original nonrenewing lease generation.
    pub generation: U64,
    /// The separately derived recipe, selected-launch and private-boot bounds.
    pub body_maximums: &'a [U64; 3],
}

impl PacketNativeImport18InitialFundingHistoryData<'_> {
    /// Names only this allocation-free borrowed loan's actual fixed controls.
    ///
    /// Serializer, output and enclosing observer work remain separate terms.
    pub const fn counter_scratch_data() -> usize {
        size_of::<Self>() + size_of::<&PacketNativeImport18InitialFundingData>()
    }
}

pub(in crate::reference_packet) type NativeImport18InitialFundingHistoryData<'a> =
    PacketNativeImport18InitialFundingHistoryData<'a>;

impl PacketNativeImport18InitialFundingData {
    /// Borrows all immutable fixed fields without an origin or success check.
    ///
    /// Failed or partial parent attempts retain the exact result even when a
    /// matching Recipe or lease is absent. This loan neither validates those
    /// parents nor reconstructs the opaque producer output.
    pub fn borrowed_history_data(&self) -> PacketNativeImport18InitialFundingHistoryData<'_> {
        PacketNativeImport18InitialFundingHistoryData {
            row: &self.row,
            recipe_identity: &self.recipe_identity,
            lease_identity: &self.lease_identity,
            selected_launch_identity: &self.selected_launch_identity,
            private_launch_identity: &self.private_launch_identity,
            nonce: &self.nonce,
            generation: self.generation,
            body_maximums: &self.body_maximums,
        }
    }

    // Origin and success are deliberately absent: failed owners still count.
    pub(in crate::reference_packet) fn observe_retained_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&self.row.retained_requested_bytes)?;
        observer.observe(&self.row.maximum_simultaneous_transient_bytes)?;
        observer.observe(&self.row.declared_counter_scratch_bytes)?;
        observer.observe(&self.recipe_identity)?;
        observer.observe(&self.lease_identity)?;
        observer.observe(&self.selected_launch_identity)?;
        observer.observe(&self.private_launch_identity)?;
        observer.observe(&self.nonce)?;
        observer.observe(&self.generation)?;
        observer.observe(&self.body_maximums)
    }
}

pub(in crate::reference_packet) fn counter_scratch_data() -> usize {
    PacketNativeImport18InitialFundingHistoryData::counter_scratch_data()
        + size_of::<&mut MetadataObserver<'static>>()
}
