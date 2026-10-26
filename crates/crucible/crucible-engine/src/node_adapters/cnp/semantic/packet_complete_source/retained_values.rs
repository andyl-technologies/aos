//! Counts actual private Source JSON and bootstrap/association backing.
//!
//! The pinned serde_json default/std representation uses scalar Numbers and
//! BTreeMap-backed objects. This walk observes retained capacities, never encodes
//! a replacement Value. Compiler frames/thread stack and allocator rounding are
//! separate unknown terms; no continuous physical-peak claim follows.

#[path = "retained_values/edition18_tokens.rs"]
pub(crate) mod edition18_tokens;

#[path = "retained_values/metadata.rs"]
mod metadata;
pub(super) use metadata::value_capacity_counter_scratch_data;
pub(in crate::node_adapters::cnp::semantic) use metadata::{
    record_value_capacity_data_with_error, value_capacity_data_with_error,
};

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use serde_json::Value;

impl PacketCompleteSemanticSource {
    /// Counts original private boot and post-Hello association heap storage.
    ///
    /// Includes source-held raw banks, actual normalized JSON capacities, typed
    /// ACK context byte banks, actual SDK emitter/shared metadata and full Hello
    /// bank metadata. Root/underlying inline allocation headers, capture banks,
    /// static/lineage and external node/process/native/Host/receiver owners are
    /// separate owning-row terms. Existing post-restore installed graphs refuse
    /// until their complete owning edition is installed; they are never omitted.
    ///
    /// # Errors
    /// Refuses foreign origin, borrowed holders, unsupported retained restore
    /// graphs, failed original SDK metadata guards or requested-layout overflow.
    pub fn original_complete_boot_association_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.original_complete_boot_association_storage_data_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_complete_boot_association_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        self.storage_origin_with_error::<E>()?;
        let mut bytes =
            self.original_import18_capture_bank_partial_storage_data_with_error::<E>(maximum)?;
        bytes = sum_with_error::<E, _>(
            [
                bytes,
                self.native_import18_phase_bank_storage_with_error::<E>(maximum)?,
            ],
            maximum,
        )?;
        bytes = sum_with_error::<E, _>(
            [
                bytes,
                self.native_import18_birth_construction_retained_storage_data(maximum)
                    .map_err(E::runtime)?,
            ],
            maximum,
        )?;
        bytes = sum_with_error::<E, _>(
            [
                bytes,
                self.isolated_derivation_known_backing_data(maximum)
                    .map_err(E::runtime)?,
            ],
            maximum,
        )?;
        if let Some((source, registration)) = &self.ack_birth_input_banks {
            bytes = sum_with_error::<E, _>(
                [bytes, source.capacity(), registration.capacity()],
                maximum,
            )?;
        }
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| E::refused("retained private birth already borrowed"))?;
        if let Some(birth) = birth.as_ref() {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    birth.retained_heap_storage_data_with_error::<E>(maximum)?,
                ],
                maximum,
            )?;
        }
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| E::refused("retained original association already borrowed"))?;
        if let Some(association) = association.as_ref() {
            bytes = sum_with_error::<E, _>(
                [
                    bytes,
                    association.retained_heap_storage_data_with_error::<E>(maximum)?,
                ],
                maximum,
            )?;
        }
        Ok(bytes)
    }
}

pub(super) fn value_storage(
    value: &Value,
    depth: usize,
    maximum: usize,
) -> Result<usize, OperationFailure> {
    value_storage_with_error::<OperationFailure>(value, depth, maximum)
}

pub(in crate::node_adapters::cnp::semantic) fn value_storage_with_error<E: StorageError>(
    value: &Value,
    depth: usize,
    maximum: usize,
) -> Result<usize, E> {
    let facts = value_capacity_data_with_error::<E>(value, depth, None)?;
    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
        &facts, maximum,
    )
}

pub(super) fn sum<const N: usize>(
    terms: [usize; N],
    maximum: usize,
) -> Result<usize, OperationFailure> {
    sum_with_error::<OperationFailure, N>(terms, maximum)
}

pub(in crate::node_adapters::cnp::semantic) fn sum_with_error<E: StorageError, const N: usize>(
    terms: [usize; N],
    maximum: usize,
) -> Result<usize, E> {
    terms.into_iter().try_fold(0usize, |total, bytes| {
        total
            .checked_add(bytes)
            .filter(|total| *total <= maximum)
            .ok_or_else(|| E::limit("retained private Source storage exhausted"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn private_normalization_counts_spare_string_and_array_backing() {
        let mut text = String::with_capacity(4096);
        text.push('x');
        let mut array = Vec::with_capacity(17);
        array.push(Value::String(text));
        let value = Value::Array(array);
        let total = value_storage(&value, 0, usize::MAX).unwrap();

        assert!(total >= 4096 + 17 * size_of::<Value>());
        assert_eq!(value_storage(&value, 0, total).unwrap(), total);
        assert!(value_storage(&value, 0, total - 1).is_err());
    }
}
