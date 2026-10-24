//! Quotes the sole SDK original, seal verification and failure incident clones.
//!
//! The prepared original/DOM/literal, existing journal banks and concrete
//! supervisor callback are separately funded by the complete Source holder.

use super::*;
use crate::reference_packet::service::complete_restore::import18::{
    bootstrap_ack::{
        PacketNativeImport18BootstrapEnvelopeProjectionData,
        native_import18_bootstrap_envelope_projection_counter_scratch_data,
        native_import18_bootstrap_envelope_projection_data,
    },
    native_import18_selection_construction_storage_data,
};
use crate::retained_metadata::requested_storage::tree_storage_data;
use crucible_node_format::canonical;
use crucible_node_format::values::MAX_ID_BYTES;
use serde_json::Value;
use std::mem::{align_of, size_of};

impl<S: ProviderStream> Connection<S> {
    /// Quotes independently owned SDK and failure clones of the closed original.
    ///
    /// An unused SDK at seal entry adds one pending-map entry. On later failure
    /// that map keeps its original while containment clones it into a separate
    /// incident vector. Publication may use this conservative same component,
    /// without treating existing SDK backing as free Source credit. The complete
    /// holder and actual supervisor callback remain separately admitted.
    ///
    /// # Errors
    /// Refuses unsupported tree layout, checked overflow or short restriction.
    pub(crate) fn original_bootstrap_sealing_construction_data(
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        let projection = native_import18_bootstrap_envelope_projection_data(maximum)?;
        let serialization = projection.serialization_requested_bytes_data()[0];
        // A combined SDK/incident census prices all nested maps at the SDK's
        // larger Envelope entry layout. The typed clone has no outer JSON
        // Envelope map; the defining projection supplies its actual subtree.
        let backing = projection.request_native_backing_storage_data(
            size_of::<Id>() + size_of::<Envelope>(),
            align_of::<Id>().max(align_of::<Envelope>()),
        )?;
        let (factories, factory_controls) =
            native_import18_selection_construction_storage_data(maximum)?;
        let pending = tree_storage_data(
            1,
            1,
            size_of::<Id>() + size_of::<Envelope>(),
            align_of::<Id>().max(align_of::<Envelope>()),
        )?;
        let incident = sum(&[
            size_of::<ConnectionIncident>(),
            3 * MAX_ID_BYTES,
            // Four slots dominate Vec's minimum growth for this sole clone;
            // the actual clone's independent strings/maps are charged below.
            4 * size_of::<Envelope>(),
            backing,
        ])?;
        let retained = sum(&[pending, MAX_ID_BYTES, backing, incident])?;
        let transient = sum(&[
            factories,
            serialization[0], serialization[2],
            // A failed insertion may drop a separately constructed clone
            // while the verification DOM still survives in the seal closure.
            backing,
            size_of::<Envelope>(), size_of::<Option<Envelope>>(),
            size_of::<Value>(), size_of::<Result<Value, serde_json::Error>>(),
            size_of::<Vec<u8>>(),
            PacketNativeImport18BootstrapEnvelopeProjectionData::serialization_failure_requested_bytes_data(),
            incident,
        ])?;
        let row = [
            retained,
            transient,
            factory_controls
                .checked_add(Self::original_bootstrap_sealing_counter_scratch_data())
                .ok_or_else(refused)?,
        ];
        if sum(&row)? > maximum {
            return Err(refused());
        }
        Ok(row)
    }

    /// Names the actual wire, map, clone, canonical writer and SDK controls.
    pub(crate) fn original_bootstrap_sealing_counter_scratch_data() -> usize {
        Self::original_bootstrap_reservation_counter_scratch_data()
            + crate::connection::native_import18::pending_assignment_counter_scratch_data()
            + native_import18_bootstrap_envelope_projection_counter_scratch_data()
            + canonical::canonical_json_counter_scratch_bytes_data()
            + size_of::<&PacketNativeImport18BootstrapAckProof>()
            + size_of::<&mut crate::session::CorrelationGuard>()
            + size_of::<PacketNativeImport18BootstrapEnvelopeProjectionData>()
            + size_of::<Result<PacketNativeImport18BootstrapEnvelopeProjectionData, ProviderError>>(
            )
            + size_of::<std::collections::btree_map::Values<'static, Id, Envelope>>()
            + size_of::<[usize; 12]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>() * 2
    }
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(refused)
    })
}

#[cfg(test)]
#[path = "sealing_storage/tests.rs"]
mod tests;
